"""Strategic attack surface planner agent."""

import json
import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.base import BaseAgent
from src.core.audit import log_action
from src.llm.client import OllamaClient

logger = logging.getLogger(__name__)

PLANNER_SYSTEM = """You are a senior security assessment planner. Given a target URL and any available surface data (pages, forms, auth flows, technologies, console errors), produce a strategic plan for authorized deep security testing.

Think like an experienced pentester: consider what an attacker would target based on the actual application surface, not just generic checklist items.

Respond in JSON only with this structure:
{
  "directives": [
    {"type": "crawl", "scope": "url", "depth": 2},
    {"type": "test_category", "category": "owasp_category", "reason": "why this matters for THIS specific target", "priority": "high|medium|low"},
    {"type": "test_auth", "target": "url", "reason": "why auth testing matters here"},
    {"type": "test_form", "target": "url", "form_index": 0, "reason": "what to probe in this form"},
    {"type": "test_api", "endpoint": "/path", "reason": "why this API endpoint matters"},
    ...
  ],
  "hypotheses": [
    {"area": "potential_vulnerability_area", "likelihood": "high|medium|low", "rationale": "detailed reasoning based on surface evidence"}
  ],
  "technologies_detected": ["list of tech stack indicators"],
  "attack_surface_summary": "2-3 sentence overview of the most interesting attack vectors"
}

Categories to consider:
- information_disclosure: Server headers, error messages, stack traces, debug info
- injection: SQL injection, NoSQL injection, command injection, LDAP injection
- broken_auth: Login forms, session management, OAuth flows, password reset
- misconfig: CORS, CSP, HSTS, permissions, default credentials
- xss: Reflected, stored, DOM-based — especially in forms and URL parameters
- csrf: Missing tokens on state-changing forms
- ssrf: Server-side request forgery via URL parameters
- outdated_components: Old JS libraries, known CVEs in dependencies
- cookie_security: Missing Secure/HttpOnly/SameSite flags
- header_security: Missing or misconfigured security headers
- client_side: DOM XSS sinks, template injection, prototype pollution
- api_discovery: Undocumented endpoints from JS analysis

For each hypothesis, reference specific evidence from the surface data (e.g., "Login form at /login lacks CSRF token" not just "possible CSRF").

Max 15 directives. Focus on HIGH probability findings based on actual surface evidence."""


class PlannerAgent(BaseAgent):
    """Uses LLM to analyze target and produce strategic security testing directives."""

    name = "planner"

    async def execute(self, payload: dict[str, Any], session: AsyncSession) -> dict[str, Any]:
        target_url = payload.get("target_url", "")
        iteration = payload.get("iteration", 0)
        previous = payload.get("previous_result", {})

        if not target_url:
            return {"findings": [], "artifacts": [], "directives": [], "hypotheses": []}

        # Build context from previous iteration results
        surface = previous.get("surface", {})
        findings = previous.get("findings", [])

        context_parts = [f"Target URL: {target_url}", f"Iteration: {iteration}"]

        if surface:
            tech_list = surface.get("technologies", [])
            if tech_list:
                context_parts.append(f"Technologies: {', '.join(tech_list)}")
            forms = surface.get("forms", [])
            if forms:
                context_parts.append(f"Forms found: {len(forms)} — {json.dumps(forms[:5], default=str)}")
            auth_pages = surface.get("auth_pages", [])
            if auth_pages:
                context_parts.append(f"Auth pages: {json.dumps(auth_pages, default=str)}")
            inputs = surface.get("inputs", [])
            if inputs:
                context_parts.append(f"Input fields: {len(inputs)} — {json.dumps(inputs[:10], default=str)}")
            buttons = surface.get("buttons", [])
            if buttons:
                context_parts.append(f"Buttons: {json.dumps(buttons[:10], default=str)}")
            scripts = surface.get("scripts", [])
            if scripts:
                context_parts.append(f"External scripts: {len(scripts)}")
            console_errors = surface.get("console_errors", [])
            if console_errors:
                context_parts.append(f"Console errors: {json.dumps(console_errors[:5], default=str)}")
            endpoints = surface.get("endpoints", [])
            if endpoints:
                context_parts.append(f"API endpoints: {json.dumps(endpoints[:10], default=str)}")

        if findings:
            finding_summaries = [
                f"- [{f.get('severity', '?')}] {f.get('title', 'Unknown')}"
                for f in findings[:15]
            ]
            context_parts.append(f"Previous findings:\n" + "\n".join(finding_summaries))

        context_parts.append("Produce a security testing plan based on the above surface data.")

        llm = OllamaClient()
        try:
            response = await llm.chat(
                messages=[
                    {"role": "system", "content": PLANNER_SYSTEM},
                    {"role": "user", "content": "\n".join(context_parts)},
                ],
                task_type="classification",
                max_tokens=2048,
            )

            plan = self._parse_plan(response)
            if not isinstance(plan, dict):
                plan = {}
            await log_action(
                session=session,
                action="plan_generated",
                actor="planner",
                payload={"target_url": target_url, "directives_count": len(plan.get("directives", []))},
            )
            return {
                "findings": [],
                "artifacts": [],
                "directives": plan.get("directives", []),
                "hypotheses": plan.get("hypotheses", []),
                "technologies_detected": plan.get("technologies_detected", []),
                "attack_surface_summary": plan.get("attack_surface_summary", ""),
                "target_url": target_url,
            }
        except Exception as exc:
            logger.error("Planner LLM call failed: %s", exc)
            return {
                "findings": [],
                "artifacts": [],
                "directives": [
                    {"type": "crawl", "scope": target_url, "depth": 2},
                    {"type": "test_category", "category": "header_security", "reason": "Check security headers"},
                    {"type": "test_category", "category": "cookie_security", "reason": "Check cookie flags"},
                    {"type": "test_category", "category": "information_disclosure", "reason": "Check for info leakage"},
                    {"type": "test_category", "category": "injection", "reason": "Test for injection reflection"},
                    {"type": "test_category", "category": "misconfig", "reason": "Check for misconfigurations"},
                ],
                "hypotheses": [],
                "technologies_detected": [],
                "target_url": target_url,
            }
        finally:
            await llm.close()

    def _parse_plan(self, response: str) -> dict[str, Any]:
        """Extract JSON plan from LLM response using centralized parser."""
        result = OllamaClient.extract_json(response)
        if isinstance(result, dict):
            return result
        return {"directives": [], "hypotheses": []}