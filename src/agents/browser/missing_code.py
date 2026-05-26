"""Missing Code Detector — detects vulnerabilities defined by absence.

R3 innovation: most scanners check for bad things that ARE present.
This checks for good things that ARE ABSENT:
- Login form without rate limiting
- API endpoint without auth middleware
- Password reset without email verification
- File upload without size/type validation
- No Content-Security-Policy header

Two-tier detection:
1. Heuristic tier: pattern match against surface data (fast, no LLM)
2. LLM tier: ask model what security controls are missing (expensive, high coverage)
"""

import json
import logging
from typing import Any

from src.llm.client import OllamaClient

logger = logging.getLogger(__name__)

MISSING_CONTROL_SYSTEM = """You are a security expert identifying MISSING security controls in web applications.

Analyze the surface data and find security controls that SHOULD be present but AREN'T. Focus on:
- Missing rate limiting on auth endpoints
- Missing input validation on forms
- Missing CORS policies
- Missing authentication on API endpoints
- Missing CSRF tokens on state-changing requests
- Missing security headers
- Missing file upload validation
- Missing session management controls

For each missing control, respond in JSON array format:
[{"missing_control": "...", "expected_location": "...", "severity": "high|medium|low", "cwe": "CWE-XXX", "evidence": "why you think it's missing"}]

Be specific — reference actual URLs, form actions, and headers from the surface data."""


class MissingCodeDetector:
    """Detects absent security controls using heuristics + LLM analysis."""

    async def detect(self, surface: dict, browser_result: dict | None = None) -> list[dict]:
        """Detect missing security controls from surface data and browser exploration."""
        findings: list[dict[str, Any]] = []

        # Heuristic detection (fast, no LLM)
        findings.extend(self._heuristic_detect(surface))

        # LLM-enhanced detection (expensive, high coverage)
        if browser_result:
            llm_findings = await self._llm_detect(surface, browser_result)
            findings.extend(llm_findings)

        # Deduplicate by missing_control key
        seen: set[str] = set()
        unique: list[dict[str, Any]] = []
        for f in findings:
            key = f.get("missing_control", f.get("title", ""))
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    async def llm_detect(self, surface: dict, existing_findings: list[dict]) -> list[dict]:
        """Public wrapper for LLM-enhanced missing code detection using existing findings as context."""
        browser_result = {"findings": existing_findings, "surface_summary": {
            k: v for k, v in surface.items() if k != "text_content"
        }}
        return await self._llm_detect(surface, browser_result)

    def _heuristic_detect(self, surface: dict) -> list[dict[str, Any]]:
        """Fast heuristic detection of missing security controls."""
        findings: list[dict[str, Any]] = []
        headers = surface.get("headers", {})
        forms = surface.get("forms", [])
        endpoints = surface.get("endpoints", [])
        cookies = surface.get("cookies", [])
        lower_headers = {k.lower(): v for k, v in headers.items()}

        # Rate limiting on auth pages
        auth_pages = surface.get("auth_pages", [])
        if auth_pages:
            rate_headers = [k for k in headers if "rate" in k.lower()]
            if not rate_headers:
                findings.append({
                    "title": "Missing rate limiting on authentication endpoint",
                    "missing_control": "rate_limiting",
                    "expected_location": "auth_endpoints",
                    "severity": "medium", "cwe": "CWE-307",
                    "evidence": f"Found {len(auth_pages)} auth pages but no rate limiting headers",
                    "source_agent": "missing_code", "confidence_score": 0.65,
                })

        # CSRF on POST forms
        for form in forms:
            inputs = form.get("inputs", form.get("fields", []))
            has_csrf = False
            if isinstance(inputs, list):
                for inp in inputs:
                    name = inp.get("name", "").lower()
                    if "csrf" in name or "token" in name or "nonce" in name:
                        has_csrf = True
                        break
            if not has_csrf:
                action = form.get("action", "unknown")
                method = form.get("method", "GET").upper()
                if method == "POST":
                    findings.append({
                        "title": f"POST form at {action} lacks CSRF token",
                        "missing_control": "csrf_protection",
                        "expected_location": action,
                        "severity": "medium", "cwe": "CWE-352",
                        "evidence": f"POST form without CSRF token at {action}",
                        "source_agent": "missing_code", "confidence_score": 0.8,
                    })

        # CORS policy
        cors = lower_headers.get("access-control-allow-origin", "")
        if cors == "*":
            findings.append({
                "title": "Wildcard CORS policy allows any origin",
                "missing_control": "cors_validation",
                "expected_location": "response_headers",
                "severity": "medium", "cwe": "CWE-942",
                "evidence": "Access-Control-Allow-Origin: *",
                "source_agent": "missing_code", "confidence_score": 0.7,
            })

        # Auth on API endpoints
        for ep in endpoints[:10]:
            ep_lower = ep.lower()
            if any(kw in ep_lower for kw in ("admin", "user", "account", "settings", "delete", "update")):
                if not lower_headers.get("authorization") and not lower_headers.get("www-authenticate"):
                    findings.append({
                        "title": f"API endpoint {ep} may lack authentication",
                        "missing_control": "auth_middleware",
                        "expected_location": ep,
                        "severity": "high", "cwe": "CWE-306",
                        "evidence": f"No auth headers; endpoint path suggests sensitive data: {ep}",
                        "source_agent": "missing_code", "confidence_score": 0.5,
                    })

        # Input validation
        for form in forms[:5]:
            inputs = form.get("inputs", form.get("fields", []))
            if isinstance(inputs, list):
                has_validation = any(
                    inp.get("pattern") or inp.get("maxlength") or inp.get("minlength")
                    or inp.get("type") in ("number", "email", "url", "date")
                    for inp in inputs
                )
                has_text = any(inp.get("type") in ("text", "search", "") for inp in inputs)
                if has_text and not has_validation:
                    action = form.get("action", "unknown")
                    findings.append({
                        "title": f"Form at {action} lacks input validation",
                        "missing_control": "input_sanitization",
                        "expected_location": action,
                        "severity": "medium", "cwe": "CWE-79",
                        "evidence": f"Text inputs without validation at {action}",
                        "source_agent": "missing_code", "confidence_score": 0.5,
                    })

        # File upload validation
        for ep in endpoints:
            if any(kw in ep.lower() for kw in ("upload", "file", "attachment")):
                findings.append({
                    "title": f"Upload endpoint {ep} may lack file validation",
                    "missing_control": "file_upload_validation",
                    "expected_location": ep,
                    "severity": "high", "cwe": "CWE-434",
                    "evidence": f"Upload endpoint detected: {ep}",
                    "source_agent": "missing_code", "confidence_score": 0.6,
                })

        # Cookie security
        for c in cookies:
            if not c.get("secure", False) and not c.get("httponly", False):
                name = c.get("name", "unknown")
                findings.append({
                    "title": f"Cookie '{name}' lacks both Secure and HttpOnly flags",
                    "missing_control": "cookie_security",
                    "expected_location": f"cookie_{name}",
                    "severity": "medium", "cwe": "CWE-614",
                    "evidence": f"Cookie '{name}' missing Secure and HttpOnly flags",
                    "source_agent": "missing_code", "confidence_score": 0.85,
                })

        return findings

    async def _llm_detect(self, surface: dict, browser_result: dict) -> list[dict[str, Any]]:
        """Use LLM to detect missing security controls that heuristics miss."""
        surface_summary = {
            "technologies": surface.get("technologies", []),
            "pages_count": len(surface.get("pages", [])),
            "forms_count": len(surface.get("forms", [])),
            "auth_pages": surface.get("auth_pages", []),
            "endpoints": surface.get("endpoints", [])[:10],
            "cookies_count": len(surface.get("cookies", [])),
            "headers_present": list(surface.get("headers", {}).keys())[:20],
            "scripts_count": len(surface.get("scripts", [])),
            "console_errors_count": len(surface.get("console_errors", [])),
        }

        browser_obs = ""
        if browser_result.get("findings"):
            browser_obs = str(browser_result["findings"][:10])[:2000]

        llm = OllamaClient()
        try:
            response = await llm.chat(
                messages=[
                    {"role": "system", "content": MISSING_CONTROL_SYSTEM},
                    {"role": "user", "content": (
                        f"Surface data:\n{json.dumps(surface_summary, default=str)[:3000]}\n\n"
                        f"Browser observations:\n{browser_obs[:2000]}\n\n"
                        "Identify MISSING security controls."
                    )},
                ],
                task_type="classification",
                max_tokens=2048,
            )
            return self._parse_missing_response(response)
        except Exception as exc:
            logger.warning("LLM missing code detection failed: %s", exc)
            return []
        finally:
            await llm.close()

    def _parse_missing_response(self, response: str) -> list[dict[str, Any]]:
        """Parse LLM response into structured findings."""
        text = response.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines)

        try:
            data = json.loads(text)
            if isinstance(data, list):
                return self._extract_findings(data)
        except json.JSONDecodeError:
            start = text.find("[")
            end = text.rfind("]") + 1
            if start >= 0 and end > start:
                try:
                    data = json.loads(text[start:end])
                    if isinstance(data, list):
                        return self._extract_findings(data)
                except json.JSONDecodeError:
                    pass

        logger.warning("Failed to parse missing code LLM response")
        return []

    @staticmethod
    def _extract_findings(data: list) -> list[dict[str, Any]]:
        findings = []
        for item in data:
            if isinstance(item, dict) and "missing_control" in item:
                findings.append({
                    "title": item.get("description", f"Missing {item['missing_control']}"),
                    "missing_control": item["missing_control"],
                    "expected_location": item.get("expected_location", "unknown"),
                    "severity": item.get("severity", "medium"),
                    "cwe": item.get("cwe"),
                    "evidence": item.get("evidence", ""),
                    "source_agent": "missing_code_llm",
                    "confidence_score": 0.5,
                })
        return findings