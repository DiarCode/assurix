"""Verifier + attack path reasoner agent."""

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.base import BaseAgent
from src.agents.browser.exploit_verifier import ExploitVerifier
from src.agents.browser.memory import FindingMemory
from src.agents.adversarial import AdversarialValidator
from src.core.audit import log_action
from src.core.config import get_settings
from src.graph.attack_graph import AttackGraphBuilder
from src.llm.frontier_client import UnifiedLLMClient
from src.llm.json_utils import extract_json_from_response
from src.patterns.library import VulnerabilityPatternLibrary
from src.reasoning.trust import TrustScorer
from src.agents.tools.severity_adjuster import SeverityAdjuster
from src.agents.tools.response_dedup import ResponseDeduplicator

logger = logging.getLogger(__name__)

REASONER_SYSTEM = """You are a Mythos-level security analyst — equal parts pentester and business logic attacker. You don't just check for technical vulnerabilities; you reason about WHAT THE APPLICATION DOES, WHERE THE VALUE FLOWS, and HOW AN ATTACKER WOULD EXPLOIT THE BUSINESS.

Given raw findings from scanners, browser agents, and surface data, you must:

## PHASE 1: Business Context Analysis
Before analyzing individual findings, establish the business context:
- What is this application's PURPOSE? (e-commerce, SaaS, banking, social media, internal tool, etc.)
- What DATA is valuable? (user PII, payment data, credentials, trade secrets, internal documents)
- What FLOWS handle money or sensitive operations? (payments, transfers, admin actions, data export)
- What TRUST boundaries exist? (anonymous -> authenticated -> admin, tenant isolation, API keys)
- Where is the BUSINESS LOGIC? (workflows, state machines, approval chains, multi-step processes)

## PHASE 2: Technical Finding Analysis
1. Deduplicate overlapping findings (merge findings about the same issue)
2. Score confidence (0.0-1.0) for each unique finding based on evidence quality
3. Validate findings with concrete evidence from the actual test results
4. Identify false positives and downgrade or remove them

## PHASE 3: Business Logic Vulnerability Discovery
Go BEYOND technical vulnerabilities. Identify business logic flaws:
- Can an attacker SKIP steps in a multi-step workflow? (e.g., skip payment, go to confirmation)
- Can an attacker MANIPULATE quantities, prices, or states? (negative quantities, price tampering)
- Can an attacker ACCESS other users' data through parameter manipulation? (IDOR beyond simple ID changes)
- Can an attacker ABUSE race conditions? (double-spend, duplicate transactions, TOCTOU)
- Can an attacker ESCALATE privileges? (regular user accessing admin functions, role manipulation)
- Can an attacker EXPLOIT trust relationships? (OAuth misconfig, API key reuse, cross-tenant access)
- Can an attacker CAUSE denial-of-service through business logic? (infinite loops, resource exhaustion)

## PHASE 4: Attack Path Inference
Chain findings into realistic multi-step attack scenarios combining technical AND business logic vulnerabilities:
- "Missing CORS + XSS = credential theft" not just "two separate issues"
- "Error disclosure + SQL injection = data exfiltration" not just "two findings"
- "IDOR in user API + missing auth on admin API = full account takeover"
- "Race condition in payment + no idempotency key = double refund"
- "Missing CSRF on profile update + stored XSS in username = wormable XSS"
- "SSRF in webhook + internal API access = cloud metadata leak -> full compromise"

For each attack path, estimate:
- Skill level required (script kiddie, intermediate, advanced)
- Likelihood of discovery
- Business impact (data breach, financial loss, reputation damage, compliance violation)

## PHASE 5: Output
Respond in JSON only:
{
  "business_context": {
    "application_type": "e.g., e-commerce, SaaS, banking, social, internal",
    "valuable_data": ["what data is worth stealing"],
    "critical_flows": ["what operations must be protected"],
    "trust_boundaries": ["where privilege escalation is possible"],
    "business_risks": ["what an attacker would target for maximum impact"]
  },
  "validated_findings": [
    {
      "title": "...",
      "description": "...",
      "severity": "critical|high|medium|low|info",
      "confidence_score": 0.0-1.0,
      "validated": true,
      "cwe_id": "CWE-XXX",
      "owasp_category": "...",
      "finding_type": "technical|business_logic|missing_control",
      "business_impact": "What this means for the business specifically",
      "remediation": "Specific fix guidance with code/config examples where appropriate",
      "evidence_summary": "What specific evidence supports this finding",
      "false_positive": false
    }
  ],
  "business_logic_findings": [
    {
      "title": "...",
      "description": "What business logic flaw was found",
      "severity": "critical|high|medium|low",
      "confidence_score": 0.0-1.0,
      "business_impact": "Concrete business impact description",
      "exploitation_scenario": "Step-by-step how an attacker would exploit this",
      "remediation": "How to fix the business logic flaw"
    }
  ],
  "attack_paths": [
    {
      "name": "Descriptive attack path name",
      "steps": [
        {"finding": "finding title", "role": "entry_point|enabler|escalation|impact", "edge_to_next": "enables|requires|exacerbates"}
      ],
      "severity": "critical|high|medium|low",
      "skill_level": "script_kiddie|intermediate|advanced",
      "likelihood": "high|medium|low",
      "business_impact": "What this attack means for the business",
      "description": "How findings chain together into a realistic attack scenario"
    }
  ],
  "analysis_notes": "Overall assessment and recommendations",
  "risk_rating": "critical|high|medium|low",
  "summary": "2-3 sentence executive summary of the most important findings and business risks"
}"""


class ReasonerAgent(BaseAgent):
    """Deduplicates, scores confidence, infers attack paths, generates remediation."""

    name = "reasoner"

    async def execute(self, payload: dict[str, Any], session: AsyncSession) -> dict[str, Any]:
        previous = payload.get("previous_result", {})
        raw_findings = previous.get("findings", [])
        target_url = previous.get("target_url", "")
        surface = previous.get("surface", {})

        if not raw_findings:
            return {
                "findings": [], "artifacts": [], "attack_paths": [],
                "validated_findings": [], "analysis_notes": "No raw findings to analyze.",
                "target_url": target_url, "surface": surface,
            }

        # Load AI agent memory for additional context
        settings = get_settings()
        engagement_id = payload.get("engagement_id", "default")
        memory = FindingMemory(engagement_id=engagement_id, artifacts_dir=settings.artifacts_dir)
        memory_context = memory.get_context_summary()

        llm = UnifiedLLMClient()
        try:
            findings_json = json.dumps(raw_findings[:30], indent=2, default=str)[:6000]
            surface_summary = {
                "technologies": surface.get("technologies", []),
                "pages_count": len(surface.get("pages", [])),
                "forms_count": len(surface.get("forms", [])),
                "auth_pages": surface.get("auth_pages", []),
                "inputs_count": len(surface.get("inputs", [])),
                "buttons_count": len(surface.get("buttons", [])),
                "scripts_count": len(surface.get("scripts", [])),
                "console_errors_count": len(surface.get("console_errors", [])),
                "cookies_count": len(surface.get("cookies", [])),
            }

            # Include browser-discovered details for context
            browser_context = []
            auth_pages = surface.get("auth_pages", [])
            if auth_pages:
                browser_context.append(f"Auth pages detected: {json.dumps(auth_pages, default=str)[:1000]}")
            console_errors = surface.get("console_errors", [])
            if console_errors:
                browser_context.append(f"Console errors: {json.dumps(console_errors[:10], default=str)[:1000]}")
            forms = surface.get("forms", [])
            if forms:
                browser_context.append(f"Discovered forms: {json.dumps(forms[:5], default=str)[:1000]}")
            inputs = surface.get("inputs", [])
            if inputs:
                browser_context.append(f"Input fields: {json.dumps(inputs[:10], default=str)[:1000]}")

            browser_context_str = "\n".join(browser_context) if browser_context else "No additional browser data."

            response = await llm.chat(
                messages=[
                    {"role": "system", "content": REASONER_SYSTEM},
                    {"role": "user", "content": (
                        f"Target: {target_url}\n"
                        f"Surface summary: {json.dumps(surface_summary)}\n\n"
                        f"Browser-discovered data:\n{browser_context_str}\n\n"
                        f"AI agent memory context:\n{memory_context}\n\n"
                        f"Raw findings ({len(raw_findings)} total):\n{findings_json}\n\n"
                        "Analyze: deduplicate, validate, score confidence, infer attack paths, "
                        "identify false positives, and provide specific remediation. "
                        "Focus on findings with concrete evidence over generic checks."
                    )},
                ],
                task_type="reasoning",
                max_tokens=4096,
            )

            result = self._parse_response(response)

            # Merge business logic findings into validated findings
            business_logic_findings = result.get("business_logic_findings", [])
            validated_findings = result.get("validated_findings", [])
            for blf in business_logic_findings:
                blf["finding_type"] = "business_logic"
                blf.setdefault("owasp_category", "A04:2021")
                blf.setdefault("cwe_id", "CWE-840")
                validated_findings.append(blf)
            result["validated_findings"] = validated_findings

            # Store business context for downstream agents
            business_context = result.get("business_context", {})
            if business_context:
                result["business_context"] = business_context

            # Adversarial validation (Red/Blue/Judge) for high-confidence findings
            settings = get_settings()
            if settings.adversarial_validation and validated_findings:
                try:
                    validator = AdversarialValidator(min_confidence=settings.adversarial_min_confidence)
                    validated_findings = await validator.validate_findings(validated_findings, surface)
                    result["validated_findings"] = validated_findings
                except Exception as exc:
                    logger.warning("Adversarial validation failed: %s", exc)

            # Build causal attack graph from findings
            attack_paths = result.get("attack_paths", [])
            chain_payload: list[dict[str, Any]] = []
            if validated_findings and len(validated_findings) >= 2:
                try:
                    graph_builder = AttackGraphBuilder()
                    graph_result = await graph_builder.build_graph(validated_findings, surface)
                    if graph_result.get("attack_paths"):
                        attack_paths = graph_result["attack_paths"]
                        result["attack_paths"] = attack_paths
                    # Plan §3.3.1: feed the BFS-derived chains into
                    # the reasoner output. The chainer is a pure
                    # consumer of the graph; it never blocks the
                    # main reasoner path because it runs in O(edges)
                    # with the closed capability vocabulary.
                    from src.graph.exploit_chains import ExploitChainer
                    chainer = ExploitChainer()
                    chains = await chainer.find_chains(
                        findings=validated_findings,
                        surface=surface,
                        graph=graph_result,
                    )
                    chain_payload = [c.to_dict() for c in chains]
                    if chain_payload:
                        # Surface chains alongside the LLM-built
                        # attack_paths so the reporter and the
                        # ``GET /scans/{id}/chains`` endpoint can
                        # consume them.
                        existing = result.get("chains") or []
                        result["chains"] = existing + chain_payload
                    # Persist chains on the Engagement row (plan §3.3.1)
                    # so the read endpoint is a single column fetch —
                    # no LLM call, no graph rebuild, no fallback shim.
                    try:
                        from src.db.models import Engagement
                        engagement = await session.get(Engagement, engagement_id)
                        if engagement is not None:
                            # Append, don't clobber — multiple iterations
                            # of the reasoner should accumulate.
                            prior = list(engagement.chains or [])
                            # Dedup by Chain.name to avoid the same chain
                            # being re-emitted when the same edge is
                            # rediscovered on a later iteration.
                            seen_names = {c.get("name") for c in prior}
                            for c in chain_payload:
                                if c.get("name") not in seen_names:
                                    prior.append(c)
                                    seen_names.add(c.get("name"))
                            engagement.chains = prior
                            engagement.chain_run_at = datetime.now(UTC)
                    except Exception as exc:
                        # Persistence is best-effort: a failed write
                        # must not block the main reasoner path.
                        logger.warning("Failed to persist chains: %s", exc)
                except Exception as exc:
                    logger.warning("Attack graph/chains failed: %s", exc)

            # Trust scoring for all findings
            try:
                trust_scorer = TrustScorer()
                validated_findings = trust_scorer.score_findings(validated_findings)

                # Mythos enhancement: content-aware severity adjustment
                validated_findings = self.severity_adjuster.adjust_batch(validated_findings)

                # Mythos enhancement: response deduplication
                validated_findings = self.response_dedup.dedup_findings(validated_findings)

                result["validated_findings"] = validated_findings
            except Exception as exc:
                logger.warning("Trust scoring failed: %s", exc)

            # ZCAT pattern matching — enrich findings with known vulnerability patterns
            try:
                pattern_lib = VulnerabilityPatternLibrary()
                for finding in validated_findings:
                    matches = pattern_lib.match(finding)
                    if matches:
                        best_pattern, best_score = matches[0]
                        finding["pattern_match"] = {
                            "name": best_pattern.name,
                            "cwe": best_pattern.cwe,
                            "score": round(best_score, 2),
                            "description": best_pattern.description,
                        }
                        if not finding.get("cwe_id") and best_score > 0.7:
                            finding["cwe_id"] = best_pattern.cwe
            except Exception as exc:
                logger.debug("Pattern matching failed: %s", exc)

            # Exploit verification — confirm findings are actually exploitable
            try:
                verifier = ExploitVerifier()
                high_severity = [f for f in validated_findings if f.get("severity") in ("critical", "high", "medium")]
                if high_severity:
                    verifications = await verifier.verify_findings(high_severity, target_url)
                    verified_map = {v.finding_title: v for v in verifications if v.verified}
                    for finding in validated_findings:
                        v = verified_map.get(finding.get("title", ""))
                        if v:
                            finding["exploit_verified"] = True
                            finding["verification_evidence"] = v.evidence
                            finding["confidence_score"] = min(1.0, finding.get("confidence_score", 0.5) + 0.15)
                        else:
                            finding["exploit_verified"] = False
                    logger.info("Exploit verification: %d/%d findings verified",
                                len(verified_map), len(high_severity))
            except Exception as exc:
                logger.warning("Exploit verification failed: %s", exc)

            await log_action(
                session=session, action="reasoning_completed", actor="reasoner",
                payload={"target_url": target_url,
                         "validated_count": len(result.get("validated_findings", [])),
                         "attack_paths_count": len(result.get("attack_paths", []))},
            )

            for f_data in result.get("validated_findings", []):
                await self._persist_finding(session, f_data, target_url)

            # Self-reflective loop: request re-investigation for low-confidence high-severity findings
            re_investigate = []
            for f in result.get("validated_findings", []):
                if f.get("severity") in ("critical", "high") and f.get("confidence_score", 0) < 0.6 and not f.get("false_positive"):
                    vuln_type = f.get("owasp_category", "").lower()
                    task_type = "auth_test" if "auth" in vuln_type or "07" in vuln_type else "xss_hunt" if "03" in vuln_type else "error_probe"
                    re_investigate.append({
                        "task_type": task_type,
                        "target": target_url,
                        "context": f"Re-investigate: {f.get('title', '')} — {f.get('evidence_summary', '')}",
                        "reason": f"Low confidence ({f.get('confidence_score', 0):.2f}) on {f.get('severity', '')} finding",
                    })

            return_dict = {
                "findings": result.get("validated_findings", []),
                "artifacts": [],
                "attack_paths": result.get("attack_paths", []),
                "validated_findings": result.get("validated_findings", []),
                "analysis_notes": result.get("analysis_notes", ""),
                "target_url": target_url,
                "surface": surface,
            }
            if re_investigate:
                return_dict["re_investigate"] = re_investigate[:3]
            return return_dict
        except Exception as exc:
            logger.error("Reasoner LLM call failed: %s", exc)
            validated = self._basic_validate(raw_findings)
            # W1-B: persist the basic-validated findings too (the LLM
            # call may have failed but the surface-check findings are
            # still useful).
            try:
                from src.agents._finding_persistence import persist_findings
                await persist_findings(
                    session=session,
                    engagement_id=payload.get("engagement_id", ""),
                    findings=validated,
                    source_agent="reasoner",
                    target_url=target_url,
                )
            except Exception as persist_exc:
                logger.warning("reasoner (LLM-fail path): persist_findings failed: %s", persist_exc)
            return {
                "findings": validated, "artifacts": [], "attack_paths": [],
                "validated_findings": validated,
                "analysis_notes": f"LLM reasoning failed ({exc}), using basic validation.",
                "target_url": target_url, "surface": surface,
            }
        finally:
            await llm.close()

    def _parse_response(self, response: str) -> dict[str, Any]:
        """Extract JSON from LLM response using robust centralized parser."""
        result = extract_json_from_response(response)
        if isinstance(result, dict):
            return result
        return {"validated_findings": [], "attack_paths": []}

    def _basic_validate(self, raw_findings: list[dict]) -> list[dict]:
        validated = []
        for f in raw_findings:
            f_copy = dict(f)
            has_evidence = bool(f.get("evidence"))
            f_copy["validated"] = has_evidence
            f_copy["confidence_score"] = f.get("confidence_score", 0.5 if has_evidence else 0.3)
            if not f_copy.get("remediation"):
                f_copy["remediation"] = "Review and apply appropriate security controls."
            validated.append(f_copy)
        return validated

    async def _persist_finding(self, session: AsyncSession, finding_data: dict, target_url: str) -> None:
        """Persist a validated finding to the database."""
        from sqlalchemy import select
        from src.db.models import Engagement, Finding

        result = await session.execute(
            select(Engagement).order_by(Engagement.created_at.desc()).limit(1)
        )
        engagement = result.scalar_one_or_none()
        if not engagement:
            return

        finding = Finding(
            engagement_id=engagement.id,
            title=finding_data.get("title", "Unknown"),
            description=finding_data.get("description", ""),
            severity=finding_data.get("severity", "info"),
            confidence_score=finding_data.get("confidence_score", 0.5),
            validated=finding_data.get("validated", False),
            cwe_id=finding_data.get("cwe_id"),
            owasp_category=finding_data.get("owasp_category"),
            remediation=finding_data.get("remediation"),
            source_agent="reasoner",
            finding_metadata=finding_data.get("evidence", {}),
        )
        session.add(finding)
        await session.flush()