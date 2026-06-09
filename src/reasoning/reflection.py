"""ReflectionPhase: Evaluates whether further investigation is warranted.

The reflection phase is the termination decision point in the ResearchLoop.
It uses LLM reasoning to determine:
1. Whether existing findings have gaps that warrant new hypotheses
2. Whether the attack surface has been sufficiently covered
3. Whether new productive hypotheses can be generated

Returns empty list = loop terminates (research is complete).
Returns new hypotheses = loop continues with fresh investigation targets.
"""

import logging
from typing import Any

from src.llm.frontier_client import UnifiedLLMClient
from src.llm.json_utils import extract_json_from_response

logger = logging.getLogger(__name__)

REFLECTION_PROMPT = """You are a security research reflection engine for an autonomous penetration testing system.

You are evaluating whether the current research loop should continue or terminate.

## Current Hypotheses Investigated
{hypotheses_summary}

## Findings So Far
{findings_summary}

## Target Surface
{surface_summary}

## Coverage Analysis
{coverage_analysis}

Your task:
1. Evaluate whether the current findings adequately cover the attack surface
2. Identify any gaps in coverage — areas of the attack surface that haven't been tested
3. Determine if there are productive new hypotheses that could yield additional findings
4. Consider whether existing findings suggest deeper investigation opportunities

Respond with a JSON object:
{{
  "should_continue": true/false,
  "coverage_assessment": "brief assessment of current coverage completeness",
  "gaps_identified": ["gap 1", "gap 2", ...],
  "new_hypotheses": [
    {{
      "hypothesis_class": "kebab-case-name",
      "attack_category": "one of: auth_bypass, injection, xss, csrf, ssrf, business_logic, race_condition, idor, misconfig, data_exposure, privilege_escalation, api_abuse, crypto_flaw",
      "description": "one sentence explaining what this hypothesis investigates",
      "required_capabilities": ["list of tool capability tags"],
      "falsification_criteria": "how to determine this hypothesis is falsified",
      "confidence": 0.0-1.0,
      "parent_hypothesis_class": "parent hypothesis class if this is a refinement, or null"
    }}
  ]
}}

IMPORTANT:
- If coverage is adequate and no productive new hypotheses exist, set should_continue=false and new_hypotheses=[]
- If there are genuine gaps, set should_continue=true with specific new hypotheses
- Do NOT generate hypotheses that duplicate already-investigated categories
- New hypotheses should be refinements of existing findings or explore genuinely new attack vectors
- Be conservative: only continue if there's a clear, productive direction for investigation
- Maximum 3 new hypotheses per reflection cycle"""


class ReflectionPhase:
    """Evaluates research loop productivity and generates new hypotheses when warranted.

    Uses LLM reasoning to assess coverage completeness and identify gaps.
    Returns empty list when no productive leads remain (termination condition).
    """

    def __init__(self, llm_client: UnifiedLLMClient | None = None) -> None:
        self.llm = llm_client or UnifiedLLMClient()

    async def evaluate(
        self,
        hypotheses: list[dict[str, Any]],
        results: list[dict[str, Any]],
        findings: list[dict[str, Any]],
        surface: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Evaluate whether further investigation is warranted.

        Args:
            hypotheses: List of hypothesis dicts that were investigated.
            results: List of investigation result dicts (from _investigate_hypothesis).
            findings: All findings discovered so far.
            surface: Target surface data.

        Returns:
            Empty list if research should terminate.
            List of new hypothesis dicts if further investigation is warranted.
        """
        # Quick check: if no findings and no hypotheses, nothing to reflect on
        if not hypotheses and not findings:
            logger.info("ReflectionPhase: no hypotheses or findings, terminating")
            return []

        try:
            prompt = REFLECTION_PROMPT.format(
                hypotheses_summary=self._summarize_hypotheses(hypotheses, results),
                findings_summary=self._summarize_findings(findings),
                surface_summary=self._summarize_surface(surface),
                coverage_analysis=self._analyze_coverage(hypotheses, findings),
            )

            response = await self.llm.generate(prompt, task_type="reasoning", max_tokens=4096)
            reflection = extract_json_from_response(response)

            if not reflection or not isinstance(reflection, dict):
                logger.warning("ReflectionPhase: LLM returned invalid reflection, terminating")
                return []

            should_continue = reflection.get("should_continue", False)
            new_hypotheses = reflection.get("new_hypotheses", [])

            if not should_continue:
                coverage = reflection.get("coverage_assessment", "no assessment")
                logger.info("ReflectionPhase: terminating — %s", coverage)
                return []

            # Validate and clean new hypotheses
            valid_hypotheses = []
            for h in new_hypotheses:
                if not isinstance(h, dict):
                    continue
                if "hypothesis_class" not in h or "attack_category" not in h:
                    continue

                h["source"] = "llm_generated"
                h["confidence"] = min(1.0, max(0.0, float(h.get("confidence", 0.4))))
                h["required_capabilities"] = h.get("required_capabilities", [])
                h["falsification_criteria"] = h.get("falsification_criteria", "")

                # Check for duplicates against existing hypotheses
                if not self._is_duplicate(h, hypotheses):
                    valid_hypotheses.append(h)

            logger.info(
                "ReflectionPhase: continuing with %d new hypotheses",
                len(valid_hypotheses),
            )
            return valid_hypotheses

        except Exception as exc:
            logger.error("ReflectionPhase: evaluation failed: %s", exc)
            return []

    def _is_duplicate(
        self,
        new_hypothesis: dict[str, Any],
        existing_hypotheses: list[dict[str, Any]],
    ) -> bool:
        """Check if a new hypothesis duplicates an existing one.

        Uses (attack_category, hypothesis_class) as deduplication key.
        """
        new_key = (
            new_hypothesis.get("attack_category", "").lower(),
            new_hypothesis.get("hypothesis_class", "").lower(),
        )
        for existing in existing_hypotheses:
            existing_key = (
                existing.get("attack_category", "").lower(),
                existing.get("hypothesis_class", "").lower(),
            )
            if new_key == existing_key:
                return True
        return False

    # -------------------------------------------------------------------
    # Summarization helpers
    # -------------------------------------------------------------------

    @staticmethod
    def _summarize_hypotheses(
        hypotheses: list[dict[str, Any]],
        results: list[dict[str, Any]],
    ) -> str:
        """Create a summary of investigated hypotheses and their results."""
        if not hypotheses:
            return "No hypotheses investigated yet."

        lines = []
        for h in hypotheses:
            cls = h.get("hypothesis_class", "unknown")
            category = h.get("attack_category", "unknown")
            status = h.get("status", "unknown")
            confidence = h.get("confidence", 0.0)
            source = h.get("source", "unknown")
            lines.append(
                f"- [{status}] {cls} ({category}, confidence={confidence:.1f}, source={source})"
            )

        # Add result summaries if available
        if results:
            lines.append("\nInvestigation results:")
            for r in results:
                findings_count = r.get("findings_count", 0)
                status = r.get("status", "unknown")
                cls = r.get("hypothesis_class", r.get("hypothesis_class", ""))
                lines.append(f"  - {cls}: {status}, {findings_count} findings")

        return "\n".join(lines)

    @staticmethod
    def _summarize_findings(findings: list[dict[str, Any]]) -> str:
        """Create a summary of all findings discovered so far."""
        if not findings:
            return "No findings discovered yet."

        # Group by severity
        by_severity: dict[str, list[str]] = {}
        for f in findings:
            severity = f.get("severity", "unknown")
            title = f.get("title", "Unknown")
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(title)

        lines = [f"Total findings: {len(findings)}"]
        for severity in ("critical", "high", "medium", "low", "info"):
            if severity in by_severity:
                lines.append(f"\n{severity.upper()} ({len(by_severity[severity])}):")
                for title in by_severity[severity][:5]:  # Limit to 5 per severity
                    lines.append(f"  - {title}")
                if len(by_severity[severity]) > 5:
                    lines.append(f"  ... and {len(by_severity[severity]) - 5} more")

        return "\n".join(lines)

    @staticmethod
    def _summarize_surface(surface: dict[str, Any] | None) -> str:
        """Create a summary of the target attack surface."""
        if not surface:
            return "No surface data available."

        parts = []
        if "technologies" in surface:
            parts.append(f"Technologies: {', '.join(surface['technologies'][:10])}")
        if "pages" in surface:
            parts.append(f"Pages: {len(surface['pages'])}")
        if "endpoints" in surface:
            parts.append(f"Endpoints: {len(surface['endpoints'])}")
        if "forms" in surface:
            parts.append(f"Forms: {len(surface['forms'])}")
        if "auth_pages" in surface:
            parts.append(f"Auth pages: {len(surface['auth_pages'])}")

        return "\n".join(parts) if parts else "Limited surface data available"

    @staticmethod
    def _analyze_coverage(
        hypotheses: list[dict[str, Any]],
        findings: list[dict[str, Any]],
    ) -> str:
        """Analyze which attack categories have been covered and which haven't."""
        all_categories = {
            "auth_bypass", "injection", "xss", "csrf", "ssrf",
            "business_logic", "race_condition", "idor", "misconfig",
            "data_exposure", "privilege_escalation", "api_abuse", "crypto_flaw",
        }

        investigated = {h.get("attack_category", "").lower() for h in hypotheses}
        uncovered = all_categories - investigated

        lines = []
        if investigated:
            lines.append(f"Categories investigated: {', '.join(sorted(investigated))}")
        if uncovered:
            lines.append(f"Categories NOT yet investigated: {', '.join(sorted(uncovered))}")

        # Findings per category
        findings_by_category: dict[str, int] = {}
        for f in findings:
            cat = f.get("owasp_category", f.get("attack_category", "unknown"))
            findings_by_category[cat] = findings_by_category.get(cat, 0) + 1

        if findings_by_category:
            lines.append("\nFindings per category:")
            for cat, count in sorted(findings_by_category.items()):
                lines.append(f"  - {cat}: {count}")

        return "\n".join(lines) if lines else "No coverage analysis available."