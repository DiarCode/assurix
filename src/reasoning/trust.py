"""Trust Scorer — assigns confidence scores to reasoning steps.

Trust factors:
- Evidence quality (screenshot, DOM, network) -> +0.2
- LLM confidence -> weighted
- Adversarial validation result -> +/-0.1
- Cross-iteration consistency -> +0.1

Enables graceful degradation when evidence is weak.
"""

from typing import Any


EVIDENCE_WEIGHTS: dict[str, float] = {
    "screenshot": 0.25,
    "dom_snapshot": 0.20,
    "network_log": 0.20,
    "console_error": 0.10,
    "header_value": 0.15,
    "cookie_value": 0.15,
    "url_reflection": 0.25,
    "html_reflection": 0.20,
    "ai_agent_step": 0.10,
    "tool_result": 0.15,
    "llm_only": 0.05,
}


class TrustScorer:
    """Assigns trust-weighted confidence scores to findings based on evidence quality."""

    def score_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Score a finding's trust level based on evidence quality."""
        evidence = finding.get("evidence", {})
        base_confidence = finding.get("confidence_score", 0.5)

        # Evidence quality bonus
        evidence_bonus = 0.0
        evidence_types: list[str] = []

        if isinstance(evidence, dict):
            for key in evidence:
                weight = EVIDENCE_WEIGHTS.get(key, 0.05)
                evidence_bonus = max(evidence_bonus, weight)
                evidence_types.append(key)
        elif evidence:
            evidence_bonus = 0.10
            evidence_types.append("present")

        # No evidence penalty
        if not evidence:
            evidence_bonus = -0.15
            evidence_types.append("none")

        # Source agent reliability
        source = finding.get("source_agent", "unknown")
        source_bonus = {
            "webapp": 0.05,
            "webapp_ai": 0.10,
            "missing_code": 0.08,
            "missing_code_llm": 0.05,
            "recon": 0.03,
        }.get(source, 0.0)

        # Severity consistency check
        severity = finding.get("severity", "info")
        severity_confidence_map = {"critical": 0.7, "high": 0.6, "medium": 0.5, "low": 0.4, "info": 0.3}
        expected_confidence = severity_confidence_map.get(severity, 0.3)
        severity_penalty = 0.0
        if base_confidence < expected_confidence - 0.2:
            severity_penalty = -0.1

        # Adversarial validation bonus
        validation_bonus = 0.0
        if finding.get("validated") is True:
            validation_bonus = 0.15
        elif finding.get("validated") is False:
            validation_bonus = -0.2

        # Compute final trust score
        trust_score = min(1.0, max(0.0,
            base_confidence + evidence_bonus + source_bonus + severity_penalty + validation_bonus
        ))

        # Determine trust level
        if trust_score >= 0.8:
            trust_level = "high"
        elif trust_score >= 0.5:
            trust_level = "medium"
        elif trust_score >= 0.3:
            trust_level = "low"
        else:
            trust_level = "unreliable"

        return {
            **finding,
            "trust_score": round(trust_score, 3),
            "trust_level": trust_level,
            "trust_breakdown": {
                "base_confidence": base_confidence,
                "evidence_bonus": evidence_bonus,
                "source_bonus": source_bonus,
                "severity_penalty": severity_penalty,
                "validation_bonus": validation_bonus,
                "evidence_types": evidence_types,
            },
        }

    def score_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Score multiple findings and return them sorted by trust score."""
        scored = [self.score_finding(f) for f in findings]
        return sorted(scored, key=lambda f: f.get("trust_score", 0), reverse=True)

    def filter_unreliable(self, findings: list[dict[str, Any]], min_trust: float = 0.3) -> list[dict[str, Any]]:
        """Filter out findings below minimum trust level."""
        scored = [self.score_finding(f) for f in findings]
        return [f for f in scored if f.get("trust_score", 0) >= min_trust]