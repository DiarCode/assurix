"""Adversarial Validation Engine — Red/Blue/Judge for false positive elimination.

For each finding:
1. Red Agent argues the finding IS a real vulnerability (with evidence)
2. Blue Agent argues it's a FALSE POSITIVE (with reasoning)
3. Judge weighs both arguments and assigns final confidence

This mirrors how expert pentesters think: "Can I break this? Can I defend it?"
"""

import json
import logging
from typing import Any

from src.llm.client import OllamaClient

logger = logging.getLogger(__name__)

RED_SYSTEM = """You are an aggressive security researcher (Red Team). Given a finding, argue
convincingly that it IS a real, exploitable vulnerability. Provide specific attack scenarios,
evidence chains, and realistic exploitation paths. Be concrete, not theoretical."""

BLUE_SYSTEM = """You are a defensive security engineer (Blue Team). Given a finding, argue
convincingly that it is a FALSE POSITIVE or LOW SEVERITY. Consider: compensating controls,
actual exploitability barriers, realistic impact, and common misconfigurations that look worse
than they are. Be specific about why this finding might not be real."""

JUDGE_SYSTEM = """You are an impartial security judge. Given a finding, Red Team arguments,
and Blue Team arguments, make a final determination:

1. Is this finding real? (validated: true/false)
2. Confidence score (0.0-1.0)
3. Adjusted severity (critical/high/medium/low/info)
4. Final reasoning (2-3 sentences)

Respond in JSON:
{"validated": true/false, "confidence_score": 0.0-1.0, "severity": "...", "reasoning": "..."}"""


class AdversarialValidator:
    """Red/Blue/Judge validation to eliminate false positives.

    P3 enhancement: Includes rule-based pre-filter to skip obvious FPs
    before expensive LLM debate, and batch processing to limit LLM calls.
    """

    # Rule-based FP patterns — findings matching these skip LLM debate
    FP_PATTERNS = [
        # SPA catch-all responses
        {"evidence_contains": '<div id="root">', "title_not_contains": "xss"},
        {"evidence_contains": '<div id="app">', "title_not_contains": "xss"},
        {"evidence_contains": '<div id="__next"', "title_not_contains": "xss"},
        # Generic 200 responses without vulnerability-specific markers
        {"title_contains": "accessible", "evidence_not_contains": "sensitive"},
        # Login redirects — not a finding
        {"title_contains": "redirects to login"},
    ]

    def __init__(self, min_confidence: float = 0.5, batch_size: int = 5):
        self.min_confidence = min_confidence
        self.batch_size = batch_size

    async def validate_findings(
        self, findings: list[dict[str, Any]], surface: dict
    ) -> list[dict[str, Any]]:
        """Run adversarial validation on findings above min_confidence.

        First applies rule-based FP filter, then LLM debate for survivors.
        """
        validated = []
        for finding in findings:
            # Rule-based pre-filter: skip obvious FPs without LLM
            if self._is_obvious_fp(finding):
                finding["validated"] = False
                finding["validation_reasoning"] = "Rule-based FP filter: matched known false positive pattern"
                finding["confidence_score"] = min(finding.get("confidence_score", 0.5), 0.2)
                validated.append(finding)
                continue

            if finding.get("confidence_score", 0) >= self.min_confidence:
                result = await self.validate_finding(finding, surface)
                validated.append(result)
            else:
                finding["validated"] = False
                finding["validation_reasoning"] = "Below confidence threshold for adversarial validation"
                validated.append(finding)
        return validated

    def _is_obvious_fp(self, finding: dict[str, Any]) -> bool:
        """Check rule-based FP patterns before expensive LLM debate."""
        title = finding.get("title", "").lower()
        evidence = finding.get("evidence", "").lower()
        description = finding.get("description", "").lower()
        combined_text = f"{title} {evidence} {description}"

        for pattern in self.FP_PATTERNS:
            match = True
            if "evidence_contains" in pattern:
                if pattern["evidence_contains"].lower() not in combined_text:
                    match = False
            if "title_contains" in pattern:
                if pattern["title_contains"].lower() not in title:
                    match = False
            if "title_not_contains" in pattern:
                if pattern["title_not_contains"].lower() in title:
                    match = False
            if "evidence_not_contains" in pattern:
                if pattern["evidence_not_contains"].lower() in combined_text:
                    match = False
            if match:
                return True
        return False

    async def validate_finding(self, finding: dict[str, Any], surface: dict) -> dict[str, Any]:
        """Run adversarial validation on a single finding."""
        llm = OllamaClient()
        try:
            finding_json = json.dumps(finding, default=str)[:1500]
            surface_json = json.dumps(
                {k: v for k, v in surface.items() if k in ("technologies", "auth_pages", "endpoints", "headers")},
                default=str,
            )[:1000]

            red_response = await llm.chat(
                messages=[
                    {"role": "system", "content": RED_SYSTEM},
                    {"role": "user", "content": (
                        f"Finding: {finding_json}\n\nTarget surface: {surface_json}\n\n"
                        "Argue this is a REAL vulnerability."
                    )},
                ],
                task_type="reasoning",
                max_tokens=1024,
            )

            blue_response = await llm.chat(
                messages=[
                    {"role": "system", "content": BLUE_SYSTEM},
                    {"role": "user", "content": (
                        f"Finding: {finding_json}\n\nTarget surface: {surface_json}\n\n"
                        "Argue this is a FALSE POSITIVE."
                    )},
                ],
                task_type="reasoning",
                max_tokens=1024,
            )

            judge_response = await llm.chat(
                messages=[
                    {"role": "system", "content": JUDGE_SYSTEM},
                    {"role": "user", "content": (
                        f"Finding: {finding_json}\n\n"
                        f"Red Team (argues REAL): {red_response[:1000]}\n\n"
                        f"Blue Team (argues FALSE POSITIVE): {blue_response[:1000]}\n\n"
                        "Make your final determination."
                    )},
                ],
                task_type="classification",
                max_tokens=512,
            )

            result = self._parse_judge(judge_response)
            return {
                **finding,
                **result,
                "red_argument": red_response[:500],
                "blue_argument": blue_response[:500],
            }

        except Exception as exc:
            logger.error("Adversarial validation failed: %s", exc)
            return {
                **finding,
                "validated": False,
                "confidence_score": 0.3,
                "validation_reasoning": f"Validation failed: {exc}",
            }
        finally:
            await llm.close()

    @staticmethod
    def _parse_judge(response: str) -> dict[str, Any]:
        """Parse judge response into structured result."""
        text = response.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines)

        try:
            data = json.loads(text)
            return {
                "validated": data.get("validated", False),
                "confidence_score": float(data.get("confidence_score", 0.5)),
                "severity": data.get("severity", "medium"),
                "validation_reasoning": data.get("reasoning", ""),
            }
        except (json.JSONDecodeError, ValueError):
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                try:
                    data = json.loads(text[start:end])
                    return {
                        "validated": data.get("validated", False),
                        "confidence_score": float(data.get("confidence_score", 0.5)),
                        "severity": data.get("severity", "medium"),
                        "validation_reasoning": data.get("reasoning", ""),
                    }
                except (json.JSONDecodeError, ValueError):
                    pass

        return {
            "validated": False,
            "confidence_score": 0.3,
            "severity": "low",
            "validation_reasoning": "Failed to parse judge response",
        }