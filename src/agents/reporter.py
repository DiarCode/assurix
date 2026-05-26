"""Report composer agent with MD file generation."""

import json
import logging
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.base import BaseAgent
from src.agents.browser.poc_pipeline import PoCPipeline
from src.core.audit import log_action
from src.core.config import get_settings
from src.llm.client import OllamaClient
from src.reporting.md_report import generate_report

logger = logging.getLogger(__name__)

REPORTER_SYSTEM = """You are a security report writer. Given validated findings and attack paths, compose an executive summary.

Respond in JSON:
{
  "executive_summary": "2-3 sentence overview for leadership",
  "risk_assessment": "Overall risk level: Critical|High|Medium|Low and why",
  "key_findings": ["Top 3-5 findings in plain language"],
  "remediation_priority": ["Ordered list of what to fix first"],
  "compliance_notes": "Any compliance implications if applicable"
}"""


class ReporterAgent(BaseAgent):
    """Composes the final MD report with evidence, attack paths, and LLM-enhanced narrative."""

    name = "reporter"

    async def execute(self, payload: dict[str, Any], session: AsyncSession) -> dict[str, Any]:
        previous = payload.get("previous_result", {})
        validated_findings = previous.get("validated_findings", previous.get("findings", []))
        attack_paths = previous.get("attack_paths", [])
        target_url = previous.get("target_url", "")
        surface = previous.get("surface", {})
        analysis_notes = previous.get("analysis_notes", "")
        engagement_id = payload.get("engagement_id", "default")

        settings = get_settings()

        severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in validated_findings:
            sev = f.get("severity", "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        llm = OllamaClient()
        report_data: dict[str, Any] = {}

        try:
            findings_json = json.dumps(validated_findings[:20], default=str)[:4000]
            paths_json = json.dumps(attack_paths[:5], default=str)[:2000]

            response = await llm.chat(
                messages=[
                    {"role": "system", "content": REPORTER_SYSTEM},
                    {"role": "user", "content": (
                        f"Target: {target_url}\n"
                        f"Findings: {findings_json}\n"
                        f"Attack paths: {paths_json}\n"
                        f"Notes: {analysis_notes}\n\n"
                        "Compose executive summary and risk assessment."
                    )},
                ],
                task_type="classification",
                max_tokens=2048,
            )
            report_data = self._parse_response(response)
        except Exception as exc:
            logger.warning("Reporter LLM call failed: %s", exc)
            report_data = self._generate_basic_report(validated_findings, target_url)
        finally:
            await llm.close()

        # Determine risk rating from findings
        risk_rating = self._assess_risk(validated_findings).split("—")[0].strip().lower()

        # Generate proof-of-concept commands for validated findings
        poc_pipeline = PoCPipeline()
        proofs_of_concept = []
        for finding in validated_findings[:20]:
            try:
                poc = poc_pipeline.generate_poc(finding, target_url)
                proofs_of_concept.append(poc)
            except Exception as exc:
                logger.debug("PoC generation failed for finding: %s", exc)

        # Generate MD report file
        report_path = ""
        try:
            report_path = generate_report(
                engagement_id=engagement_id,
                target_url=target_url,
                findings=validated_findings,
                attack_paths=attack_paths,
                surface=surface,
                analysis_notes=report_data.get("executive_summary", analysis_notes),
                risk_rating=risk_rating,
                artifacts_dir=settings.artifacts_dir,
                proofs_of_concept=proofs_of_concept,
            )
            report_path = str(report_path)
            logger.info("MD report generated at: %s", report_path)
        except Exception as exc:
            logger.error("Failed to generate MD report: %s", exc)

        await log_action(
            session=session, action="report_generated", actor="reporter",
            payload={"target_url": target_url, "findings_total": len(validated_findings),
                     "severity_counts": severity_counts, "report_path": report_path},
        )

        return {
            "findings": validated_findings,
            "artifacts": [],
            "report_path": report_path,
            "proofs_of_concept": proofs_of_concept,
            "report": {
                "target_url": target_url,
                "severity_counts": severity_counts,
                "total_findings": len(validated_findings),
                "attack_paths": attack_paths,
                **report_data,
            },
        }

    def _parse_response(self, response: str) -> dict[str, Any]:
        """Extract JSON from LLM response using robust centralized parser."""
        from src.llm.client import OllamaClient
        result = OllamaClient.extract_json(response)
        if isinstance(result, dict):
            return result
        return {}

    def _generate_basic_report(self, findings: list[dict], target_url: str) -> dict[str, Any]:
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        top = sorted(findings, key=lambda f: sev_order.get(f.get("severity", "info"), 0), reverse=True)[:5]
        return {
            "executive_summary": f"Security assessment of {target_url} found {len(findings)} findings.",
            "risk_assessment": self._assess_risk(findings),
            "key_findings": [f.get("title", "") for f in top],
            "remediation_priority": [f.get("remediation", "Review") for f in top[:5]],
            "compliance_notes": "",
        }

    def _assess_risk(self, findings: list[dict]) -> str:
        for sev in ("critical", "high"):
            if any(f.get("severity") == sev for f in findings):
                return f"{sev.upper()} — {sev} severity findings present"
        if any(f.get("severity") == "medium" for f in findings):
            return "MEDIUM — medium severity issues found"
        if findings:
            return "LOW — only informational/low issues found"
        return "MINIMAL — no significant findings"