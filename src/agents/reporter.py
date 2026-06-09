"""Report composer agent with MD file generation + DB persistence.

After the kill-chain completes, this agent:

  1. Pulls validated findings + attack paths + recon surface from
     ``payload['previous_result']`` (the reasoner's output).
  2. Asks the LLM for an executive-summary narrative. The LLM call
     is best-effort — a failure here does not block report generation;
     the technical template renders with a deterministic fallback.
  3. Persists all findings to the ``findings`` table via the session
     passed in by the engine. This is the source of truth for any
     future report regeneration.
  4. Writes the MD report to ``data/reports/<timestamp>_<target>_<eng8>.md``
     and refreshes the ``data/reports/LATEST.md`` symlink.
"""

import json
import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.base import BaseAgent
from src.agents.browser.poc_pipeline import PoCPipeline
from src.core.audit import log_action
from src.db.models import Finding, Severity
from src.llm.frontier_client import UnifiedLLMClient
from src.llm.json_utils import extract_json_from_response
from src.reporting.md_report import generate_report

logger = logging.getLogger(__name__)

REPORTER_SYSTEM = """You are a senior security analyst writing the executive summary for a security assessment report. You will be given:

  - The target under assessment
  - A list of validated findings (severity, title, description, evidence, remediation)
  - A list of confirmed attack paths
  - Free-form analyst notes

Produce a JSON object with these exact keys:
{
  "executive_summary": "2-4 sentence overview written for a CISO/leadership audience. State what was tested, what was found, and what it means in business terms.",
  "risk_assessment": "Overall risk level: Critical|High|Medium|Low and a one-sentence justification tied to specific findings.",
  "key_findings": ["Top 3-5 findings in plain language, ordered by severity"],
  "remediation_priority": ["Ordered list of what to fix first, with rationale"],
  "compliance_notes": "Any compliance implications (PCI-DSS, GDPR, SOC2, OWASP Top 10) that apply to the findings. Empty string if none.",
  "methodology_summary": "2-3 sentences summarizing the kill-chain: what recon was done, what hypotheses were generated, what exploitation was attempted, what validation passed."
}

Be specific. Reference actual findings by title, not generic categories. If there are no findings, the methodology_summary must explain what was attempted and why nothing exploitable was confirmed."""


class ReporterAgent(BaseAgent):
    """Composes the final MD report with evidence, attack paths, and LLM-enhanced narrative.

    Findings are persisted to the DB before the MD file is written, so
    the DB row and the MD section stay in sync. The MD file is the
    human-readable artifact; the DB row is the source of truth.
    """

    name = "reporter"

    async def execute(self, payload: dict[str, Any], session: AsyncSession) -> dict[str, Any]:
        previous = payload.get("previous_result", {})
        validated_findings = previous.get(
            "validated_findings", previous.get("findings", [])
        )
        attack_paths = previous.get("attack_paths", [])
        target_url = previous.get("target_url", "")
        surface = previous.get("surface", {})
        analysis_notes = previous.get("analysis_notes", "")
        engagement_id = payload.get("engagement_id", "default")

        # W2-C: the research_loop summary result (``findings: []``)
        # is empty even when the per-agent ``persist_findings`` helper
        # has already written 14+ rows to the ``findings`` table.
        # Per CLAUDE.md, the DB row is the source of truth — fall
        # back to it whenever the in-memory payload is empty so the
        # report actually renders what was found instead of "no
        # exploitable vulnerabilities". This was the dj1naq.sytes.net
        # regression: 29 findings in the DB, 0 in the report.
        if not validated_findings and engagement_id and engagement_id != "default":
            validated_findings = await self._load_findings_from_db(
                session, engagement_id
            )
            if validated_findings:
                logger.info(
                    "Reporter: %d findings recovered from DB (in-memory "
                    "previous_result.findings was empty)",
                    len(validated_findings),
                )

        severity_counts: dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        }
        for f in validated_findings:
            sev = f.get("severity", "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # LLM call is best-effort. The technical template renders even
        # if the LLM call fails or returns invalid JSON.
        llm = UnifiedLLMClient()
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
                        "Compose the executive summary JSON."
                    )},
                ],
                task_type="classification",
                max_tokens=2048,
            )
            parsed = self._parse_response(response)
            if parsed:
                report_data = parsed
            else:
                # LLM returned a non-empty response that wasn't valid JSON.
                # Fall back rather than fail the whole report.
                logger.warning("Reporter LLM returned non-JSON response; using fallback")
                report_data = self._generate_basic_report(validated_findings, target_url)
        except Exception as exc:
            logger.warning("Reporter LLM call failed: %s; using fallback", exc)
            report_data = self._generate_basic_report(validated_findings, target_url)
        finally:
            try:
                await llm.close()
            except Exception:
                pass

        risk_rating = self._assess_risk(validated_findings).split("—")[0].strip().lower()

        # Persist findings to the DB. The DB row is the source of truth
        # for any future report regeneration; the MD file is a derived
        # view that the agent renders from the same validated_findings.
        try:
            await self._persist_findings(
                session=session,
                engagement_id=engagement_id,
                findings=validated_findings,
            )
        except Exception as exc:
            # Persistence failure must not block report generation —
            # the MD file is still useful and the user has the report.
            logger.error("Failed to persist findings to DB: %s", exc)

        # Generate proof-of-concept commands for validated findings
        poc_pipeline = PoCPipeline()
        proofs_of_concept: list[dict[str, Any]] = []
        for finding in validated_findings[:20]:
            try:
                poc = poc_pipeline.generate_poc(finding, target_url)
                proofs_of_concept.append(poc)
            except Exception as exc:
                logger.debug("PoC generation failed for finding: %s", exc)

        # Build the methodology section from the recon result + attack paths.
        methodology = self._build_methodology(
            surface=surface, attack_paths=attack_paths, analysis_notes=analysis_notes,
        )

        # Write the MD report to data/reports/. The template renders
        # even if the LLM call failed.
        report_path = ""
        try:
            path = generate_report(
                engagement_id=engagement_id,
                target_url=target_url,
                findings=validated_findings,
                attack_paths=attack_paths,
                surface=surface,
                # W1-C: pass the raw analyst notes (collected from
                # the previous agent) as ``raw_analysis_notes``. The
                # legacy ``analysis_notes`` kwarg is kept for API
                # stability but the dedicated kwarg drives the new
                # "## Analyst Notes" section, so the LLM's executive
                # summary and the raw notes are no longer conflated.
                raw_analysis_notes=analysis_notes,
                risk_rating=risk_rating,
                proofs_of_concept=proofs_of_concept,
                llm_narrative=report_data,
                methodology=methodology,
            )
            report_path = str(path)
            logger.info("MD report generated at: %s", report_path)
        except Exception as exc:
            logger.error("Failed to generate MD report: %s", exc)

        await log_action(
            session=session, action="report_generated", actor="reporter",
            payload={
                "target_url": target_url,
                "findings_total": len(validated_findings),
                "severity_counts": severity_counts,
                "report_path": report_path,
            },
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

    async def _persist_findings(
        self,
        session: AsyncSession,
        engagement_id: str,
        findings: list[dict[str, Any]],
    ) -> None:
        """Insert each finding into the ``findings`` table.

        Idempotency is best-effort: we INSERT a new row per finding
        here. The downstream ``JSONReportGenerator`` may regenerate
        the same set of finding IDs; the dedup_key column is the
        stable identity that the report generator uses to deduplicate
        at render time. This is intentional — the DB is the audit log,
        the MD file is the rendered view.
        """
        for f in findings:
            severity = f.get("severity", "info")
            # Coerce severity string to the Severity enum if possible;
            # fall back to "info" when the LLM emitted an unexpected value.
            try:
                sev_enum = Severity(severity)
            except ValueError:
                sev_enum = Severity.INFO
            try:
                confidence = float(f.get("confidence_score") or 0.0)
            except (TypeError, ValueError):
                confidence = 0.0

            row = Finding(
                engagement_id=engagement_id,
                title=str(f.get("title", "Untitled finding"))[:500],
                description=str(f.get("description", "")),
                severity=sev_enum,
                confidence_score=confidence,
                validated=bool(f.get("validated", False)),
                cwe_id=f.get("cwe_id"),
                owasp_category=f.get("owasp_category"),
                remediation=f.get("remediation"),
                source_agent=str(f.get("source_agent", "reporter"))[:100],
                finding_metadata={
                    "evidence": f.get("evidence", {}),
                    "poc": f.get("poc"),
                    "request_response": f.get("request_response"),
                    "attack_path": f.get("attack_path"),
                },
                dedup_key=f.get("dedup_key"),
            )
            session.add(row)
        # Flush so the IDs are assigned, but don't commit — the engine
        # commits the surrounding transaction.
        await session.flush()

    async def _load_findings_from_db(
        self, session: AsyncSession, engagement_id: str
    ) -> list[dict[str, Any]]:
        """Recover findings from the DB when the in-memory payload is empty.

        W2-C: the live engine's research_loop summary returns
        ``{"findings": [], ...}`` even when the per-agent
        ``persist_findings`` helper (W1-B) has already written
        rows to the ``findings`` table. Per CLAUDE.md, the DB row
        is the source of truth for any future report regeneration,
        so the reporter reloads from the table when the in-memory
        list is empty. Each row is converted to the same dict shape
        the rest of the reporter expects.
        """
        from sqlalchemy import select
        from src.db.models import Finding

        stmt = (
            select(Finding)
            .where(Finding.engagement_id == engagement_id)
            .order_by(Finding.created_at)
        )
        result = await session.execute(stmt)
        rows = result.scalars().all()
        return [self._finding_row_to_dict(r) for r in rows]

    @staticmethod
    def _finding_row_to_dict(row: Any) -> dict[str, Any]:
        """Convert a ``Finding`` SQLAlchemy row to the dict shape the
        reporter (and ``generate_report``) expects."""
        metadata = dict(row.finding_metadata or {})
        return {
            "title": row.title,
            "description": row.description,
            "severity": row.severity,
            "confidence_score": float(row.confidence_score or 0.0),
            "validated": bool(row.validated),
            "cwe_id": row.cwe_id,
            "owasp_category": row.owasp_category,
            "remediation": row.remediation,
            "source_agent": row.source_agent,
            "dedup_key": row.dedup_key,
            "evidence": metadata.get("evidence", {}),
            "poc": metadata.get("poc"),
            "request_response": metadata.get("request_response"),
            "attack_path": metadata.get("attack_path"),
        }

    def _build_methodology(
        self,
        surface: dict[str, Any],
        attack_paths: list[dict[str, Any]],
        analysis_notes: str,
    ) -> dict[str, Any]:
        """Build a methodology section from the recon + attack paths.

        The LLM may also add its own methodology_summary to the
        executive summary; this section documents the kill-chain
        steps the *agents* actually ran, with whatever timestamps
        were emitted by the recon and pentester agents.
        """
        steps: list[dict[str, Any]] = []

        # Recon phase
        if surface:
            recon_actions = []
            technologies = surface.get("technologies", [])
            if technologies:
                recon_actions.append(f"Detected technologies: {', '.join(technologies)}")
            pages = surface.get("pages", [])
            if pages:
                recon_actions.append(f"Crawled {len(pages)} pages")
            endpoints = surface.get("endpoints", [])
            if endpoints:
                recon_actions.append(f"Probed {len(endpoints)} endpoints")
            if recon_actions:
                steps.append({
                    "phase": "Reconnaissance",
                    "timestamp": "",
                    "action": "\n".join(f"- {a}" for a in recon_actions),
                    "outcome": "Attack surface mapped",
                })

        # Exploitation phase
        if attack_paths:
            for i, ap in enumerate(attack_paths[:5], 1):
                steps.append({
                    "phase": f"Exploit chain {i}",
                    "timestamp": "",
                    "action": ap.get("description", ""),
                    "outcome": f"Severity: {ap.get('severity', 'unknown')}",
                })

        # Validation phase
        if steps:
            steps.append({
                "phase": "Validation",
                "timestamp": "",
                "action": "Validated findings through the strict finding gate "
                          "(PoC + request/response + confidence >= 0.30).",
                "outcome": "Findings that did not meet the bar were downgraded to info.",
            })

        summary = ""
        if analysis_notes:
            summary = analysis_notes

        return {"steps": steps, "summary": summary}

    def _parse_response(self, response: str) -> dict[str, Any]:
        """Extract JSON from LLM response using robust centralized parser."""
        result = extract_json_from_response(response)
        if isinstance(result, dict):
            return result
        return {}

    def _generate_basic_report(
        self, findings: list[dict], target_url: str
    ) -> dict[str, Any]:
        """Deterministic fallback when the LLM call fails or returns garbage."""
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        top = sorted(
            findings, key=lambda f: sev_order.get(f.get("severity", "info"), 0),
            reverse=True,
        )[:5]
        total = len(findings)
        if total == 0:
            exec_sum = (
                f"Security assessment of {target_url} completed. No exploitable "
                f"vulnerabilities were confirmed by the strict validation gate. "
                f"See the Methodology and Attack Surface sections for the full "
                f"kill-chain recap and the surface map."
            )
        else:
            exec_sum = (
                f"Security assessment of {target_url} found {total} finding"
                f"{'s' if total != 1 else ''}. The detailed findings section "
                f"below contains the full evidence."
            )
        return {
            "executive_summary": exec_sum,
            "risk_assessment": self._assess_risk(findings),
            "key_findings": [f.get("title", "") for f in top if f.get("title")],
            "remediation_priority": [
                f.get("remediation", "Review") for f in top[:5] if f.get("remediation")
            ],
            "compliance_notes": "",
            "methodology_summary": "",
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
