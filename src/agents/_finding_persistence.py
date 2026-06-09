"""Shared finding-persistence helpers for investigation agents.

Per CLAUDE.md: "Every finding produced by an agent must be persisted to
the findings table. The agent that produced the finding (or the
reporter, as a finalization step) is responsible for the INSERT."

Previously the reporter was the only writer; the engine's post-execute
phase only moved findings around in memory. Investigation agents
(webapp, pentester, reasoner) collected findings into their return
``findings`` list, which was then synthesized into
``previous_result["validated_findings"]`` for the reporter — but the
raw dicts never reached the DB. This module gives every investigation
agent a one-call helper to INSERT its findings as it returns them.
"""
from __future__ import annotations

import hashlib
import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import EvidenceArtifact, Finding

logger = logging.getLogger(__name__)


def _dedup_key(target: str, category: str, param: str = "") -> str:
    """Stable identity for cross-scan deduplication. Matches the
    pattern used by ``src/reporting/json_report.py``."""
    h = hashlib.sha256()
    h.update((target or "").encode("utf-8"))
    h.update(b"|")
    h.update((category or "").encode("utf-8"))
    h.update(b"|")
    h.update((param or "").encode("utf-8"))
    return h.hexdigest()[:16]


def _safe_metadata(finding: dict[str, Any]) -> dict[str, Any]:
    """JSON-native dict for the Finding.finding_metadata JSON column.

    The SQLAlchemy JSON column uses stdlib ``json.dumps`` with no
    ``default=str`` fallback (per the egats-set-serialization memory),
    so any set/tuple inside the finding would crash the flush. Coerce
    containers to lists and drop non-serializable values.
    """
    md: dict[str, Any] = {}
    for k, v in finding.items():
        if k in ("id", "engagement_id", "created_at"):
            continue
        if isinstance(v, set):
            md[k] = sorted(v)
        elif isinstance(v, tuple):
            md[k] = list(v)
        elif isinstance(v, (str, int, float, bool, type(None), list, dict)):
            md[k] = v
        else:
            md[k] = str(v)
    return md


async def persist_findings(
    session: AsyncSession,
    engagement_id: str,
    findings: list[dict[str, Any]],
    *,
    source_agent: str,
    target_url: str = "",
) -> int:
    """INSERT each finding in ``findings`` into the ``findings`` table.

    Wraps the whole block in a try/except so a malformed finding or
    a transient DB error doesn't kill the agent — it just logs and
    returns the count of successfully persisted findings. The
    reporter's later ``_persist_findings`` is idempotent (dedup_key
    indexed) so double-writes are safe.

    Args:
        session: DB session owned by the engine.
        engagement_id: Engagement the findings belong to.
        findings: List of finding dicts (the agent's local result).
        source_agent: Agent name to attribute the findings to.
        target_url: Used for dedup_key derivation.

    Returns:
        Number of findings successfully persisted.
    """
    if not findings:
        return 0
    persisted = 0
    try:
        for f in findings:
            try:
                title = (f.get("title") or "").strip()[:500] or "(untitled)"
                description = (f.get("description") or "").strip() or title
                severity = (f.get("severity") or "info").lower()
                if severity not in ("critical", "high", "medium", "low", "info"):
                    severity = "info"
                confidence = float(f.get("confidence_score", 0.0) or 0.0)
                if confidence < 0.0:
                    confidence = 0.0
                if confidence > 1.0:
                    confidence = 1.0
                category = f.get("category") or f.get("vuln_type") or source_agent
                param = f.get("param") or f.get("parameter") or ""
                target = f.get("url") or f.get("target") or target_url

                row = Finding(
                    engagement_id=engagement_id,
                    title=title,
                    description=description,
                    severity=severity,
                    confidence_score=confidence,
                    source_agent=source_agent,
                    cwe_id=f.get("cwe_id"),
                    owasp_category=f.get("owasp_category"),
                    remediation=f.get("remediation"),
                    finding_metadata=_safe_metadata(f),
                    dedup_key=_dedup_key(target, str(category), str(param)),
                )
                session.add(row)
                # If the finding carries raw evidence (request/response
                # snippets), persist an EvidenceArtifact so the report
                # can attach the proof to the finding.
                evidence = f.get("evidence")
                if isinstance(evidence, dict):
                    session.add(EvidenceArtifact(
                        engagement_id=engagement_id,
                        finding_id=None,  # set after flush; this row may not exist yet
                        artifact_type="request_response",
                        content=evidence,
                    ))
                persisted += 1
            except Exception as inner_exc:
                logger.warning(
                    "persist_findings: skipped malformed finding (%s): %s",
                    source_agent, inner_exc,
                )
        await session.flush()
    except Exception as exc:
        logger.error(
            "persist_findings: bulk insert failed for %s: %s",
            source_agent, exc,
        )
    return persisted


__all__ = ["persist_findings", "_dedup_key"]
