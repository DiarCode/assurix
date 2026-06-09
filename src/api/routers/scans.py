"""Scan (engagement) routes."""

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_db
from src.core.audit import log_action
from src.db.models import Engagement, EngagementStatus
from src.orchestrator.state import EngagementStateMachine

router = APIRouter()

# Default timeout for auto-completing RESEARCHING engagements (24 hours)
RESEARCH_SIGNOFF_TIMEOUT_HOURS = 24

# Default engagement config — applied to every new scan when the caller does
# not explicitly override it. These defaults enable the depth-oriented
# "offensive" mode of Assurix: research loop, hypothesis orchestrator, and
# the post-reporter depth pass all run by default, and the strict finding
# gate filters out under-evidenced findings at report time.
#
# SECURITY: This module is mounted on an unauthenticated POST /scans endpoint
# (see SECURITY.md — API auth boundary). The ``_merge_default_config`` helper
# filters caller-supplied overrides through a hard allowlist (defined below)
# so that callers cannot disable operator-only safety controls. The keys in
# this dict are the single source of truth for those operator-only controls.
DEFAULT_ENGAGEMENT_CONFIG: dict = {
    "max_iterations": 200,
    "use_research_loop": True,
    "use_hypothesis_orchestrator": True,
    "use_depth_pass": True,
    "strict_finding_gate": True,
    "depth_pass_budget_minutes": 30,
    "depth_pass_max_invocations": 200,
    "mode": "offensive",
}

# SECURITY (FIX 5/6): Hard allowlist of caller-overridable config keys. The
# POST /scans endpoint is unauthenticated, so callers must not be able to
# flip operator-only safety controls (strict_finding_gate, use_* flags,
# mode, max_iterations). Only the keys listed here are honored; any other
# caller key is silently dropped. If you need to make a new field
# caller-overridable, add it here AND consider whether it should also
# require an auth dependency.
_CALLER_OVERRIDABLE_CONFIG_KEYS: frozenset[str] = frozenset({
    "target_id",
    "target_url",
    "auth_cookies",
    "auth_header",
    "extra_payload",
    "signoff_timeout_hours",
    "depth_pass_budget_minutes",
    "depth_pass_max_invocations",
})

# Operator-only keys that MUST be sourced from DEFAULT_ENGAGEMENT_CONFIG.
# If a caller supplies any of these in their config payload they are
# silently dropped (we do not 400, so a benign typo doesn't block scan
# creation). These are documented for operators in SECURITY.md and the
# API docs.
_OPERATOR_ONLY_CONFIG_KEYS: frozenset[str] = frozenset({
    "strict_finding_gate",
    "use_depth_pass",
    "use_research_loop",
    "use_hypothesis_orchestrator",
    "mode",
    "max_iterations",
})


def _merge_default_config(caller_config: dict) -> dict:
    """Layer the canonical default engagement config under caller overrides.

    The caller-supplied dict is filtered through ``_CALLER_OVERRIDABLE_CONFIG_KEYS``
    before being merged, so explicit API/CLI overrides only apply to keys
    explicitly designated as caller-overridable. Operator-only safety
    controls (``strict_finding_gate``, ``use_depth_pass``, etc.) are never
    honored from caller input — they always come from
    ``DEFAULT_ENGAGEMENT_CONFIG``.

    Note: keys that are neither in the allowlist nor operator-only are
    silently dropped (e.g. a typo like ``strict_finding_gte`` won't crash
    the request, it just won't take effect).
    """
    merged = dict(DEFAULT_ENGAGEMENT_CONFIG)
    if caller_config:
        safe_overrides = {
            k: v for k, v in caller_config.items() if k in _CALLER_OVERRIDABLE_CONFIG_KEYS
        }
        merged.update(safe_overrides)
    return merged


@router.get("")
async def list_scans(session: AsyncSession = Depends(get_db)) -> list[dict]:
    result = await session.execute(select(Engagement))
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "target_id": r.target_id,
            "status": r.status.value if hasattr(r.status, "value") else str(r.status),
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            "iteration_count": r.iteration_count,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


@router.post("")
async def start_scan(payload: dict, session: AsyncSession = Depends(get_db)) -> dict:
    # Apply the default engagement config so every new scan runs the full
    # depth-oriented stack (research loop, hypothesis orchestrator, depth
    # pass, strict finding gate). Caller-supplied keys win per-key.
    caller_config = payload.get("config", {}) or {}
    merged_config = _merge_default_config(caller_config)
    engagement = Engagement(
        target_id=payload["target_id"],
        status=EngagementStatus.PENDING,
        config=merged_config,
    )
    session.add(engagement)
    await session.flush()
    return {"id": engagement.id, "status": engagement.status, "target_id": engagement.target_id}


@router.get("/{engagement_id}")
async def get_scan(engagement_id: str, session: AsyncSession = Depends(get_db)) -> dict:
    engagement = await session.get(Engagement, engagement_id)
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return {
        "id": engagement.id,
        "target_id": engagement.target_id,
        "status": engagement.status.value if hasattr(engagement.status, "value") else str(engagement.status),
        "started_at": engagement.started_at.isoformat() if engagement.started_at else None,
        "completed_at": engagement.completed_at.isoformat() if engagement.completed_at else None,
        "iteration_count": engagement.iteration_count,
        "config": engagement.config,
        "created_at": engagement.created_at.isoformat() if engagement.created_at else None,
    }


@router.post("/{engagement_id}/signoff")
async def signoff_research(engagement_id: str, session: AsyncSession = Depends(get_db)) -> dict:
    """Human sign-off for RESEARCHING engagement.

    When the ResearchLoop's reflection phase produces no new hypotheses,
    the engagement transitions to RESEARCHING. A human researcher can
    review the findings and sign off, transitioning to COMPLETED.

    This endpoint also handles auto-completion after a configurable timeout.
    """
    engagement = await session.get(Engagement, engagement_id)
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")

    current_status = engagement.status.value if hasattr(engagement.status, "value") else str(engagement.status)

    if current_status != EngagementStatus.RESEARCHING:
        raise HTTPException(
            status_code=4022,
            detail=f"Cannot sign off engagement in {current_status} status. Must be in RESEARCHING status.",
        )

    # Transition RESEARCHING → COMPLETED
    engagement.status = EngagementStatus.COMPLETED
    engagement.completed_at = datetime.now(UTC)
    await session.flush()

    await log_action(
        session=session,
        action="research_signoff",
        actor="human_researcher",
        payload={"engagement_id": engagement_id, "previous_status": current_status},
    )

    return {
        "id": engagement.id,
        "status": EngagementStatus.COMPLETED,
        "message": "Research sign-off accepted. Engagement completed.",
    }


@router.post("/{engagement_id}/auto-complete")
async def auto_complete_research(engagement_id: str, session: AsyncSession = Depends(get_db)) -> dict:
    """Auto-complete a RESEARCHING engagement after timeout.

    If no human sign-off is received within the configured timeout
    (default: 24 hours), the engagement auto-transitions to COMPLETED.
    """
    engagement = await session.get(Engagement, engagement_id)
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")

    current_status = engagement.status.value if hasattr(engagement.status, "value") else str(engagement.status)

    if current_status != EngagementStatus.RESEARCHING:
        raise HTTPException(
            status_code=422,
            detail=f"Cannot auto-complete engagement in {current_status} status.",
        )

    # Check timeout
    timeout_hours = engagement.config.get("signoff_timeout_hours", RESEARCH_SIGNOFF_TIMEOUT_HOURS)
    if engagement.started_at:
        elapsed_hours = (datetime.now(UTC) - engagement.started_at).total_seconds() / 3600
        if elapsed_hours < timeout_hours:
            raise HTTPException(
                status_code=425,
                detail=f"Timeout not reached. {timeout_hours - elapsed_hours:.1f} hours remaining.",
            )

    # Transition RESEARCHING → COMPLETED
    engagement.status = EngagementStatus.COMPLETED
    engagement.completed_at = datetime.now(UTC)
    await session.flush()

    await log_action(
        session=session,
        action="research_auto_complete",
        actor="system",
        payload={"engagement_id": engagement_id, "timeout_hours": timeout_hours},
    )

    return {
        "id": engagement.id,
        "status": EngagementStatus.COMPLETED,
        "message": f"Research auto-completed after {timeout_hours} hour timeout.",
    }


@router.get("/{scan_id}")
async def get_scan(scan_id: str, session: AsyncSession = Depends(get_db)) -> dict:
    result = await session.execute(select(Engagement).where(Engagement.id == scan_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "id": row.id,
        "target_id": row.target_id,
        "status": row.status,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "completed_at": row.completed_at.isoformat() if row.completed_at else None,
        "iteration_count": row.iteration_count,
        "config": row.config,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.get("/{scan_id}/chains")
async def get_scan_chains(scan_id: str, session: AsyncSession = Depends(get_db)) -> dict:
    """Return the exploit chains for a scan (plan §3.3.1 endpoint).

    Reads from the dedicated ``engagements.chains`` column populated by
    the reasoner at the end of its run. This is a single-column read —
    no LLM call, no graph rebuild, no fallback path. If the reasoner
    has not yet run for this engagement the response is an empty list.

    Returns:
        ``{"scan_id": ..., "chain_count": ..., "chains": [...], "chain_run_at": ...}``.
        Each chain is a dict from ``Chain.to_dict()`` — see
        ``src/schemas/chain.py``.

    Raises:
        404 if the scan does not exist.
    """
    engagement = await session.get(Engagement, scan_id)
    if engagement is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    chains = list(engagement.chains or [])
    return {
        "scan_id": scan_id,
        "chain_count": len(chains),
        "chains": chains,
        "chain_run_at": (
            engagement.chain_run_at.isoformat()
            if engagement.chain_run_at else None
        ),
    }
