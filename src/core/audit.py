"""Immutable audit logger with Merkle chain hashing."""

import hashlib
import json
from contextvars import ContextVar
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import AuditLog

# Set by the workflow engine at the start of each iteration so that
# `log_action()` calls from agents automatically pick up the current
# engagement_id. Falls back to the explicit `engagement_id=` kwarg.
_current_engagement_id: ContextVar[str | None] = ContextVar(
    "_current_engagement_id", default=None
)


def set_active_engagement(engagement_id: str | None) -> None:
    """Set the engagement_id used by subsequent log_action() calls.

    Use None to clear the binding (e.g. in tests or after the engine
    finishes). The engine calls this at the start of each iteration so
    agents that don't explicitly pass engagement_id still produce
    correctly-scoped audit log entries.
    """
    _current_engagement_id.set(engagement_id)


def get_active_engagement() -> str | None:
    """Return the engagement_id bound by set_active_engagement()."""
    return _current_engagement_id.get()


async def get_last_hash(session: AsyncSession, engagement_id: str | None) -> str:
    """Fetch the most recent audit hash for an engagement."""
    stmt = (
        select(AuditLog)
        .where(AuditLog.engagement_id == engagement_id)
        .order_by(AuditLog.timestamp.desc())
        .limit(1)
    )
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    return row.current_hash if row else "0" * 64


def _compute_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    """SHA-256(prev_hash + canonical_payload)."""
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=True, default=str)
    data = f"{prev_hash}:{canonical}".encode()
    return hashlib.sha256(data).hexdigest()


async def log_action(
    session: AsyncSession,
    action: str,
    actor: str,
    payload: dict[str, Any],
    engagement_id: str | None = None,
) -> AuditLog:
    """Append an immutable audit log entry with Merkle chain linkage.

    The engagement_id is resolved in this order:
    1. Explicit ``engagement_id`` kwarg (preferred, e.g. for ad-hoc logging)
    2. The current contextvar set by ``set_active_engagement()`` (set by
       the workflow engine at the start of each iteration)
    3. None (will produce a row with engagement_id=NULL; for unit tests
       and callers outside an engagement scope)
    """
    effective_engagement_id = (
        engagement_id
        if engagement_id is not None
        else _current_engagement_id.get()
    )
    prev_hash = await get_last_hash(session, effective_engagement_id)
    current_hash = _compute_hash(prev_hash, payload)

    entry = AuditLog(
        engagement_id=effective_engagement_id,
        action=action,
        actor=actor,
        payload=payload,
        prev_hash=prev_hash,
        current_hash=current_hash,
    )
    session.add(entry)
    await session.flush()
    return entry
