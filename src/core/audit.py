"""Immutable audit logger with Merkle chain hashing."""

import hashlib
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import AuditLog


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
    """Append an immutable audit log entry with Merkle chain linkage."""
    prev_hash = await get_last_hash(session, engagement_id)
    current_hash = _compute_hash(prev_hash, payload)

    entry = AuditLog(
        engagement_id=engagement_id,
        action=action,
        actor=actor,
        payload=payload,
        prev_hash=prev_hash,
        current_hash=current_hash,
    )
    session.add(entry)
    await session.flush()
    return entry
