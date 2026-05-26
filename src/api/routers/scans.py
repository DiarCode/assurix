"""Scan (engagement) routes."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_db
from src.db.models import Engagement, EngagementStatus

router = APIRouter()


@router.get("")
async def list_scans(session: AsyncSession = Depends(get_db)) -> list[dict]:
    result = await session.execute(select(Engagement))
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "target_id": r.target_id,
            "status": r.status,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            "iteration_count": r.iteration_count,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


@router.post("")
async def start_scan(payload: dict, session: AsyncSession = Depends(get_db)) -> dict:
    engagement = Engagement(
        target_id=payload["target_id"],
        status=EngagementStatus.PENDING,
        config=payload.get("config", {}),
    )
    session.add(engagement)
    await session.flush()
    return {"id": engagement.id, "status": engagement.status, "target_id": engagement.target_id}


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
