"""Target CRUD routes."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_db
from src.db.models import Target

router = APIRouter()


@router.get("")
async def list_targets(session: AsyncSession = Depends(get_db)) -> list[dict]:
    result = await session.execute(select(Target))
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "url": r.url,
            "repo_path": r.repo_path,
            "target_type": r.target_type,
            "verified": r.verified,
            "policy_id": r.policy_id,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


@router.post("")
async def create_target(payload: dict, session: AsyncSession = Depends(get_db)) -> dict:
    target = Target(
        name=payload.get("name", ""),
        url=payload.get("url"),
        repo_path=payload.get("repo_path"),
        target_type=payload.get("target_type", "webapp"),
        verified=payload.get("verified", False),
        policy_id=payload.get("policy_id"),
    )
    session.add(target)
    await session.flush()
    return {"id": target.id, "name": target.name}


@router.get("/{target_id}")
async def get_target(target_id: str, session: AsyncSession = Depends(get_db)) -> dict:
    result = await session.execute(select(Target).where(Target.id == target_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Target not found")
    return {
        "id": row.id,
        "name": row.name,
        "url": row.url,
        "repo_path": row.repo_path,
        "target_type": row.target_type,
        "verified": row.verified,
        "policy_id": row.policy_id,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }
