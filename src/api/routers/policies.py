"""Scope policy CRUD routes."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_db
from src.db.models import ScopePolicy

router = APIRouter()


@router.get("")
async def list_policies(session: AsyncSession = Depends(get_db)) -> list[dict]:
    result = await session.execute(select(ScopePolicy))
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "allowed_domains": r.allowed_domains,
            "rate_rps": r.rate_rps,
            "max_iterations": r.max_iterations,
            "safe_mode": r.safe_mode,
            "allow_destructive": r.allow_destructive,
        }
        for r in rows
    ]


@router.post("")
async def create_policy(payload: dict, session: AsyncSession = Depends(get_db)) -> dict:
    policy = ScopePolicy(
        name=payload.get("name", "default"),
        allowed_domains=payload.get("allowed_domains", []),
        rate_rps=payload.get("rate_rps", 10.0),
        max_iterations=payload.get("max_iterations", 50),
        safe_mode=payload.get("safe_mode", True),
        allow_destructive=payload.get("allow_destructive", False),
        auth_state=payload.get("auth_state"),
    )
    session.add(policy)
    await session.flush()
    return {"id": policy.id, "name": policy.name}


@router.get("/{policy_id}")
async def get_policy(policy_id: str, session: AsyncSession = Depends(get_db)) -> dict:
    result = await session.execute(select(ScopePolicy).where(ScopePolicy.id == policy_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Policy not found")
    return {
        "id": row.id,
        "name": row.name,
        "allowed_domains": row.allowed_domains,
        "rate_rps": row.rate_rps,
        "max_iterations": row.max_iterations,
        "safe_mode": row.safe_mode,
        "allow_destructive": row.allow_destructive,
        "auth_state": row.auth_state,
    }
