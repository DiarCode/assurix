"""Report generation routes."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_db
from src.db.models import Engagement

router = APIRouter()


@router.post("/{engagement_id}")
async def generate_report(engagement_id: str, session: AsyncSession = Depends(get_db)) -> dict:
    result = await session.execute(select(Engagement).where(Engagement.id == engagement_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return {
        "engagement_id": engagement_id,
        "status": "generated",
        "message": "Report generation is a placeholder in Phase 1 MVP.",
    }


@router.get("/{engagement_id}/download")
async def download_report(engagement_id: str, session: AsyncSession = Depends(get_db)) -> dict:
    result = await session.execute(select(Engagement).where(Engagement.id == engagement_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return {
        "engagement_id": engagement_id,
        "download_url": None,
        "message": "Report download is a placeholder in Phase 1 MVP.",
    }
