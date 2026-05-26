"""Finding routes."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_db
from src.db.models import Finding

router = APIRouter()


@router.get("")
async def list_findings(
    engagement_id: str | None = None,
    severity: str | None = None,
    validated_only: bool = False,
    session: AsyncSession = Depends(get_db),
) -> list[dict]:
    stmt = select(Finding)
    if engagement_id:
        stmt = stmt.where(Finding.engagement_id == engagement_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if validated_only:
        stmt = stmt.where(Finding.validated.is_(True))
    result = await session.execute(stmt)
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "engagement_id": r.engagement_id,
            "title": r.title,
            "description": r.description,
            "severity": r.severity,
            "confidence_score": r.confidence_score,
            "validated": r.validated,
            "cwe_id": r.cwe_id,
            "owasp_category": r.owasp_category,
            "source_agent": r.source_agent,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


@router.get("/{finding_id}")
async def get_finding(finding_id: str, session: AsyncSession = Depends(get_db)) -> dict:
    result = await session.execute(select(Finding).where(Finding.id == finding_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {
        "id": row.id,
        "engagement_id": row.engagement_id,
        "title": row.title,
        "description": row.description,
        "severity": row.severity,
        "confidence_score": row.confidence_score,
        "validated": row.validated,
        "cwe_id": row.cwe_id,
        "owasp_category": row.owasp_category,
        "remediation": row.remediation,
        "source_agent": row.source_agent,
        "finding_metadata": row.finding_metadata,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }
