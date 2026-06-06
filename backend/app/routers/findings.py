"""Findings CRUD and feedback router."""

import uuid
from typing import List, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.finding import Finding
from app.schemas.finding import FindingFeedback, FindingRead

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("/", response_model=List[FindingRead])
async def list_findings(
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    agent_type: Optional[str] = Query(None),
    false_positive: Optional[bool] = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> List[FindingRead]:
    """List findings with optional filters."""
    query = select(Finding).order_by(Finding.created_at.desc())
    if severity:
        query = query.where(Finding.severity == severity)
    if category:
        query = query.where(Finding.category == category)
    if agent_type:
        query = query.where(Finding.agent_type == agent_type)
    if false_positive is not None:
        query = query.where(Finding.false_positive == false_positive)
    query = query.limit(limit).offset(offset)

    result = await db.execute(query)
    findings = result.scalars().all()
    return [FindingRead.model_validate(f) for f in findings]


@router.get("/{finding_id}", response_model=FindingRead)
async def get_finding(
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> FindingRead:
    """Get a specific finding by ID."""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return FindingRead.model_validate(finding)


@router.post("/{finding_id}/feedback", response_model=FindingRead)
async def submit_feedback(
    finding_id: uuid.UUID,
    feedback: FindingFeedback,
    db: AsyncSession = Depends(get_db),
) -> FindingRead:
    """Submit human feedback on a finding (accept/reject as false positive)."""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.false_positive = feedback.false_positive
    finding.human_feedback = feedback.human_feedback
    await db.commit()
    await db.refresh(finding)

    logger.info(
        "finding.feedback_submitted",
        finding_id=str(finding_id),
        false_positive=feedback.false_positive,
    )
    return FindingRead.model_validate(finding)
