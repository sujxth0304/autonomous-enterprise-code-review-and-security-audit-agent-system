"""Pull Request CRUD and review trigger router."""

import uuid
from typing import Any, Dict, List, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.agent_run import AgentRun
from app.models.finding import Finding
from app.models.pr import PRStatus, PullRequest
from app.schemas.agent_run import AgentRunRead
from app.schemas.finding import FindingRead
from app.schemas.pr import PRCreate, PRRead, PRUpdate
from app.workers.tasks import process_pr_review

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/prs", tags=["pull-requests"])


@router.get("/", response_model=List[PRRead])
async def list_prs(
    status: Optional[str] = Query(None),
    repo: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> List[PRRead]:
    """List all pull requests with optional filters."""
    query = select(PullRequest).order_by(PullRequest.created_at.desc())
    if status:
        query = query.where(PullRequest.status == status)
    if repo:
        query = query.where(PullRequest.repo_full_name == repo)
    query = query.limit(limit).offset(offset)

    result = await db.execute(query)
    prs = result.scalars().all()
    return [PRRead.model_validate(pr) for pr in prs]


@router.post("/", response_model=PRRead, status_code=status.HTTP_201_CREATED)
async def create_pr(
    pr_data: PRCreate,
    db: AsyncSession = Depends(get_db),
) -> PRRead:
    """Create a new pull request record."""
    pr = PullRequest(**pr_data.model_dump())
    db.add(pr)
    await db.commit()
    await db.refresh(pr)
    logger.info("pr.created", pr_id=str(pr.id), repo=pr.repo_full_name, pr_number=pr.pr_number)
    return PRRead.model_validate(pr)


@router.get("/{pr_id}", response_model=PRRead)
async def get_pr(pr_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> PRRead:
    """Get a specific pull request by ID."""
    result = await db.execute(select(PullRequest).where(PullRequest.id == pr_id))
    pr = result.scalar_one_or_none()
    if not pr:
        raise HTTPException(status_code=404, detail="Pull request not found")
    return PRRead.model_validate(pr)


@router.patch("/{pr_id}", response_model=PRRead)
async def update_pr(
    pr_id: uuid.UUID,
    updates: PRUpdate,
    db: AsyncSession = Depends(get_db),
) -> PRRead:
    """Update pull request status or metadata."""
    result = await db.execute(select(PullRequest).where(PullRequest.id == pr_id))
    pr = result.scalar_one_or_none()
    if not pr:
        raise HTTPException(status_code=404, detail="Pull request not found")

    for field, value in updates.model_dump(exclude_none=True).items():
        setattr(pr, field, value)

    await db.commit()
    await db.refresh(pr)
    return PRRead.model_validate(pr)


@router.post("/{pr_id}/trigger-review", response_model=Dict[str, Any])
async def trigger_review(
    pr_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Manually trigger a code review for a pull request."""
    result = await db.execute(select(PullRequest).where(PullRequest.id == pr_id))
    pr = result.scalar_one_or_none()
    if not pr:
        raise HTTPException(status_code=404, detail="Pull request not found")

    if pr.status == PRStatus.REVIEWING.value:
        raise HTTPException(status_code=409, detail="Review already in progress")

    # Update status and enqueue Celery task
    pr.status = PRStatus.QUEUED.value
    await db.commit()

    task = process_pr_review.delay(str(pr_id))
    logger.info("pr.review_triggered", pr_id=str(pr_id), task_id=task.id)

    return {"status": "queued", "task_id": task.id, "pr_id": str(pr_id)}


@router.get("/{pr_id}/findings", response_model=List[FindingRead])
async def get_pr_findings(
    pr_id: uuid.UUID,
    severity: Optional[str] = Query(None),
    agent_type: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
) -> List[FindingRead]:
    """Get all findings for a pull request."""
    result = await db.execute(select(PullRequest).where(PullRequest.id == pr_id))
    pr = result.scalar_one_or_none()
    if not pr:
        raise HTTPException(status_code=404, detail="Pull request not found")

    query = select(Finding).where(Finding.pr_id == pr_id)
    if severity:
        query = query.where(Finding.severity == severity)
    if agent_type:
        query = query.where(Finding.agent_type == agent_type)
    query = query.order_by(Finding.created_at.desc())

    result = await db.execute(query)
    findings = result.scalars().all()
    return [FindingRead.model_validate(f) for f in findings]


@router.get("/{pr_id}/agent-runs", response_model=List[AgentRunRead])
async def get_pr_agent_runs(
    pr_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> List[AgentRunRead]:
    """Get all agent runs for a pull request."""
    result = await db.execute(select(PullRequest).where(PullRequest.id == pr_id))
    pr = result.scalar_one_or_none()
    if not pr:
        raise HTTPException(status_code=404, detail="Pull request not found")

    query = (
        select(AgentRun)
        .where(AgentRun.pr_id == pr_id)
        .order_by(AgentRun.started_at.asc())
    )
    result = await db.execute(query)
    runs = result.scalars().all()
    return [AgentRunRead.model_validate(r) for r in runs]
