"""Agent run status router."""

import uuid
from typing import List, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.agent_run import AgentRun
from app.schemas.agent_run import AgentRunRead

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/agents", tags=["agents"])


@router.get("/runs/", response_model=List[AgentRunRead])
async def list_agent_runs(
    agent_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> List[AgentRunRead]:
    """List agent runs with optional filters."""
    query = select(AgentRun).order_by(AgentRun.started_at.desc())
    if agent_type:
        query = query.where(AgentRun.agent_type == agent_type)
    if status:
        query = query.where(AgentRun.status == status)
    query = query.limit(limit).offset(offset)

    result = await db.execute(query)
    runs = result.scalars().all()
    return [AgentRunRead.model_validate(r) for r in runs]


@router.get("/runs/{run_id}", response_model=AgentRunRead)
async def get_agent_run(
    run_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> AgentRunRead:
    """Get a specific agent run by ID."""
    result = await db.execute(select(AgentRun).where(AgentRun.id == run_id))
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Agent run not found")
    return AgentRunRead.model_validate(run)
