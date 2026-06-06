"""Pydantic schemas for AgentRun."""

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class AgentRunBase(BaseModel):
    pr_id: uuid.UUID
    agent_type: str


class AgentRunCreate(AgentRunBase):
    pass


class AgentRunUpdate(BaseModel):
    status: Optional[str] = None
    completed_at: Optional[datetime] = None
    steps_taken: Optional[int] = None
    tokens_used: Optional[int] = None
    error_message: Optional[str] = None
    trace_id: Optional[str] = None
    duration_seconds: Optional[float] = None
    findings_count: Optional[int] = None


class AgentRunRead(AgentRunBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    steps_taken: int
    tokens_used: int
    error_message: Optional[str] = None
    trace_id: Optional[str] = None
    duration_seconds: Optional[float] = None
    findings_count: int
