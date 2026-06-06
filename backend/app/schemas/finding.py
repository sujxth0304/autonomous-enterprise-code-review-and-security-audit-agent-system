"""Pydantic schemas for Finding."""

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class FindingBase(BaseModel):
    pr_id: uuid.UUID
    agent_type: str
    severity: str
    category: str
    title: str
    description: str
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    code_snippet: Optional[str] = None
    suggestion: Optional[str] = None
    patch: Optional[str] = None
    confidence_score: float = 0.8
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    rule_id: Optional[str] = None


class FindingCreate(FindingBase):
    pass


class FindingRead(FindingBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    false_positive: bool
    human_feedback: Optional[str] = None
    created_at: datetime


class FindingFeedback(BaseModel):
    false_positive: bool
    human_feedback: Optional[str] = None
