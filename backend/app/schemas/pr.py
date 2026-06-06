"""Pydantic schemas for PullRequest."""

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class PRBase(BaseModel):
    repo_full_name: str
    pr_number: int
    title: str
    author: str
    base_branch: str
    head_branch: str
    diff_url: Optional[str] = None
    html_url: Optional[str] = None
    body: Optional[str] = None
    files_changed: int = 0
    additions: int = 0
    deletions: int = 0


class PRCreate(PRBase):
    pass


class PRUpdate(BaseModel):
    status: Optional[str] = None
    risk_score: Optional[float] = None
    reviewed_at: Optional[datetime] = None


class PRRead(PRBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    status: str
    risk_score: Optional[float] = None
    created_at: datetime
    updated_at: datetime
    reviewed_at: Optional[datetime] = None
