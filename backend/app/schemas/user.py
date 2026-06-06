"""Pydantic schemas for User and Auth."""

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    github_id: str
    login: str
    email: Optional[str] = None
    name: Optional[str] = None
    avatar_url: Optional[str] = None
    role: str
    created_at: datetime


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenData(BaseModel):
    sub: str
    github_id: str
    role: str
