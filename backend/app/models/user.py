"""User ORM model."""

import uuid
from datetime import datetime
from enum import Enum

from sqlalchemy import DateTime, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class UserRole(str, Enum):
    ADMIN = "admin"
    REVIEWER = "reviewer"
    VIEWER = "viewer"


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    github_id: Mapped[str] = mapped_column(String(50), nullable=False, unique=True, index=True)
    login: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    email: Mapped[str] = mapped_column(String(255), nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=True)
    avatar_url: Mapped[str] = mapped_column(String(500), nullable=True)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default=UserRole.VIEWER.value)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_login: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"<User {self.login}>"
