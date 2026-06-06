"""PullRequest ORM model."""

import uuid
from datetime import datetime
from enum import Enum

from sqlalchemy import DateTime, Float, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class PRStatus(str, Enum):
    PENDING = "pending"
    QUEUED = "queued"
    REVIEWING = "reviewing"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class PullRequest(Base):
    __tablename__ = "pull_requests"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    repo_full_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    pr_number: Mapped[int] = mapped_column(Integer, nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    author: Mapped[str] = mapped_column(String(255), nullable=False)
    base_branch: Mapped[str] = mapped_column(String(255), nullable=False)
    head_branch: Mapped[str] = mapped_column(String(255), nullable=False)
    diff_url: Mapped[str] = mapped_column(Text, nullable=True)
    html_url: Mapped[str] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default=PRStatus.PENDING.value, index=True
    )
    risk_score: Mapped[float] = mapped_column(Float, nullable=True)
    files_changed: Mapped[int] = mapped_column(Integer, default=0)
    additions: Mapped[int] = mapped_column(Integer, default=0)
    deletions: Mapped[int] = mapped_column(Integer, default=0)
    body: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    findings: Mapped[list["Finding"]] = relationship(  # noqa: F821
        "Finding", back_populates="pull_request", cascade="all, delete-orphan"
    )
    agent_runs: Mapped[list["AgentRun"]] = relationship(  # noqa: F821
        "AgentRun", back_populates="pull_request", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<PullRequest {self.repo_full_name}#{self.pr_number}>"
