"""AgentRun ORM model."""

import uuid
from datetime import datetime
from enum import Enum

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class AgentRunStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AgentRun(Base):
    __tablename__ = "agent_runs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    pr_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("pull_requests.id", ondelete="CASCADE"), nullable=False
    )
    agent_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=AgentRunStatus.PENDING.value
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    steps_taken: Mapped[int] = mapped_column(Integer, default=0)
    tokens_used: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str] = mapped_column(Text, nullable=True)
    trace_id: Mapped[str] = mapped_column(String(255), nullable=True)
    duration_seconds: Mapped[float] = mapped_column(Float, nullable=True)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)

    # Relationships
    pull_request: Mapped["PullRequest"] = relationship(  # noqa: F821
        "PullRequest", back_populates="agent_runs"
    )

    def __repr__(self) -> str:
        return f"<AgentRun {self.agent_type}:{self.status}>"
