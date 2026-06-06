"""Finding ORM model."""

import uuid
from datetime import datetime
from enum import Enum

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(str, Enum):
    SECURITY = "security"
    COMPLIANCE = "compliance"
    STATIC_ANALYSIS = "static_analysis"
    DEPENDENCY = "dependency"
    PERFORMANCE = "performance"
    MAINTAINABILITY = "maintainability"
    REMEDIATION = "remediation"


class AgentType(str, Enum):
    STATIC_ANALYSIS = "static_analysis"
    SECURITY_AUDIT = "security_audit"
    DEPENDENCY = "dependency"
    COMPLIANCE = "compliance"
    REMEDIATION = "remediation"
    REFLECTION = "reflection"
    ORCHESTRATOR = "orchestrator"


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    pr_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("pull_requests.id", ondelete="CASCADE"), nullable=False
    )
    agent_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    file_path: Mapped[str] = mapped_column(String(1000), nullable=True)
    line_start: Mapped[int] = mapped_column(Integer, nullable=True)
    line_end: Mapped[int] = mapped_column(Integer, nullable=True)
    code_snippet: Mapped[str] = mapped_column(Text, nullable=True)
    suggestion: Mapped[str] = mapped_column(Text, nullable=True)
    patch: Mapped[str] = mapped_column(Text, nullable=True)
    confidence_score: Mapped[float] = mapped_column(Float, default=0.8)
    false_positive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    human_feedback: Mapped[str] = mapped_column(Text, nullable=True)
    cwe_id: Mapped[str] = mapped_column(String(50), nullable=True)
    owasp_category: Mapped[str] = mapped_column(String(50), nullable=True)
    rule_id: Mapped[str] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    pull_request: Mapped["PullRequest"] = relationship(  # noqa: F821
        "PullRequest", back_populates="findings"
    )

    def __repr__(self) -> str:
        return f"<Finding {self.severity}:{self.title[:50]}>"
