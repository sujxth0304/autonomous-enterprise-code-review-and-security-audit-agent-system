"""Initial schema: users, pull_requests, findings, agent_runs

Revision ID: 001_initial
Revises:
Create Date: 2024-01-01 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ─── users ────────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("github_id", sa.String(50), nullable=False),
        sa.Column("login", sa.String(255), nullable=False),
        sa.Column("email", sa.String(255), nullable=True),
        sa.Column("name", sa.String(255), nullable=True),
        sa.Column("avatar_url", sa.String(500), nullable=True),
        sa.Column("role", sa.String(20), nullable=False, server_default="viewer"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("github_id"),
        sa.UniqueConstraint("login"),
    )
    op.create_index("ix_users_github_id", "users", ["github_id"])

    # ─── pull_requests ────────────────────────────────────────────────────────
    op.create_table(
        "pull_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("repo_full_name", sa.String(255), nullable=False),
        sa.Column("pr_number", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("author", sa.String(255), nullable=False),
        sa.Column("base_branch", sa.String(255), nullable=False),
        sa.Column("head_branch", sa.String(255), nullable=False),
        sa.Column("diff_url", sa.Text(), nullable=True),
        sa.Column("html_url", sa.Text(), nullable=True),
        sa.Column("body", sa.Text(), nullable=True),
        sa.Column("status", sa.String(50), nullable=False, server_default="pending"),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("files_changed", sa.Integer(), server_default="0"),
        sa.Column("additions", sa.Integer(), server_default="0"),
        sa.Column("deletions", sa.Integer(), server_default="0"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            onupdate=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_pull_requests_repo_full_name", "pull_requests", ["repo_full_name"])
    op.create_index("ix_pull_requests_status", "pull_requests", ["status"])
    op.create_unique_constraint(
        "uq_pr_repo_number", "pull_requests", ["repo_full_name", "pr_number"]
    )

    # ─── findings ─────────────────────────────────────────────────────────────
    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "pr_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("pull_requests.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("agent_type", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("category", sa.String(50), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("file_path", sa.String(1000), nullable=True),
        sa.Column("line_start", sa.Integer(), nullable=True),
        sa.Column("line_end", sa.Integer(), nullable=True),
        sa.Column("code_snippet", sa.Text(), nullable=True),
        sa.Column("suggestion", sa.Text(), nullable=True),
        sa.Column("patch", sa.Text(), nullable=True),
        sa.Column("confidence_score", sa.Float(), server_default="0.8"),
        sa.Column("false_positive", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("human_feedback", sa.Text(), nullable=True),
        sa.Column("cwe_id", sa.String(50), nullable=True),
        sa.Column("owasp_category", sa.String(50), nullable=True),
        sa.Column("rule_id", sa.String(255), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_findings_pr_id", "findings", ["pr_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_category", "findings", ["category"])
    op.create_index("ix_findings_agent_type", "findings", ["agent_type"])

    # ─── agent_runs ───────────────────────────────────────────────────────────
    op.create_table(
        "agent_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "pr_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("pull_requests.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("agent_type", sa.String(50), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("steps_taken", sa.Integer(), server_default="0"),
        sa.Column("tokens_used", sa.Integer(), server_default="0"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("trace_id", sa.String(255), nullable=True),
        sa.Column("duration_seconds", sa.Float(), nullable=True),
        sa.Column("findings_count", sa.Integer(), server_default="0"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_agent_runs_pr_id", "agent_runs", ["pr_id"])
    op.create_index("ix_agent_runs_agent_type", "agent_runs", ["agent_type"])


def downgrade() -> None:
    op.drop_table("agent_runs")
    op.drop_table("findings")
    op.drop_table("pull_requests")
    op.drop_table("users")
