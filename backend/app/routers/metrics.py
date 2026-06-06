"""Aggregate metrics router for dashboard analytics."""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import structlog
from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.agent_run import AgentRun
from app.models.finding import Finding
from app.models.pr import PullRequest

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/metrics", tags=["metrics"])


@router.get("/summary", response_model=Dict[str, Any])
async def get_summary(
    days: int = Query(7, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Get aggregate summary metrics for the dashboard."""
    since = datetime.now(timezone.utc) - timedelta(days=days)

    # Total PRs reviewed in period
    total_prs_result = await db.execute(
        select(func.count(PullRequest.id)).where(PullRequest.created_at >= since)
    )
    total_prs = total_prs_result.scalar() or 0

    # Total findings in period
    total_findings_result = await db.execute(
        select(func.count(Finding.id)).where(Finding.created_at >= since)
    )
    total_findings = total_findings_result.scalar() or 0

    # False positive count
    fp_result = await db.execute(
        select(func.count(Finding.id)).where(
            Finding.created_at >= since, Finding.false_positive == True  # noqa: E712
        )
    )
    fp_count = fp_result.scalar() or 0

    fp_rate = round(fp_count / total_findings, 3) if total_findings > 0 else 0.0

    # Average review duration
    avg_duration_result = await db.execute(
        select(func.avg(AgentRun.duration_seconds)).where(
            AgentRun.started_at >= since, AgentRun.duration_seconds.isnot(None)
        )
    )
    avg_duration = avg_duration_result.scalar() or 0.0

    # Findings by severity
    severity_result = await db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.created_at >= since)
        .group_by(Finding.severity)
    )
    severity_breakdown = {row[0]: row[1] for row in severity_result.fetchall()}

    # Findings by category
    category_result = await db.execute(
        select(Finding.category, func.count(Finding.id))
        .where(Finding.created_at >= since)
        .group_by(Finding.category)
    )
    category_breakdown = {row[0]: row[1] for row in category_result.fetchall()}

    return {
        "period_days": days,
        "total_prs_reviewed": total_prs,
        "total_findings": total_findings,
        "false_positive_rate": fp_rate,
        "avg_review_duration_seconds": round(avg_duration, 1),
        "severity_breakdown": severity_breakdown,
        "category_breakdown": category_breakdown,
    }


@router.get("/findings-over-time", response_model=List[Dict[str, Any]])
async def get_findings_over_time(
    days: int = Query(30, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Get daily finding counts over time for trend charts."""
    since = datetime.now(timezone.utc) - timedelta(days=days)

    result = await db.execute(
        select(
            func.date_trunc("day", Finding.created_at).label("date"),
            Finding.severity,
            func.count(Finding.id).label("count"),
        )
        .where(Finding.created_at >= since)
        .group_by(func.date_trunc("day", Finding.created_at), Finding.severity)
        .order_by(func.date_trunc("day", Finding.created_at))
    )

    rows = result.fetchall()
    return [{"date": str(row.date)[:10], "severity": row.severity, "count": row.count} for row in rows]


@router.get("/top-repos", response_model=List[Dict[str, Any]])
async def get_top_repos(
    days: int = Query(30, ge=1, le=90),
    limit: int = Query(10, le=50),
    db: AsyncSession = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Get repositories with most findings."""
    since = datetime.now(timezone.utc) - timedelta(days=days)

    result = await db.execute(
        select(
            PullRequest.repo_full_name,
            func.count(Finding.id).label("finding_count"),
        )
        .join(Finding, Finding.pr_id == PullRequest.id)
        .where(Finding.created_at >= since)
        .group_by(PullRequest.repo_full_name)
        .order_by(func.count(Finding.id).desc())
        .limit(limit)
    )

    return [
        {"repo": row.repo_full_name, "finding_count": row.finding_count}
        for row in result.fetchall()
    ]


@router.get("/agent-performance", response_model=List[Dict[str, Any]])
async def get_agent_performance(
    days: int = Query(7, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Get per-agent performance metrics."""
    since = datetime.now(timezone.utc) - timedelta(days=days)

    result = await db.execute(
        select(
            AgentRun.agent_type,
            func.count(AgentRun.id).label("run_count"),
            func.avg(AgentRun.duration_seconds).label("avg_duration"),
            func.sum(AgentRun.tokens_used).label("total_tokens"),
            func.avg(AgentRun.findings_count).label("avg_findings"),
        )
        .where(AgentRun.started_at >= since)
        .group_by(AgentRun.agent_type)
    )

    return [
        {
            "agent_type": row.agent_type,
            "run_count": row.run_count,
            "avg_duration_seconds": round(row.avg_duration or 0, 1),
            "total_tokens_used": row.total_tokens or 0,
            "avg_findings_per_run": round(row.avg_findings or 0, 1),
        }
        for row in result.fetchall()
    ]
