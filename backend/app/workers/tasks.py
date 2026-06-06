"""Celery tasks for async PR review processing."""

import asyncio
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import structlog
from celery import Task

from app.workers.celery_app import celery_app

logger = structlog.get_logger(__name__)


class AsyncTask(Task):
    """Base task class that supports async task functions."""

    def run_async(self, coro):
        """Run async coroutine in a new event loop."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


@celery_app.task(
    bind=True,
    base=AsyncTask,
    name="app.workers.tasks.process_pr_review",
    max_retries=3,
    default_retry_delay=60,
    queue="pr_review",
    soft_time_limit=600,  # 10 minutes soft limit
    time_limit=660,  # 11 minutes hard limit
)
def process_pr_review(self: AsyncTask, pr_id: str) -> Dict[str, Any]:
    """
    Main Celery task: run the full multi-agent PR review pipeline.

    1. Fetch PR data and diff from database/GitHub
    2. Run LangGraph orchestrator
    3. Persist findings to database
    4. Update PR status
    5. Post GitHub review comment
    """
    return self.run_async(_process_pr_review_async(pr_id, self))


async def _process_pr_review_async(pr_id: str, task: Any) -> Dict[str, Any]:
    """Async implementation of the PR review task."""
    from sqlalchemy import select

    from app.agents.orchestrator import run_pr_review
    from app.database import async_session_factory
    from app.models.agent_run import AgentRun, AgentRunStatus
    from app.models.finding import Finding
    from app.models.pr import PRStatus, PullRequest
    from app.tools.github_tools import fetch_pr_diff

    start_time = time.monotonic()
    log = logger.bind(pr_id=pr_id, task_id=task.request.id)
    log.info("task.process_pr_review.start")

    async with async_session_factory() as session:
        # Fetch PR from DB
        result = await session.execute(
            select(PullRequest).where(PullRequest.id == uuid.UUID(pr_id))
        )
        pr = result.scalar_one_or_none()
        if not pr:
            log.error("task.pr_not_found")
            return {"error": "PR not found", "pr_id": pr_id}

        # Update status to reviewing
        pr.status = PRStatus.REVIEWING.value
        await session.commit()

        # Create orchestrator agent run record
        orchestrator_run = AgentRun(
            pr_id=pr.id,
            agent_type="orchestrator",
            status=AgentRunStatus.RUNNING.value,
        )
        session.add(orchestrator_run)
        await session.commit()

        try:
            # Fetch diff from GitHub
            diff_content = ""
            try:
                diff_content = await fetch_pr_diff(
                    repo=pr.repo_full_name,
                    pr_number=pr.pr_number,
                )
                log.info("task.diff_fetched", diff_size=len(diff_content))
            except Exception as e:
                log.warning("task.diff_fetch_failed", error=str(e))
                diff_content = f"# Diff unavailable: {e}"

            pr_data = {
                "pr_id": pr_id,
                "repo_full_name": pr.repo_full_name,
                "pr_number": pr.pr_number,
                "title": pr.title,
                "author": pr.author,
                "base_branch": pr.base_branch,
                "head_branch": pr.head_branch,
                "files_changed": pr.files_changed,
                "additions": pr.additions,
                "deletions": pr.deletions,
                "body": pr.body or "",
            }

            # Run the orchestrator
            final_state = await run_pr_review(
                pr_id=pr_id,
                pr_data=pr_data,
                diff_content=diff_content,
            )

            duration = time.monotonic() - start_time
            findings = final_state.get("findings", [])

            # Persist findings
            finding_records = []
            for f in findings:
                if not f.get("title") or not f.get("description"):
                    continue
                finding = Finding(
                    pr_id=pr.id,
                    agent_type=f.get("agent_type", "orchestrator"),
                    severity=f.get("severity", "medium"),
                    category=f.get("category", "static_analysis"),
                    title=f.get("title", "")[:500],
                    description=f.get("description", ""),
                    file_path=f.get("file_path"),
                    line_start=f.get("line_start"),
                    line_end=f.get("line_end"),
                    code_snippet=f.get("code_snippet"),
                    suggestion=f.get("suggestion"),
                    patch=f.get("patch"),
                    confidence_score=f.get("confidence_score", 0.8),
                    cwe_id=f.get("cwe_id"),
                    owasp_category=f.get("owasp_category"),
                    rule_id=f.get("rule_id"),
                )
                session.add(finding)
                finding_records.append(finding)

            # Update PR
            pr.status = PRStatus.COMPLETED.value
            pr.risk_score = final_state.get("risk_score", 0.0)
            pr.reviewed_at = datetime.now(timezone.utc)

            # Update orchestrator run
            orchestrator_run.status = AgentRunStatus.COMPLETED.value
            orchestrator_run.completed_at = datetime.now(timezone.utc)
            orchestrator_run.steps_taken = final_state.get("steps_taken", 0)
            orchestrator_run.duration_seconds = duration
            orchestrator_run.findings_count = len(finding_records)

            await session.commit()

            log.info(
                "task.process_pr_review.complete",
                findings_count=len(finding_records),
                risk_score=pr.risk_score,
                duration=round(duration, 2),
            )

            # Post GitHub review comment (best effort)
            try:
                await _post_github_review(pr, final_state, findings)
            except Exception as e:
                log.warning("task.github_review_post_failed", error=str(e))

            return {
                "pr_id": pr_id,
                "status": "completed",
                "findings_count": len(finding_records),
                "risk_score": pr.risk_score,
                "duration_seconds": round(duration, 2),
            }

        except Exception as exc:
            duration = time.monotonic() - start_time
            log.error("task.process_pr_review.failed", error=str(exc), duration=duration)

            pr.status = PRStatus.FAILED.value
            orchestrator_run.status = AgentRunStatus.FAILED.value
            orchestrator_run.error_message = str(exc)[:1000]
            orchestrator_run.completed_at = datetime.now(timezone.utc)
            orchestrator_run.duration_seconds = duration
            await session.commit()

            # Retry on transient errors
            if "rate limit" in str(exc).lower() or "timeout" in str(exc).lower():
                raise task.retry(exc=exc, countdown=120)

            raise


async def _post_github_review(pr, final_state: Dict, findings: list) -> None:
    """Post the review summary as a GitHub PR comment."""
    from app.tools.github_tools import post_pr_comment

    risk_score = final_state.get("risk_score", 0.0)
    risk_emoji = "🔴" if risk_score > 0.7 else "🟡" if risk_score > 0.3 else "🟢"

    critical_count = sum(1 for f in findings if f.get("severity") == "critical")
    high_count = sum(1 for f in findings if f.get("severity") == "high")
    medium_count = sum(1 for f in findings if f.get("severity") == "medium")

    body = f"""## {risk_emoji} Automated Code Review Report

**Risk Score:** {risk_score:.2f}/1.0

### Finding Summary
| Severity | Count |
|----------|-------|
| 🔴 Critical | {critical_count} |
| 🟠 High | {high_count} |
| 🟡 Medium | {medium_count} |

### Top Findings
"""

    for finding in findings[:5]:
        if finding.get("severity") in ("critical", "high"):
            body += f"\n- **[{finding['severity'].upper()}]** {finding.get('title', 'N/A')}"
            if finding.get("file_path"):
                body += f" (`{finding['file_path']}`)"

    body += "\n\n*Generated by Autonomous Code Review Agent*"

    await post_pr_comment(
        repo=pr.repo_full_name,
        pr_number=pr.pr_number,
        body=body,
    )


@celery_app.task(
    name="app.workers.tasks.cleanup_old_task_results",
    queue="default",
)
def cleanup_old_task_results() -> Dict[str, int]:
    """Clean up old Celery task results from Redis."""
    from app.workers.celery_app import celery_app as app

    # Celery handles result expiry via result_expires config
    # This task can do additional cleanup if needed
    logger.info("task.cleanup.start")
    return {"status": "ok"}
