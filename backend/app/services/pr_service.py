"""Business logic for PR ingestion and status management."""

from typing import Any, Dict, Optional

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.pr import PRStatus, PullRequest
from app.schemas.pr import PRCreate

logger = structlog.get_logger(__name__)


class PRService:
    """Service class for PullRequest business logic."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def upsert_pr_from_event(
        self, event: Dict[str, Any]
    ) -> Optional[PullRequest]:
        """
        Create or update a PR record from a webhook event.

        Returns the PR if it should be reviewed, None otherwise.
        """
        repo = event.get("repo_full_name")
        pr_number = event.get("pr_number")
        action = event.get("action")

        if not repo or not pr_number:
            logger.warning("pr_service.invalid_event", event=event)
            return None

        # Check if PR already exists
        result = await self.session.execute(
            select(PullRequest).where(
                PullRequest.repo_full_name == repo,
                PullRequest.pr_number == pr_number,
            )
        )
        pr = result.scalar_one_or_none()

        if pr:
            # Update existing PR
            if action == "synchronize":
                # New commits pushed - reset status for re-review
                pr.status = PRStatus.PENDING.value
                pr.risk_score = None
                logger.info("pr_service.pr_updated_for_rereview", repo=repo, pr=pr_number)
            pr.title = event.get("pr_title", pr.title)
            pr.author = event.get("pr_author", pr.author)
            pr.base_branch = event.get("base_branch", pr.base_branch)
            pr.head_branch = event.get("head_branch", pr.head_branch)
            pr.diff_url = event.get("diff_url", pr.diff_url)
            pr.html_url = event.get("html_url", pr.html_url)
            pr.files_changed = event.get("files_changed", pr.files_changed) or 0
            pr.additions = event.get("additions", pr.additions) or 0
            pr.deletions = event.get("deletions", pr.deletions) or 0
            pr.body = event.get("body", pr.body)
        else:
            # Create new PR
            pr = PullRequest(
                repo_full_name=repo,
                pr_number=pr_number,
                title=event.get("pr_title", f"PR #{pr_number}"),
                author=event.get("pr_author", "unknown"),
                base_branch=event.get("base_branch", "main"),
                head_branch=event.get("head_branch", "unknown"),
                diff_url=event.get("diff_url"),
                html_url=event.get("html_url"),
                status=PRStatus.PENDING.value,
                files_changed=event.get("files_changed", 0) or 0,
                additions=event.get("additions", 0) or 0,
                deletions=event.get("deletions", 0) or 0,
                body=event.get("body"),
            )
            self.session.add(pr)
            logger.info("pr_service.pr_created", repo=repo, pr=pr_number)

        await self.session.commit()
        await self.session.refresh(pr)
        return pr

    async def update_status(
        self, pr_id: str, status: str, risk_score: Optional[float] = None
    ) -> Optional[PullRequest]:
        """Update PR review status."""
        import uuid
        result = await self.session.execute(
            select(PullRequest).where(PullRequest.id == uuid.UUID(pr_id))
        )
        pr = result.scalar_one_or_none()
        if not pr:
            return None

        pr.status = status
        if risk_score is not None:
            pr.risk_score = risk_score

        await self.session.commit()
        await self.session.refresh(pr)
        return pr

    async def get_pending_prs(self, limit: int = 50) -> list:
        """Get PRs pending review."""
        result = await self.session.execute(
            select(PullRequest)
            .where(PullRequest.status == PRStatus.PENDING.value)
            .order_by(PullRequest.created_at.asc())
            .limit(limit)
        )
        return result.scalars().all()
