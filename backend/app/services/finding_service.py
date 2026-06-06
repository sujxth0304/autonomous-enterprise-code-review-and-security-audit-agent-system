"""Finding CRUD and deduplication service."""

from typing import Any, Dict, List, Optional
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding

logger = structlog.get_logger(__name__)


class FindingService:
    """Service for finding management and deduplication."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def bulk_create_findings(
        self, findings_data: List[Dict[str, Any]], pr_id: UUID
    ) -> List[Finding]:
        """Create multiple findings, deduplicating against existing ones."""
        existing_result = await self.session.execute(
            select(Finding).where(Finding.pr_id == pr_id)
        )
        existing = existing_result.scalars().all()
        existing_keys = {
            (f.file_path, f.line_start, f.title[:40].lower()) for f in existing
        }

        new_findings = []
        for data in findings_data:
            key = (
                data.get("file_path"),
                data.get("line_start"),
                data.get("title", "")[:40].lower(),
            )
            if key in existing_keys:
                logger.debug("finding_service.dedup_skip", title=data.get("title"))
                continue

            finding = Finding(
                pr_id=pr_id,
                agent_type=data.get("agent_type", "orchestrator"),
                severity=data.get("severity", "medium"),
                category=data.get("category", "static_analysis"),
                title=data.get("title", "")[:500],
                description=data.get("description", ""),
                file_path=data.get("file_path"),
                line_start=data.get("line_start"),
                line_end=data.get("line_end"),
                code_snippet=data.get("code_snippet"),
                suggestion=data.get("suggestion"),
                patch=data.get("patch"),
                confidence_score=data.get("confidence_score", 0.8),
                cwe_id=data.get("cwe_id"),
                owasp_category=data.get("owasp_category"),
                rule_id=data.get("rule_id"),
            )
            self.session.add(finding)
            new_findings.append(finding)
            existing_keys.add(key)

        await self.session.commit()
        logger.info(
            "finding_service.bulk_create",
            pr_id=str(pr_id),
            new=len(new_findings),
            deduplicated=len(findings_data) - len(new_findings),
        )
        return new_findings

    async def get_pr_findings_summary(self, pr_id: UUID) -> Dict[str, int]:
        """Get severity summary for a PR's findings."""
        from sqlalchemy import func

        result = await self.session.execute(
            select(Finding.severity, func.count(Finding.id))
            .where(Finding.pr_id == pr_id)
            .group_by(Finding.severity)
        )
        return {row[0]: row[1] for row in result.fetchall()}

    async def mark_false_positive(
        self, finding_id: UUID, is_fp: bool, feedback: Optional[str] = None
    ) -> Optional[Finding]:
        """Mark a finding as false positive with optional human feedback."""
        result = await self.session.execute(
            select(Finding).where(Finding.id == finding_id)
        )
        finding = result.scalar_one_or_none()
        if not finding:
            return None

        finding.false_positive = is_fp
        finding.human_feedback = feedback
        await self.session.commit()
        await self.session.refresh(finding)

        logger.info(
            "finding_service.feedback_recorded",
            finding_id=str(finding_id),
            false_positive=is_fp,
        )
        return finding
