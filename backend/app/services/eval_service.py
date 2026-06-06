"""GPT-4o-as-judge evaluation service for finding quality and false positive tracking."""

from typing import Any, Dict, List, Optional

import structlog

from app.config import settings

logger = structlog.get_logger(__name__)


class EvalService:
    """Service for evaluating finding quality using LLM-as-judge."""

    def __init__(self):
        self._llm = None

    def _get_llm(self):
        """Lazy initialize GPT-4o judge."""
        if self._llm is None and settings.OPENAI_API_KEY:
            try:
                from langchain_openai import ChatOpenAI
                self._llm = ChatOpenAI(
                    model="gpt-4o",
                    temperature=0,
                    openai_api_key=settings.OPENAI_API_KEY,
                )
            except Exception as exc:
                logger.warning("eval_service.llm_init_failed", error=str(exc))
        return self._llm

    async def evaluate_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate a single finding using GPT-4o as judge.

        Returns quality score and false positive likelihood.
        """
        llm = self._get_llm()
        if not llm:
            return self._heuristic_eval(finding)

        prompt = f"""Evaluate this security/code finding from an automated review tool:

Title: {finding.get('title')}
Severity: {finding.get('severity')}
Category: {finding.get('category')}
Description: {finding.get('description')}
Code: {finding.get('code_snippet', 'N/A')}
File: {finding.get('file_path', 'N/A')} line {finding.get('line_start', 'N/A')}
Suggestion: {finding.get('suggestion', 'N/A')}

Rate this finding on:
1. accuracy (0-1): Is the finding technically correct?
2. severity_appropriate (0-1): Is severity correctly assigned?
3. actionability (0-1): Is the suggestion actionable and specific?
4. false_positive_likelihood (0-1): 0=definitely real, 1=definitely FP

Return JSON: {{"accuracy": 0.9, "severity_appropriate": 0.8, "actionability": 0.7, "fp_likelihood": 0.1, "reasoning": "..."}}"""

        try:
            response = await llm.ainvoke(prompt)
            import json
            import re
            json_match = re.search(r'\{.*\}', response.content, re.DOTALL)
            if json_match:
                scores = json.loads(json_match.group())
                overall = (
                    scores.get("accuracy", 0.7) * 0.4
                    + scores.get("severity_appropriate", 0.7) * 0.2
                    + scores.get("actionability", 0.7) * 0.4
                )
                return {
                    "quality_score": round(overall, 3),
                    "false_positive_likelihood": scores.get("fp_likelihood", 0.2),
                    "scores": scores,
                    "method": "llm_judge",
                }
        except Exception as exc:
            logger.warning("eval_service.llm_eval_failed", error=str(exc))

        return self._heuristic_eval(finding)

    def _heuristic_eval(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Heuristic evaluation without LLM."""
        score = finding.get("confidence_score", 0.7)

        # Boost for specific findings
        if finding.get("cwe_id"):
            score = min(1.0, score + 0.05)
        if finding.get("code_snippet"):
            score = min(1.0, score + 0.05)
        if finding.get("suggestion") and len(finding["suggestion"]) > 50:
            score = min(1.0, score + 0.05)

        # Reduce for vague findings
        desc = finding.get("description", "")
        if len(desc) < 50:
            score *= 0.8

        return {
            "quality_score": round(score, 3),
            "false_positive_likelihood": round(1.0 - score, 3),
            "method": "heuristic",
        }

    async def evaluate_batch(
        self, findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Evaluate a batch of findings and return enriched findings."""
        results = []
        for finding in findings:
            try:
                eval_result = await self.evaluate_finding(finding)
                enriched = {
                    **finding,
                    "confidence_score": eval_result.get("quality_score", finding.get("confidence_score", 0.7)),
                    "eval_scores": eval_result,
                }
                results.append(enriched)
            except Exception as exc:
                logger.warning("eval_service.batch_item_failed", error=str(exc))
                results.append(finding)
        return results

    async def calculate_false_positive_rate(
        self, pr_id: Optional[str] = None, days: int = 30
    ) -> Dict[str, float]:
        """Calculate false positive rate from human feedback data."""
        from datetime import datetime, timedelta, timezone

        from sqlalchemy import func, select

        from app.database import async_session_factory
        from app.models.finding import Finding

        async with async_session_factory() as session:
            since = datetime.now(timezone.utc) - timedelta(days=days)

            query = select(
                func.count(Finding.id).label("total"),
                func.sum(
                    Finding.false_positive.cast(__import__("sqlalchemy").Integer)
                ).label("fp_count"),
            ).where(
                Finding.created_at >= since,
                Finding.human_feedback.isnot(None),
            )

            if pr_id:
                import uuid
                query = query.where(Finding.pr_id == uuid.UUID(pr_id))

            result = await session.execute(query)
            row = result.fetchone()

            total = row.total or 0
            fp_count = row.fp_count or 0
            rate = fp_count / total if total > 0 else 0.0

            return {
                "total_reviewed": total,
                "false_positives": fp_count,
                "false_positive_rate": round(rate, 4),
                "period_days": days,
            }
