"""Reflection meta-agent: quality scoring and false positive filtering."""

from typing import Any, Dict, List, Optional

import structlog
from langchain_openai import ChatOpenAI
from pydantic import BaseModel

from app.config import settings

logger = structlog.get_logger(__name__)


class FindingQualityScore(BaseModel):
    finding_title: str
    confidence_score: float
    is_likely_false_positive: bool
    reasoning: str
    suggested_revision: Optional[str] = None


async def score_finding_quality(
    finding: Dict[str, Any],
    llm: Optional[Any] = None,
) -> FindingQualityScore:
    """
    Use GPT-4o as a judge to score a finding's quality and likelihood of being a false positive.
    Falls back to heuristic scoring if OpenAI is unavailable.
    """
    if not settings.OPENAI_API_KEY or not llm:
        return _heuristic_quality_score(finding)

    prompt = f"""You are a senior security engineer reviewing an automated code analysis finding.
Evaluate whether this finding is accurate, actionable, and not a false positive.

Finding:
- Title: {finding.get('title', '')}
- Severity: {finding.get('severity', '')}
- Category: {finding.get('category', '')}
- Description: {finding.get('description', '')}
- Code Snippet: {finding.get('code_snippet', 'N/A')}
- File: {finding.get('file_path', 'N/A')} line {finding.get('line_start', 'N/A')}

Evaluate:
1. Is the finding technically accurate?
2. Is the code snippet clearly vulnerable/problematic?
3. Could this be a test file or example code?
4. Is the description specific and actionable?

Respond with JSON:
{{
  "confidence_score": 0.0-1.0,
  "is_likely_false_positive": true/false,
  "reasoning": "brief explanation",
  "suggested_revision": "optional revised description if needed"
}}"""

    try:
        response = await llm.ainvoke(prompt)
        import json
        content = response.content
        # Extract JSON from response
        json_match = __import__("re").search(r'\{.*\}', content, __import__("re").DOTALL)
        if json_match:
            data = json.loads(json_match.group())
            return FindingQualityScore(
                finding_title=finding.get("title", ""),
                confidence_score=float(data.get("confidence_score", 0.7)),
                is_likely_false_positive=bool(data.get("is_likely_false_positive", False)),
                reasoning=data.get("reasoning", ""),
                suggested_revision=data.get("suggested_revision"),
            )
    except Exception as exc:
        logger.warning("reflection.llm_score_failed", error=str(exc))

    return _heuristic_quality_score(finding)


def _heuristic_quality_score(finding: Dict[str, Any]) -> FindingQualityScore:
    """Heuristic-based quality scoring without LLM."""
    score = finding.get("confidence_score", 0.8)
    is_fp = False
    reasoning = "Heuristic evaluation"

    title = finding.get("title", "").lower()
    desc = finding.get("description", "").lower()
    file_path = finding.get("file_path", "").lower()
    code = finding.get("code_snippet", "").lower()

    # Reduce confidence for test files
    if any(kw in file_path for kw in ["test_", "_test", "spec_", "_spec", "/tests/", "/test/"]):
        score *= 0.5
        is_fp = score < 0.5
        reasoning = "Finding in test file - may be intentional test code"

    # Reduce confidence for documentation/example files
    if any(kw in file_path for kw in ["example", "sample", "demo", "fixture"]):
        score *= 0.6
        reasoning = "Finding in example/sample file"

    # Boost confidence for specific patterns
    if any(kw in code for kw in ["password", "secret", "api_key", "token"]) and "hardcoded" in desc:
        score = min(1.0, score * 1.2)
        reasoning = "High confidence: hardcoded credential pattern"

    # Reduce for very generic findings
    if "may" in desc and "possibly" in desc:
        score *= 0.7
        reasoning = "Uncertain language in description reduces confidence"

    return FindingQualityScore(
        finding_title=finding.get("title", ""),
        confidence_score=round(score, 3),
        is_likely_false_positive=is_fp,
        reasoning=reasoning,
    )


async def run_reflection_agent(
    findings: List[Dict[str, Any]],
    false_positive_threshold: float = 0.4,
) -> Dict[str, Any]:
    """
    Meta-agent that reviews all findings for quality.

    - Scores each finding (0-1 confidence)
    - Marks likely false positives
    - Re-evaluates low confidence findings
    - Returns filtered, quality-reviewed findings
    """
    llm = None
    if settings.OPENAI_API_KEY:
        try:
            llm = ChatOpenAI(
                model="gpt-4o",
                temperature=0,
                openai_api_key=settings.OPENAI_API_KEY,
            )
        except Exception:
            pass

    reviewed_findings = []
    false_positive_count = 0
    total_findings = len(findings)

    for finding in findings:
        quality_score = await score_finding_quality(finding, llm)

        updated_finding = {
            **finding,
            "confidence_score": quality_score.confidence_score,
        }

        if quality_score.is_likely_false_positive or quality_score.confidence_score < false_positive_threshold:
            false_positive_count += 1
            logger.info(
                "reflection.filtered_finding",
                title=finding.get("title"),
                confidence=quality_score.confidence_score,
                reason=quality_score.reasoning,
            )
            continue  # Filter out

        if quality_score.suggested_revision and quality_score.confidence_score < 0.7:
            updated_finding["description"] = (
                f"{finding.get('description', '')}\n\n"
                f"**Reviewer Note:** {quality_score.suggested_revision}"
            )

        reviewed_findings.append(updated_finding)

    # Deduplicate by (file_path, line_start, title prefix)
    seen = set()
    deduped = []
    for f in reviewed_findings:
        key = (
            f.get("file_path", ""),
            f.get("line_start"),
            f.get("title", "")[:40].lower(),
        )
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    false_positive_rate = false_positive_count / total_findings if total_findings > 0 else 0.0

    logger.info(
        "reflection_agent.complete",
        original=total_findings,
        filtered=false_positive_count,
        final=len(deduped),
        fp_rate=round(false_positive_rate, 3),
    )

    return {
        "findings": deduped,
        "original_count": total_findings,
        "filtered_count": false_positive_count,
        "final_count": len(deduped),
        "false_positive_rate": false_positive_rate,
    }
