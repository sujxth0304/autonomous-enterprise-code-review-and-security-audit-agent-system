"""LangGraph orchestrator for multi-agent PR review pipeline."""

import operator
import time
from datetime import datetime, timezone
from typing import Annotated, Any, Dict, List, Optional, TypedDict

import structlog
from langgraph.graph import END, StateGraph

from app.agents.compliance_agent import run_compliance_agent
from app.agents.dependency_agent import run_dependency_agent
from app.agents.remediation_agent import run_remediation_agent
from app.agents.security_audit_agent import run_security_audit_agent
from app.agents.static_analysis_agent import run_static_analysis_agent
from app.config import settings

logger = structlog.get_logger(__name__)


class PRReviewState(TypedDict):
    """State container that flows through the LangGraph orchestrator."""

    pr_id: str
    pr_data: Dict[str, Any]
    diff_content: str
    risk_score: float
    findings: Annotated[List[Dict[str, Any]], operator.add]
    agent_results: Dict[str, Any]
    current_step: str
    errors: Annotated[List[str], operator.add]
    final_report: str
    steps_taken: int
    skip_deep_analysis: bool


# ─── Node implementations ────────────────────────────────────────────────────


async def triage_node(state: PRReviewState) -> PRReviewState:
    """
    Triage node: assess PR risk score based on surface-level metrics.

    Examines file count, additions/deletions, changed files types,
    presence of security-sensitive paths, and diff size to determine
    an overall risk score [0.0, 1.0].
    """
    log = logger.bind(pr_id=state["pr_id"], node="triage")
    log.info("triage.start")

    pr_data = state["pr_data"]
    risk_factors = []

    files_changed = pr_data.get("files_changed", 0)
    additions = pr_data.get("additions", 0)
    deletions = pr_data.get("deletions", 0)
    diff_content = state.get("diff_content", "")

    # Factor 1: Size of change
    total_lines = additions + deletions
    if total_lines > 500:
        risk_factors.append(0.3)
    elif total_lines > 200:
        risk_factors.append(0.2)
    elif total_lines > 50:
        risk_factors.append(0.1)
    else:
        risk_factors.append(0.05)

    # Factor 2: Number of files
    if files_changed > 20:
        risk_factors.append(0.2)
    elif files_changed > 10:
        risk_factors.append(0.1)
    else:
        risk_factors.append(0.05)

    # Factor 3: Security-sensitive keywords in diff
    security_patterns = [
        "password", "secret", "token", "api_key", "auth", "crypto",
        "encrypt", "decrypt", "sql", "exec(", "eval(", "subprocess",
        "os.system", "pickle", "deserializ", "jwt", "oauth", "pem",
        "private_key", "chmod", "sudo", "root", "admin",
    ]
    diff_lower = diff_content.lower()
    security_hits = sum(1 for p in security_patterns if p in diff_lower)
    if security_hits > 5:
        risk_factors.append(0.3)
    elif security_hits > 2:
        risk_factors.append(0.2)
    elif security_hits > 0:
        risk_factors.append(0.1)
    else:
        risk_factors.append(0.0)

    # Factor 4: Sensitive file paths
    sensitive_paths = ["auth", "security", "crypto", "payment", "billing", "admin", "config"]
    file_path_risk = any(
        sp in (pr_data.get("head_branch", "") + diff_content[:500]).lower()
        for sp in sensitive_paths
    )
    if file_path_risk:
        risk_factors.append(0.2)
    else:
        risk_factors.append(0.0)

    risk_score = min(1.0, sum(risk_factors))
    skip_deep = risk_score < settings.LOW_RISK_THRESHOLD

    log.info("triage.complete", risk_score=risk_score, skip_deep=skip_deep)

    return {
        **state,
        "risk_score": risk_score,
        "skip_deep_analysis": skip_deep,
        "current_step": "triage",
        "steps_taken": state.get("steps_taken", 0) + 1,
        "agent_results": {**state.get("agent_results", {}), "triage": {"risk_score": risk_score}},
    }


async def static_analysis_node(state: PRReviewState) -> PRReviewState:
    """Run static analysis agent on the PR diff."""
    log = logger.bind(pr_id=state["pr_id"], node="static_analysis")
    log.info("static_analysis.start")

    try:
        findings = await run_static_analysis_agent(
            pr_data=state["pr_data"],
            diff_content=state["diff_content"],
        )
        log.info("static_analysis.complete", findings_count=len(findings))
        return {
            **state,
            "findings": findings,
            "current_step": "static_analysis",
            "steps_taken": state["steps_taken"] + 1,
            "agent_results": {
                **state["agent_results"],
                "static_analysis": {"findings_count": len(findings)},
            },
        }
    except Exception as exc:
        log.error("static_analysis.error", error=str(exc))
        return {
            **state,
            "errors": [f"static_analysis: {exc}"],
            "current_step": "static_analysis",
            "steps_taken": state["steps_taken"] + 1,
        }


async def security_audit_node(state: PRReviewState) -> PRReviewState:
    """Run security audit agent on the PR diff."""
    log = logger.bind(pr_id=state["pr_id"], node="security_audit")
    log.info("security_audit.start")

    try:
        findings = await run_security_audit_agent(
            pr_data=state["pr_data"],
            diff_content=state["diff_content"],
        )
        log.info("security_audit.complete", findings_count=len(findings))
        return {
            **state,
            "findings": findings,
            "current_step": "security_audit",
            "steps_taken": state["steps_taken"] + 1,
            "agent_results": {
                **state["agent_results"],
                "security_audit": {"findings_count": len(findings)},
            },
        }
    except Exception as exc:
        log.error("security_audit.error", error=str(exc))
        return {
            **state,
            "errors": [f"security_audit: {exc}"],
            "current_step": "security_audit",
            "steps_taken": state["steps_taken"] + 1,
        }


async def dependency_check_node(state: PRReviewState) -> PRReviewState:
    """Run dependency analysis agent."""
    log = logger.bind(pr_id=state["pr_id"], node="dependency_check")
    log.info("dependency_check.start")

    try:
        findings = await run_dependency_agent(
            pr_data=state["pr_data"],
            diff_content=state["diff_content"],
        )
        log.info("dependency_check.complete", findings_count=len(findings))
        return {
            **state,
            "findings": findings,
            "current_step": "dependency_check",
            "steps_taken": state["steps_taken"] + 1,
            "agent_results": {
                **state["agent_results"],
                "dependency": {"findings_count": len(findings)},
            },
        }
    except Exception as exc:
        log.error("dependency_check.error", error=str(exc))
        return {
            **state,
            "errors": [f"dependency_check: {exc}"],
            "current_step": "dependency_check",
            "steps_taken": state["steps_taken"] + 1,
        }


async def compliance_check_node(state: PRReviewState) -> PRReviewState:
    """Run compliance agent (GDPR, SOC2)."""
    log = logger.bind(pr_id=state["pr_id"], node="compliance_check")
    log.info("compliance_check.start")

    try:
        findings = await run_compliance_agent(
            pr_data=state["pr_data"],
            diff_content=state["diff_content"],
        )
        log.info("compliance_check.complete", findings_count=len(findings))
        return {
            **state,
            "findings": findings,
            "current_step": "compliance_check",
            "steps_taken": state["steps_taken"] + 1,
            "agent_results": {
                **state["agent_results"],
                "compliance": {"findings_count": len(findings)},
            },
        }
    except Exception as exc:
        log.error("compliance_check.error", error=str(exc))
        return {
            **state,
            "errors": [f"compliance_check: {exc}"],
            "current_step": "compliance_check",
            "steps_taken": state["steps_taken"] + 1,
        }


async def remediation_node(state: PRReviewState) -> PRReviewState:
    """Run remediation agent to generate fix suggestions."""
    log = logger.bind(pr_id=state["pr_id"], node="remediation")

    all_findings = state.get("findings", [])
    critical_and_high = [
        f for f in all_findings if f.get("severity") in ("critical", "high")
    ]

    if not critical_and_high:
        log.info("remediation.skipped_no_critical_findings")
        return {**state, "current_step": "remediation", "steps_taken": state["steps_taken"] + 1}

    log.info("remediation.start", findings_to_remediate=len(critical_and_high))

    try:
        remediation_findings = await run_remediation_agent(
            findings=critical_and_high,
            diff_content=state["diff_content"],
        )
        return {
            **state,
            "findings": remediation_findings,
            "current_step": "remediation",
            "steps_taken": state["steps_taken"] + 1,
            "agent_results": {
                **state["agent_results"],
                "remediation": {"enriched_count": len(remediation_findings)},
            },
        }
    except Exception as exc:
        log.error("remediation.error", error=str(exc))
        return {
            **state,
            "errors": [f"remediation: {exc}"],
            "current_step": "remediation",
            "steps_taken": state["steps_taken"] + 1,
        }


async def reflection_node(state: PRReviewState) -> PRReviewState:
    """Meta-agent: score finding quality and filter low-confidence results."""
    log = logger.bind(pr_id=state["pr_id"], node="reflection")
    log.info("reflection.start", total_findings=len(state.get("findings", [])))

    findings = state.get("findings", [])
    reviewed_findings = []

    for finding in findings:
        confidence = finding.get("confidence_score", 0.8)
        # Filter out very low confidence findings (likely hallucinations)
        if confidence >= 0.4:
            reviewed_findings.append(finding)
        else:
            log.warning(
                "reflection.finding_filtered",
                title=finding.get("title"),
                confidence=confidence,
            )

    # Deduplicate findings by (file_path, line_start, title)
    seen = set()
    deduped = []
    for f in reviewed_findings:
        key = (f.get("file_path"), f.get("line_start"), f.get("title", "")[:50])
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    log.info(
        "reflection.complete",
        original=len(findings),
        after_filter=len(reviewed_findings),
        after_dedup=len(deduped),
    )

    # Replace accumulated findings with clean list via a workaround
    # (we return it in agent_results and synthesize picks it up)
    return {
        **state,
        "current_step": "reflection",
        "steps_taken": state["steps_taken"] + 1,
        "agent_results": {
            **state["agent_results"],
            "reflection": {
                "original_count": len(findings),
                "final_count": len(deduped),
                "deduplicated_findings": deduped,
            },
        },
    }


async def synthesize_node(state: PRReviewState) -> PRReviewState:
    """Synthesize all agent results into a final report."""
    log = logger.bind(pr_id=state["pr_id"], node="synthesize")
    log.info("synthesize.start")

    agent_results = state.get("agent_results", {})
    reflection_data = agent_results.get("reflection", {})
    final_findings = reflection_data.get("deduplicated_findings", state.get("findings", []))

    severity_counts: Dict[str, int] = {}
    for f in final_findings:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    pr_data = state["pr_data"]
    risk_score = state["risk_score"]

    report_lines = [
        f"# Code Review Report: {pr_data.get('repo_full_name')} PR #{pr_data.get('pr_number')}",
        "",
        f"**Risk Score:** {risk_score:.2f}/1.0",
        f"**Total Findings:** {len(final_findings)}",
        "",
        "## Severity Summary",
    ]
    for sev in ("critical", "high", "medium", "low", "info"):
        count = severity_counts.get(sev, 0)
        if count > 0:
            report_lines.append(f"- **{sev.upper()}**: {count}")

    report_lines += ["", "## Agent Results"]
    for agent, result in agent_results.items():
        if agent != "reflection":
            report_lines.append(f"- **{agent}**: {result}")

    if final_findings:
        report_lines += ["", "## Critical & High Findings"]
        for f in final_findings:
            if f.get("severity") in ("critical", "high"):
                report_lines.append(
                    f"\n### [{f.get('severity', '').upper()}] {f.get('title')}"
                )
                report_lines.append(f"**File:** `{f.get('file_path', 'N/A')}` "
                                    f"(lines {f.get('line_start')}-{f.get('line_end')})")
                report_lines.append(f"\n{f.get('description', '')}")
                if f.get("suggestion"):
                    report_lines.append(f"\n**Suggestion:** {f.get('suggestion')}")

    final_report = "\n".join(report_lines)
    log.info("synthesize.complete", final_findings=len(final_findings))

    return {
        **state,
        "final_report": final_report,
        "current_step": "synthesize",
        "steps_taken": state["steps_taken"] + 1,
        "findings": final_findings,  # Replace with final list
    }


# ─── Routing logic ───────────────────────────────────────────────────────────


def route_based_on_risk(state: PRReviewState) -> str:
    """Route to appropriate analysis based on risk score."""
    if state.get("steps_taken", 0) >= settings.MAX_AGENT_STEPS:
        return "synthesize"
    if state.get("skip_deep_analysis"):
        return "static_analysis"
    return "static_analysis"


def after_static_analysis(state: PRReviewState) -> str:
    """After static analysis, proceed based on risk level."""
    if state.get("steps_taken", 0) >= settings.MAX_AGENT_STEPS:
        return "synthesize"
    if state.get("skip_deep_analysis"):
        return "synthesize"
    return "security_audit"


def after_security_audit(state: PRReviewState) -> str:
    """After security audit, proceed to dependency check."""
    if state.get("steps_taken", 0) >= settings.MAX_AGENT_STEPS:
        return "synthesize"
    return "dependency_check"


def after_dependency_check(state: PRReviewState) -> str:
    """After dependency check, proceed to compliance."""
    if state.get("steps_taken", 0) >= settings.MAX_AGENT_STEPS:
        return "synthesize"
    return "compliance_check"


def after_compliance(state: PRReviewState) -> str:
    """After compliance check, proceed to remediation."""
    if state.get("steps_taken", 0) >= settings.MAX_AGENT_STEPS:
        return "synthesize"
    return "remediation"


# ─── Graph construction ──────────────────────────────────────────────────────


def build_orchestrator_graph() -> StateGraph:
    """Build and compile the LangGraph orchestration graph."""
    graph = StateGraph(PRReviewState)

    # Add nodes
    graph.add_node("triage", triage_node)
    graph.add_node("static_analysis", static_analysis_node)
    graph.add_node("security_audit", security_audit_node)
    graph.add_node("dependency_check", dependency_check_node)
    graph.add_node("compliance_check", compliance_check_node)
    graph.add_node("remediation", remediation_node)
    graph.add_node("reflection", reflection_node)
    graph.add_node("synthesize", synthesize_node)

    # Set entry point
    graph.set_entry_point("triage")

    # Add edges
    graph.add_conditional_edges(
        "triage",
        route_based_on_risk,
        {
            "static_analysis": "static_analysis",
            "synthesize": "synthesize",
        },
    )
    graph.add_conditional_edges(
        "static_analysis",
        after_static_analysis,
        {
            "security_audit": "security_audit",
            "synthesize": "synthesize",
        },
    )
    graph.add_conditional_edges(
        "security_audit",
        after_security_audit,
        {
            "dependency_check": "dependency_check",
            "synthesize": "synthesize",
        },
    )
    graph.add_conditional_edges(
        "dependency_check",
        after_dependency_check,
        {
            "compliance_check": "compliance_check",
            "synthesize": "synthesize",
        },
    )
    graph.add_conditional_edges(
        "compliance_check",
        after_compliance,
        {
            "remediation": "remediation",
            "synthesize": "synthesize",
        },
    )
    graph.add_edge("remediation", "reflection")
    graph.add_edge("reflection", "synthesize")
    graph.add_edge("synthesize", END)

    return graph.compile()


# Singleton compiled graph
_orchestrator_graph = None


def get_orchestrator():
    """Get or create the singleton orchestrator graph."""
    global _orchestrator_graph
    if _orchestrator_graph is None:
        _orchestrator_graph = build_orchestrator_graph()
    return _orchestrator_graph


async def run_pr_review(
    pr_id: str,
    pr_data: Dict[str, Any],
    diff_content: str,
) -> Dict[str, Any]:
    """
    Execute the full PR review pipeline.

    Returns the final state including findings, risk score, and report.
    """
    orchestrator = get_orchestrator()
    start_time = time.monotonic()

    initial_state: PRReviewState = {
        "pr_id": pr_id,
        "pr_data": pr_data,
        "diff_content": diff_content,
        "risk_score": 0.0,
        "findings": [],
        "agent_results": {},
        "current_step": "init",
        "errors": [],
        "final_report": "",
        "steps_taken": 0,
        "skip_deep_analysis": False,
    }

    logger.info("orchestrator.start", pr_id=pr_id)

    try:
        final_state = await orchestrator.ainvoke(initial_state)
    except Exception as exc:
        logger.error("orchestrator.failed", pr_id=pr_id, error=str(exc))
        raise

    duration = time.monotonic() - start_time
    logger.info(
        "orchestrator.complete",
        pr_id=pr_id,
        duration_seconds=round(duration, 2),
        findings_count=len(final_state.get("findings", [])),
        risk_score=final_state.get("risk_score"),
    )

    return final_state
