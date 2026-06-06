"""Unit tests for LangGraph orchestrator."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.agents.orchestrator import (
    PRReviewState,
    after_compliance,
    after_dependency_check,
    after_security_audit,
    after_static_analysis,
    route_based_on_risk,
    triage_node,
    synthesize_node,
)
from app.config import settings


class TestTriageNode:
    """Tests for the triage node."""

    @pytest.mark.asyncio
    async def test_low_risk_small_pr(self):
        """Small PRs with no security keywords should get low risk score."""
        state: PRReviewState = {
            "pr_id": "test-pr-1",
            "pr_data": {
                "repo_full_name": "owner/repo",
                "pr_number": 1,
                "files_changed": 2,
                "additions": 15,
                "deletions": 5,
                "head_branch": "fix/typo",
            },
            "diff_content": "+def hello():\n+    return 'world'\n",
            "risk_score": 0.0,
            "findings": [],
            "agent_results": {},
            "current_step": "init",
            "errors": [],
            "final_report": "",
            "steps_taken": 0,
            "skip_deep_analysis": False,
        }

        result = await triage_node(state)

        assert result["risk_score"] < settings.RISK_SCORE_THRESHOLD
        assert result["steps_taken"] == 1
        assert result["current_step"] == "triage"

    @pytest.mark.asyncio
    async def test_high_risk_security_keywords(self):
        """PRs with security keywords should get higher risk score."""
        state: PRReviewState = {
            "pr_id": "test-pr-2",
            "pr_data": {
                "repo_full_name": "owner/repo",
                "pr_number": 2,
                "files_changed": 15,
                "additions": 600,
                "deletions": 200,
                "head_branch": "refactor/auth",
            },
            "diff_content": (
                "+password = 'secret'\n"
                "+jwt_token = encode_jwt(user)\n"
                "+if auth.verify(token, secret):\n"
                "+    admin = True\n"
                "+    encrypt(data, key)\n"
                "+    sql.execute('SELECT * FROM users')\n"
                "+    eval(user_input)\n"
            ),
            "risk_score": 0.0,
            "findings": [],
            "agent_results": {},
            "current_step": "init",
            "errors": [],
            "final_report": "",
            "steps_taken": 0,
            "skip_deep_analysis": False,
        }

        result = await triage_node(state)

        assert result["risk_score"] > settings.LOW_RISK_THRESHOLD

    @pytest.mark.asyncio
    async def test_triage_increments_steps(self):
        """Triage node should increment step counter."""
        state: PRReviewState = {
            "pr_id": "test",
            "pr_data": {"files_changed": 1, "additions": 5, "deletions": 0, "head_branch": ""},
            "diff_content": "+simple change",
            "risk_score": 0.0,
            "findings": [],
            "agent_results": {},
            "current_step": "init",
            "errors": [],
            "final_report": "",
            "steps_taken": 3,
            "skip_deep_analysis": False,
        }

        result = await triage_node(state)
        assert result["steps_taken"] == 4


class TestRoutingFunctions:
    """Tests for conditional routing based on risk."""

    def test_high_risk_routes_to_static_analysis(self):
        """High risk PRs should route through all agents."""
        state: PRReviewState = {
            "pr_id": "test",
            "pr_data": {},
            "diff_content": "",
            "risk_score": 0.8,
            "findings": [],
            "agent_results": {},
            "current_step": "triage",
            "errors": [],
            "final_report": "",
            "steps_taken": 1,
            "skip_deep_analysis": False,
        }

        route = route_based_on_risk(state)
        assert route == "static_analysis"

    def test_low_risk_still_routes_to_static(self):
        """Low risk PRs still route to static analysis first."""
        state: PRReviewState = {
            "pr_id": "test",
            "pr_data": {},
            "diff_content": "",
            "risk_score": 0.1,
            "findings": [],
            "agent_results": {},
            "current_step": "triage",
            "errors": [],
            "final_report": "",
            "steps_taken": 1,
            "skip_deep_analysis": True,
        }

        route = route_based_on_risk(state)
        assert route == "static_analysis"

    def test_max_steps_routes_to_synthesize(self):
        """Hitting max steps should go directly to synthesize."""
        state: PRReviewState = {
            "pr_id": "test",
            "pr_data": {},
            "diff_content": "",
            "risk_score": 0.9,
            "findings": [],
            "agent_results": {},
            "current_step": "triage",
            "errors": [],
            "final_report": "",
            "steps_taken": settings.MAX_AGENT_STEPS + 1,
            "skip_deep_analysis": False,
        }

        route = route_based_on_risk(state)
        assert route == "synthesize"

    def test_after_static_skips_deep_for_low_risk(self):
        """After static analysis, low risk PRs skip to synthesize."""
        state: PRReviewState = {
            "pr_id": "test",
            "pr_data": {},
            "diff_content": "",
            "risk_score": 0.1,
            "findings": [],
            "agent_results": {},
            "current_step": "static_analysis",
            "errors": [],
            "final_report": "",
            "steps_taken": 2,
            "skip_deep_analysis": True,
        }

        route = after_static_analysis(state)
        assert route == "synthesize"

    def test_after_static_proceeds_for_high_risk(self):
        """After static analysis, high risk PRs proceed to security audit."""
        state: PRReviewState = {
            "pr_id": "test",
            "pr_data": {},
            "diff_content": "",
            "risk_score": 0.9,
            "findings": [],
            "agent_results": {},
            "current_step": "static_analysis",
            "errors": [],
            "final_report": "",
            "steps_taken": 2,
            "skip_deep_analysis": False,
        }

        route = after_static_analysis(state)
        assert route == "security_audit"


class TestSynthesizeNode:
    """Tests for the synthesize node."""

    @pytest.mark.asyncio
    async def test_synthesize_generates_report(self):
        """Synthesize node should generate a final report."""
        state: PRReviewState = {
            "pr_id": "test",
            "pr_data": {
                "repo_full_name": "owner/repo",
                "pr_number": 42,
                "files_changed": 5,
            },
            "diff_content": "",
            "risk_score": 0.75,
            "findings": [
                {
                    "severity": "high",
                    "category": "security",
                    "title": "SQL Injection",
                    "description": "User input not sanitized",
                    "file_path": "app.py",
                    "line_start": 42,
                    "line_end": 42,
                    "suggestion": "Use parameterized queries",
                    "confidence_score": 0.9,
                }
            ],
            "agent_results": {
                "triage": {"risk_score": 0.75},
                "static_analysis": {"findings_count": 1},
                "reflection": {
                    "deduplicated_findings": [
                        {
                            "severity": "high",
                            "category": "security",
                            "title": "SQL Injection",
                            "description": "User input not sanitized",
                            "file_path": "app.py",
                            "line_start": 42,
                            "line_end": 42,
                            "suggestion": "Use parameterized queries",
                            "confidence_score": 0.9,
                        }
                    ]
                },
            },
            "current_step": "reflection",
            "errors": [],
            "final_report": "",
            "steps_taken": 7,
            "skip_deep_analysis": False,
        }

        result = await synthesize_node(state)

        assert result["final_report"] != ""
        assert "owner/repo" in result["final_report"]
        assert "42" in result["final_report"]
        assert result["current_step"] == "synthesize"
        assert len(result["findings"]) > 0

    @pytest.mark.asyncio
    async def test_synthesize_with_no_findings(self):
        """Synthesize should work when there are no findings."""
        state: PRReviewState = {
            "pr_id": "test",
            "pr_data": {"repo_full_name": "owner/repo", "pr_number": 1, "files_changed": 1},
            "diff_content": "",
            "risk_score": 0.1,
            "findings": [],
            "agent_results": {"reflection": {"deduplicated_findings": []}},
            "current_step": "reflection",
            "errors": [],
            "final_report": "",
            "steps_taken": 3,
            "skip_deep_analysis": True,
        }

        result = await synthesize_node(state)
        assert result["final_report"] != ""
        assert result["findings"] == []


class TestOrchestratorGraph:
    """Tests for the full orchestrator graph."""

    def test_build_graph_succeeds(self):
        """Graph should build without errors."""
        from app.agents.orchestrator import build_orchestrator_graph
        graph = build_orchestrator_graph()
        assert graph is not None

    def test_get_orchestrator_singleton(self):
        """get_orchestrator should return same instance."""
        from app.agents.orchestrator import get_orchestrator
        g1 = get_orchestrator()
        g2 = get_orchestrator()
        assert g1 is g2
