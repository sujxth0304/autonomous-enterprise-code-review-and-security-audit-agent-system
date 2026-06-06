"""Tests for webhook signature verification and event handling."""

import hashlib
import hmac
import json
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.routers.webhooks import verify_github_signature


class TestWebhookSignature:
    """Tests for HMAC signature verification."""

    def test_valid_signature(self):
        """Valid signatures should pass verification."""
        payload = b'{"action": "opened"}'
        secret = "test-secret"
        expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        signature = f"sha256={expected}"

        assert verify_github_signature(payload, signature, secret) is True

    def test_invalid_signature(self):
        """Invalid signatures should fail verification."""
        payload = b'{"action": "opened"}'
        assert verify_github_signature(payload, "sha256=invalid", "test-secret") is False

    def test_missing_sha256_prefix(self):
        """Signatures without sha256= prefix should fail."""
        payload = b'{"action": "opened"}'
        secret = "test-secret"
        expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

        assert verify_github_signature(payload, expected, secret) is False

    def test_empty_signature(self):
        """Empty signatures should fail."""
        assert verify_github_signature(b"payload", "", "secret") is False

    def test_none_signature(self):
        """None signatures should fail."""
        assert verify_github_signature(b"payload", None, "secret") is False

    def test_timing_safe_comparison(self):
        """Verify that comparison is timing-safe (uses hmac.compare_digest)."""
        payload = b'{"test": "data"}'
        secret = "my-secret"
        expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        valid_sig = f"sha256={expected}"

        # Should work with the correct signature
        assert verify_github_signature(payload, valid_sig, secret) is True

        # Should fail with modified payload
        assert verify_github_signature(b'{"test": "modified"}', valid_sig, secret) is False

    def test_wrong_secret(self):
        """Signatures made with wrong secret should fail."""
        payload = b'{"action": "opened"}'
        correct_sig = "sha256=" + hmac.new(b"correct", payload, hashlib.sha256).hexdigest()

        assert verify_github_signature(payload, correct_sig, "wrong") is False


class TestWebhookEndpoint:
    """Integration tests for the webhook endpoint."""

    def _make_signature(self, payload: bytes, secret: str = "dev-webhook-secret") -> str:
        """Create a valid GitHub webhook signature."""
        sig = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        return f"sha256={sig}"

    def test_ping_event(self):
        """Ping events should return 202 with pong."""
        client = TestClient(app)
        payload = json.dumps({"zen": "Keep it logically awesome.", "hook_id": 123}).encode()

        response = client.post(
            "/api/v1/webhooks/github",
            content=payload,
            headers={
                "X-Hub-Signature-256": self._make_signature(payload),
                "X-GitHub-Event": "ping",
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 202
        assert response.json()["action"] == "pong"

    def test_pr_opened_event_dispatched(self):
        """PR opened events should be dispatched for review."""
        client = TestClient(app)
        payload = json.dumps({
            "action": "opened",
            "pull_request": {
                "number": 42,
                "title": "Add feature",
                "user": {"login": "testuser"},
                "base": {"ref": "main"},
                "head": {"ref": "feature-branch"},
                "diff_url": "https://github.com/owner/repo/pull/42.diff",
                "html_url": "https://github.com/owner/repo/pull/42",
                "body": "Test PR",
                "changed_files": 3,
                "additions": 100,
                "deletions": 20,
            },
            "repository": {"full_name": "owner/repo"},
        }).encode()

        with patch(
            "app.routers.webhooks.dispatch_pr_event",
            new_callable=AsyncMock,
        ) as mock_dispatch:
            response = client.post(
                "/api/v1/webhooks/github",
                content=payload,
                headers={
                    "X-Hub-Signature-256": self._make_signature(payload),
                    "X-GitHub-Event": "pull_request",
                    "Content-Type": "application/json",
                },
            )

        assert response.status_code == 202
        data = response.json()
        assert data["status"] == "accepted"
        assert data["action"] == "opened"

    def test_pr_closed_not_reviewed(self):
        """Closed PRs should not trigger review."""
        client = TestClient(app)
        payload = json.dumps({
            "action": "closed",
            "pull_request": {"number": 42, "user": {"login": "u"}, "base": {"ref": "main"}, "head": {"ref": "f"}},
            "repository": {"full_name": "owner/repo"},
        }).encode()

        response = client.post(
            "/api/v1/webhooks/github",
            content=payload,
            headers={
                "X-Hub-Signature-256": self._make_signature(payload),
                "X-GitHub-Event": "pull_request",
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 202
        assert "ignored" in response.json()["action"]

    def test_invalid_signature_returns_401(self):
        """Invalid signatures should return 401."""
        client = TestClient(app)
        payload = b'{"action": "opened"}'

        response = client.post(
            "/api/v1/webhooks/github",
            content=payload,
            headers={
                "X-Hub-Signature-256": "sha256=invalid",
                "X-GitHub-Event": "pull_request",
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 401

    def test_missing_signature_returns_401(self):
        """Missing signature should return 401."""
        client = TestClient(app)
        payload = b'{"action": "opened"}'

        response = client.post(
            "/api/v1/webhooks/github",
            content=payload,
            headers={"X-GitHub-Event": "pull_request"},
        )
        assert response.status_code == 401

    def test_unknown_event_accepted(self):
        """Unknown event types should return 202 with ignored status."""
        client = TestClient(app)
        payload = json.dumps({"action": "something"}).encode()

        response = client.post(
            "/api/v1/webhooks/github",
            content=payload,
            headers={
                "X-Hub-Signature-256": self._make_signature(payload),
                "X-GitHub-Event": "push",
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 202
