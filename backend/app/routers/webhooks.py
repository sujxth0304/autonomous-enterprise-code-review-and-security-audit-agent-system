"""GitHub webhook ingestion router."""

import hashlib
import hmac
import json
from typing import Any, Dict

import structlog
from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Request, status

from app.config import settings
from app.kafka.producer import get_kafka_producer

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/webhooks", tags=["webhooks"])


def verify_github_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify HMAC-SHA256 signature from GitHub webhook."""
    if not signature or not signature.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)


async def dispatch_pr_event(event_type: str, payload: Dict[str, Any]) -> None:
    """Push PR event to Kafka for async processing."""
    pr_data = payload.get("pull_request", {})
    repo = payload.get("repository", {})

    event = {
        "event_type": event_type,
        "action": payload.get("action"),
        "pr_number": pr_data.get("number"),
        "pr_title": pr_data.get("title"),
        "pr_author": pr_data.get("user", {}).get("login"),
        "base_branch": pr_data.get("base", {}).get("ref"),
        "head_branch": pr_data.get("head", {}).get("ref"),
        "diff_url": pr_data.get("diff_url"),
        "html_url": pr_data.get("html_url"),
        "body": pr_data.get("body"),
        "repo_full_name": repo.get("full_name"),
        "files_changed": pr_data.get("changed_files", 0),
        "additions": pr_data.get("additions", 0),
        "deletions": pr_data.get("deletions", 0),
    }

    try:
        producer = await get_kafka_producer()
        await producer.publish_pr_event(event)
        logger.info(
            "webhook.event_dispatched",
            event_type=event_type,
            repo=repo.get("full_name"),
            pr_number=pr_data.get("number"),
        )
    except Exception as exc:
        logger.error("webhook.dispatch_failed", error=str(exc))
        raise


@router.post("/github", status_code=status.HTTP_202_ACCEPTED)
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: str = Header(None),
    x_github_event: str = Header(None),
) -> Dict[str, str]:
    """
    Receive GitHub webhook events.

    Verifies HMAC signature and dispatches PR events to Kafka.
    Supported events: pull_request (opened, synchronize, reopened, closed)
    """
    payload_bytes = await request.body()

    # Verify signature
    if not verify_github_signature(
        payload_bytes, x_hub_signature_256 or "", settings.GITHUB_WEBHOOK_SECRET
    ):
        logger.warning(
            "webhook.invalid_signature",
            event=x_github_event,
            signature=x_hub_signature_256,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature",
        )

    try:
        payload = json.loads(payload_bytes)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    logger.info("webhook.received", event=x_github_event, action=payload.get("action"))

    # Handle pull_request events
    if x_github_event == "pull_request":
        action = payload.get("action")
        if action in ("opened", "synchronize", "reopened"):
            background_tasks.add_task(dispatch_pr_event, x_github_event, payload)
            return {"status": "accepted", "action": action}
        elif action == "closed":
            logger.info("webhook.pr_closed", pr=payload.get("pull_request", {}).get("number"))
            return {"status": "ok", "action": "ignored_closed"}

    # Handle ping event (webhook setup)
    if x_github_event == "ping":
        return {"status": "ok", "action": "pong"}

    return {"status": "ok", "action": "ignored"}
