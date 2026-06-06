"""Celery application configuration."""

from celery import Celery
from celery.schedules import crontab

from app.config import settings

celery_app = Celery(
    "code_review",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.workers.tasks", "app.workers.embedding_tasks"],
)

celery_app.conf.update(
    # Serialization
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    # Task routing
    task_routes={
        "app.workers.tasks.process_pr_review": {"queue": "pr_review"},
        "app.workers.embedding_tasks.reembed_all_prs": {"queue": "embeddings"},
        "app.workers.embedding_tasks.embed_pr_diff": {"queue": "embeddings"},
    },
    # Worker settings
    worker_prefetch_multiplier=1,  # Important for long-running tasks
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    # Result expiry
    result_expires=86400,  # 24 hours
    # Rate limiting
    task_annotations={
        "app.workers.tasks.process_pr_review": {
            "rate_limit": f"{settings.MAX_CONCURRENT_REVIEWS}/m",
        }
    },
    # Retry settings
    task_max_retries=3,
    task_default_retry_delay=60,
    # Beat schedule for periodic tasks
    beat_schedule={
        "nightly-reembedding": {
            "task": "app.workers.embedding_tasks.reembed_all_prs",
            "schedule": crontab(hour=2, minute=0),  # 2 AM UTC daily
        },
        "cleanup-old-results": {
            "task": "app.workers.tasks.cleanup_old_task_results",
            "schedule": crontab(hour=3, minute=0),  # 3 AM UTC daily
        },
    },
)
