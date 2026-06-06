"""Kafka consumer that reads PR events and dispatches Celery tasks."""

import asyncio
import json
import signal
import sys
from typing import Any, Dict

import structlog

from app.config import settings

logger = structlog.get_logger(__name__)


class PREventConsumer:
    """Kafka consumer that processes PR review events."""

    def __init__(self):
        self._consumer = None
        self._running = False

    def _create_consumer(self):
        """Create and configure the Kafka consumer."""
        from kafka import KafkaConsumer

        return KafkaConsumer(
            settings.KAFKA_PR_EVENTS_TOPIC,
            bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS.split(","),
            group_id=settings.KAFKA_CONSUMER_GROUP_ID,
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            key_deserializer=lambda k: k.decode("utf-8") if k else None,
            auto_offset_reset="earliest",
            enable_auto_commit=False,  # Manual commit for at-least-once processing
            session_timeout_ms=30000,
            heartbeat_interval_ms=10000,
            max_poll_interval_ms=300000,  # 5 min max processing time
            max_poll_records=10,  # Process 10 events per poll
        )

    async def handle_event(self, event: Dict[str, Any]) -> None:
        """Process a single PR event and dispatch Celery task."""
        from app.services.pr_service import PRService

        event_type = event.get("event_type")
        action = event.get("action")
        repo = event.get("repo_full_name")
        pr_number = event.get("pr_number")

        log = logger.bind(event_type=event_type, action=action, repo=repo, pr=pr_number)
        log.info("consumer.event_received")

        if event_type != "pull_request" or action not in ("opened", "synchronize", "reopened"):
            log.debug("consumer.event_skipped")
            return

        if not repo or not pr_number:
            log.warning("consumer.invalid_event", reason="missing repo or pr_number")
            return

        try:
            # Upsert PR in database
            async with __import__("app.database", fromlist=["async_session_factory"]).async_session_factory() as session:
                service = PRService(session)
                pr = await service.upsert_pr_from_event(event)

            if pr:
                # Dispatch Celery task for review
                from app.workers.tasks import process_pr_review
                task = process_pr_review.delay(str(pr.id))
                log.info(
                    "consumer.task_dispatched",
                    pr_id=str(pr.id),
                    task_id=task.id,
                )
            else:
                log.warning("consumer.pr_upsert_failed")

        except Exception as exc:
            log.error("consumer.handle_event_failed", error=str(exc))
            raise

    def run(self) -> None:
        """Start the consumer loop. Blocks until stopped."""
        logger.info("consumer.starting", topic=settings.KAFKA_PR_EVENTS_TOPIC)

        try:
            self._consumer = self._create_consumer()
        except Exception as exc:
            logger.error("consumer.connect_failed", error=str(exc))
            sys.exit(1)

        self._running = True
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        def shutdown_handler(signum, frame):
            logger.info("consumer.shutdown_signal", signal=signum)
            self._running = False

        signal.signal(signal.SIGTERM, shutdown_handler)
        signal.signal(signal.SIGINT, shutdown_handler)

        try:
            while self._running:
                try:
                    message_pack = self._consumer.poll(timeout_ms=1000, max_records=10)

                    if not message_pack:
                        continue

                    for topic_partition, messages in message_pack.items():
                        for message in messages:
                            try:
                                loop.run_until_complete(self.handle_event(message.value))
                                # Commit offset only after successful processing
                                self._consumer.commit()
                            except Exception as exc:
                                logger.error(
                                    "consumer.message_failed",
                                    error=str(exc),
                                    offset=message.offset,
                                    partition=message.partition,
                                )
                                # Don't commit - will be reprocessed
                                # In production, implement DLQ (dead letter queue)

                except Exception as exc:
                    if self._running:
                        logger.error("consumer.poll_error", error=str(exc))
                        import time
                        time.sleep(5)  # Back off on error

        finally:
            if self._consumer:
                self._consumer.close()
            loop.close()
            logger.info("consumer.stopped")


def main():
    """Entry point for the Kafka consumer process."""
    import os

    # Configure structlog
    import structlog
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ]
    )

    consumer = PREventConsumer()
    consumer.run()


if __name__ == "__main__":
    main()
