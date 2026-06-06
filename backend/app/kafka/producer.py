"""Kafka producer for publishing PR events."""

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import structlog

from app.config import settings

logger = structlog.get_logger(__name__)


class KafkaProducerWrapper:
    """Async-friendly wrapper around kafka-python KafkaProducer."""

    def __init__(self):
        self._producer = None

    def _get_producer(self):
        """Lazy initialization of Kafka producer."""
        if self._producer is None:
            try:
                from kafka import KafkaProducer

                self._producer = KafkaProducer(
                    bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS.split(","),
                    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                    key_serializer=lambda k: k.encode("utf-8") if k else None,
                    acks="all",
                    retries=3,
                    retry_backoff_ms=500,
                    max_request_size=10485760,  # 10MB for large diffs
                    request_timeout_ms=30000,
                    connections_max_idle_ms=300000,
                )
                logger.info(
                    "kafka.producer_connected",
                    servers=settings.KAFKA_BOOTSTRAP_SERVERS,
                )
            except Exception as exc:
                logger.error("kafka.producer_connect_failed", error=str(exc))
                raise

        return self._producer

    async def publish_pr_event(self, event: Dict[str, Any]) -> None:
        """Publish a PR event to the Kafka topic."""
        event["published_at"] = datetime.now(timezone.utc).isoformat()
        event["schema_version"] = "1.0"

        topic = settings.KAFKA_PR_EVENTS_TOPIC
        key = f"{event.get('repo_full_name', 'unknown')}:{event.get('pr_number', 0)}"

        try:
            producer = self._get_producer()
            future = producer.send(topic, key=key, value=event)
            # Block for at most 10 seconds to get delivery confirmation
            record_metadata = future.get(timeout=10)
            logger.info(
                "kafka.event_published",
                topic=record_metadata.topic,
                partition=record_metadata.partition,
                offset=record_metadata.offset,
                repo=event.get("repo_full_name"),
                pr=event.get("pr_number"),
            )
        except Exception as exc:
            logger.error(
                "kafka.publish_failed",
                error=str(exc),
                topic=topic,
                event_type=event.get("event_type"),
            )
            raise

    def flush(self) -> None:
        """Flush pending messages."""
        if self._producer:
            self._producer.flush(timeout=30)

    def close(self) -> None:
        """Close the Kafka producer."""
        if self._producer:
            try:
                self._producer.flush(timeout=10)
                self._producer.close(timeout=10)
            except Exception:
                pass
            self._producer = None
            logger.info("kafka.producer_closed")


# Singleton producer
_producer: Optional[KafkaProducerWrapper] = None


async def get_kafka_producer() -> KafkaProducerWrapper:
    """Get or create the singleton Kafka producer."""
    global _producer
    if _producer is None:
        _producer = KafkaProducerWrapper()
    return _producer


async def close_kafka_producer() -> None:
    """Close the Kafka producer on shutdown."""
    global _producer
    if _producer:
        _producer.close()
        _producer = None
