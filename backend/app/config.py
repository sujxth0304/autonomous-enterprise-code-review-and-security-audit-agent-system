"""Application configuration using Pydantic Settings."""

from functools import lru_cache
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ─── Application ─────────────────────────────────────────────────────────
    APP_ENV: str = "development"
    LOG_LEVEL: str = "INFO"
    API_V1_PREFIX: str = "/api/v1"
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:5173"

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",")]

    # ─── Database ─────────────────────────────────────────────────────────────
    DATABASE_URL: str = "postgresql+asyncpg://codereview:codereview_dev@localhost:5432/codereview"
    DATABASE_SYNC_URL: str = "postgresql+psycopg2://codereview:codereview_dev@localhost:5432/codereview"

    # ─── Redis ────────────────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"

    # ─── Kafka ────────────────────────────────────────────────────────────────
    KAFKA_BOOTSTRAP_SERVERS: str = "localhost:9092"
    KAFKA_PR_EVENTS_TOPIC: str = "pr-events"
    KAFKA_CONSUMER_GROUP_ID: str = "code-review-consumers"

    # ─── Weaviate ─────────────────────────────────────────────────────────────
    WEAVIATE_URL: str = "http://localhost:8080"
    WEAVIATE_API_KEY: Optional[str] = None

    # ─── AI / LLM ─────────────────────────────────────────────────────────────
    ANTHROPIC_API_KEY: str = Field(default="", description="Anthropic API key")
    OPENAI_API_KEY: str = Field(default="", description="OpenAI API key")

    # ─── GitHub Integration ───────────────────────────────────────────────────
    GITHUB_WEBHOOK_SECRET: str = "dev-webhook-secret"
    GITHUB_APP_ID: str = ""
    GITHUB_APP_PRIVATE_KEY: str = ""
    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""

    # ─── JWT Auth ─────────────────────────────────────────────────────────────
    JWT_SECRET_KEY: str = "dev-secret-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # ─── LangSmith ────────────────────────────────────────────────────────────
    LANGSMITH_API_KEY: Optional[str] = None
    LANGSMITH_PROJECT: str = "code-review-prod"
    LANGCHAIN_TRACING_V2: bool = False

    # ─── Agent Configuration ──────────────────────────────────────────────────
    MAX_AGENT_STEPS: int = 10
    RISK_SCORE_THRESHOLD: float = 0.7
    LOW_RISK_THRESHOLD: float = 0.3
    MAX_CONCURRENT_REVIEWS: int = 4

    # ─── OpenTelemetry ────────────────────────────────────────────────────────
    OTEL_EXPORTER_OTLP_ENDPOINT: str = "http://localhost:4317"
    OTEL_SERVICE_NAME: str = "code-review-backend"
    OTEL_ENVIRONMENT: str = "development"

    # ─── Semgrep ──────────────────────────────────────────────────────────────
    SEMGREP_APP_TOKEN: Optional[str] = None
    SEMGREP_RULES_PATH: str = "auto"

    # ─── OSV.dev ──────────────────────────────────────────────────────────────
    OSV_API_URL: str = "https://api.osv.dev/v1"


@lru_cache()
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()


settings = get_settings()
