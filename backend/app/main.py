"""FastAPI application entry point."""

import time
from contextlib import asynccontextmanager
from typing import Any, Dict

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from starlette.responses import Response

from app.config import settings
from app.database import close_db, init_db
from app.routers import agents, auth, findings, metrics, prs, webhooks

logger = structlog.get_logger(__name__)

# ─── Prometheus metrics ───────────────────────────────────────────────────────

REQUEST_COUNT = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status_code"],
)
REQUEST_LATENCY = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency",
    ["method", "endpoint"],
)
PR_REVIEW_COUNT = Counter(
    "pr_reviews_total",
    "Total PR reviews triggered",
)
FINDING_COUNT = Counter(
    "findings_total",
    "Total findings created",
    ["severity", "category"],
)


# ─── Structlog configuration ──────────────────────────────────────────────────

def configure_logging():
    """Configure structlog for structured JSON logging."""
    import logging
    import sys

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer() if settings.APP_ENV == "production"
            else structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(sys.stdout),
        cache_logger_on_first_use=True,
    )


# ─── OpenTelemetry setup ──────────────────────────────────────────────────────

def setup_telemetry(app: FastAPI) -> None:
    """Initialize OpenTelemetry tracing."""
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.sdk.resources import SERVICE_NAME, Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        resource = Resource(attributes={SERVICE_NAME: settings.OTEL_SERVICE_NAME})
        provider = TracerProvider(resource=resource)

        exporter = OTLPSpanExporter(endpoint=settings.OTEL_EXPORTER_OTLP_ENDPOINT)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)

        FastAPIInstrumentor.instrument_app(app)
        logger.info("telemetry.initialized", endpoint=settings.OTEL_EXPORTER_OTLP_ENDPOINT)
    except Exception as exc:
        logger.warning("telemetry.setup_failed", error=str(exc))


# ─── Application lifecycle ────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle."""
    configure_logging()
    logger.info(
        "app.starting",
        env=settings.APP_ENV,
        version="0.1.0",
    )

    # Initialize database
    try:
        await init_db()
        logger.info("app.db_initialized")
    except Exception as exc:
        logger.error("app.db_init_failed", error=str(exc))

    # Initialize Redis connection check
    try:
        import redis.asyncio as aioredis
        r = aioredis.from_url(settings.REDIS_URL)
        await r.ping()
        await r.close()
        logger.info("app.redis_connected")
    except Exception as exc:
        logger.warning("app.redis_check_failed", error=str(exc))

    # Initialize Kafka producer (lazy)
    logger.info("app.kafka_producer_lazy_init")

    # Set LangSmith tracing env vars
    if settings.LANGSMITH_API_KEY:
        import os
        os.environ["LANGCHAIN_API_KEY"] = settings.LANGSMITH_API_KEY
        os.environ["LANGCHAIN_PROJECT"] = settings.LANGSMITH_PROJECT
        os.environ["LANGCHAIN_TRACING_V2"] = "true"

    logger.info("app.startup_complete")
    yield

    # Shutdown
    logger.info("app.shutting_down")
    try:
        from app.kafka.producer import close_kafka_producer
        await close_kafka_producer()
    except Exception:
        pass

    await close_db()
    logger.info("app.shutdown_complete")


# ─── App factory ─────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="Autonomous Code Review Agent API",
        description="Multi-agent system for automated GitHub PR code review and security auditing",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Request logging middleware
    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        start = time.monotonic()
        response = await call_next(request)
        duration = time.monotonic() - start

        REQUEST_COUNT.labels(
            method=request.method,
            endpoint=request.url.path,
            status_code=response.status_code,
        ).inc()
        REQUEST_LATENCY.labels(
            method=request.method,
            endpoint=request.url.path,
        ).observe(duration)

        logger.info(
            "http.request",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=round(duration * 1000, 2),
        )
        return response

    # Include routers
    prefix = settings.API_V1_PREFIX
    app.include_router(auth.router, prefix=prefix)
    app.include_router(webhooks.router, prefix=prefix)
    app.include_router(prs.router, prefix=prefix)
    app.include_router(findings.router, prefix=prefix)
    app.include_router(agents.router, prefix=prefix)
    app.include_router(metrics.router, prefix=prefix)

    # Health check
    @app.get("/health", tags=["health"])
    async def health_check() -> Dict[str, Any]:
        """Health check endpoint for load balancers and k8s probes."""
        checks: Dict[str, str] = {}

        # Database check
        try:
            from sqlalchemy import text
            from app.database import engine
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            checks["database"] = "healthy"
        except Exception as e:
            checks["database"] = f"unhealthy: {e}"

        # Redis check
        try:
            import redis.asyncio as aioredis
            r = aioredis.from_url(settings.REDIS_URL, socket_connect_timeout=2)
            await r.ping()
            await r.close()
            checks["redis"] = "healthy"
        except Exception as e:
            checks["redis"] = f"unhealthy: {e}"

        all_healthy = all("healthy" == v or "healthy" in v for v in checks.values()
                          if not v.startswith("unhealthy"))
        status = "healthy" if all_healthy else "degraded"

        return {
            "status": status,
            "version": "0.1.0",
            "environment": settings.APP_ENV,
            "checks": checks,
        }

    # Prometheus metrics endpoint
    @app.get("/metrics/prometheus", include_in_schema=False)
    async def prometheus_metrics():
        """Expose Prometheus metrics."""
        return Response(
            content=generate_latest(),
            media_type=CONTENT_TYPE_LATEST,
        )

    # Setup OTel
    setup_telemetry(app)

    return app


app = create_app()
