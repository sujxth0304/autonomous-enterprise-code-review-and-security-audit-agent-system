"""SQLAlchemy async engine, session factory, and Base."""

from typing import AsyncGenerator

import structlog
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import settings

logger = structlog.get_logger(__name__)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""
    pass


engine = create_async_engine(
    settings.DATABASE_URL,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    pool_recycle=3600,
    echo=settings.APP_ENV == "development",
)

async_session_factory = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency that provides an async DB session."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Create all tables on startup (for dev). Use alembic in production."""
    from app.models import agent_run, finding, pr, user  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("database.initialized")


async def close_db() -> None:
    """Close the database engine."""
    await engine.dispose()
    logger.info("database.closed")
