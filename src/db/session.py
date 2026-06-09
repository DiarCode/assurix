"""Async SQLAlchemy session factory with SQLite WAL mode."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from src.core.config import get_settings

_engine = None
_async_session_maker = None


def _get_engine():
    global _engine
    if _engine is None:
        settings = get_settings()
        # pool_size: number of permanent connections kept open. The engine's
        # _run_loop holds a long-lived session across an agent's LLM call
        # (potentially 30+ seconds for ollama.com), and the CLI's polling loop
        # opens a fresh session every 5s. Default pool size (5) is technically
        # enough but in practice aiosqlite + WAL can serialize connections
        # when they overlap, leading to deadlocks. Bump to 10 to be safe.
        _engine = create_async_engine(
            settings.database_url,
            echo=settings.log_level == "DEBUG",
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=10,
            pool_timeout=30,
        )
    return _engine


def _get_session_maker():
    global _async_session_maker
    if _async_session_maker is None:
        _async_session_maker = async_sessionmaker(
            bind=_get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )
    return _async_session_maker


async def init_db() -> None:
    """Create tables and enable WAL mode."""
    from src.db.models import Base

    engine = _get_engine()
    async with engine.begin() as conn:
        await conn.exec_driver_sql("PRAGMA journal_mode=WAL")
        await conn.run_sync(Base.metadata.create_all)


async def dispose_engine() -> None:
    """Dispose the engine and session maker (call before exit)."""
    global _engine, _async_session_maker
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _async_session_maker = None


@asynccontextmanager
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async DB session for FastAPI dependency injection."""
    async with _get_session_maker()() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()