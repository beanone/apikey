"""Database initialization and configuration module."""

import logging
import os
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import QueuePool

from .models import Base, DBState

logger = logging.getLogger(__name__)

# Database configuration
DB_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./apikey.db")
POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "5"))
MAX_OVERFLOW = int(os.getenv("DB_MAX_OVERFLOW", "10"))
POOL_TIMEOUT = int(os.getenv("DB_POOL_TIMEOUT", "30"))
POOL_RECYCLE = int(os.getenv("DB_POOL_RECYCLE", "1800"))  # 30 minutes


def _is_async_sqlite(url: str) -> bool:
    return url.startswith("sqlite+aiosqlite")


async def init_db() -> None:
    """Initialize the database connection and create tables if they don't exist.

    This function:
    1. Creates an async engine (with pooling for non-async-sqlite)
    2. Creates a session factory
    3. Creates all tables if they don't exist
    4. Stores the engine and session factory in DBState

    Raises:
        RuntimeError: If database initialization fails
    """
    try:
        if _is_async_sqlite(DB_URL):
            engine = create_async_engine(
                DB_URL,
                echo=os.getenv("SQL_ECHO", "").lower() == "true",
            )
        else:
            engine = create_async_engine(
                DB_URL,
                poolclass=QueuePool,
                pool_size=POOL_SIZE,
                max_overflow=MAX_OVERFLOW,
                pool_timeout=POOL_TIMEOUT,
                pool_recycle=POOL_RECYCLE,
                echo=os.getenv("SQL_ECHO", "").lower() == "true",
            )

        async_session_maker = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        DBState.engine = engine
        DBState.async_session_maker = async_session_maker

        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise RuntimeError(f"Database initialization failed: {e}") from e


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """Get a database session.

    Returns:
        AsyncGenerator[AsyncSession, None]: An async generator yielding database sessions

    Raises:
        RuntimeError: If database is not initialized
    """
    if DBState.async_session_maker is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")

    async with DBState.async_session_maker() as session:
        try:
            yield session
        except Exception as e:
            await session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            await session.close()


async def close_db() -> None:
    """Close the database connection.

    This function:
    1. Closes the database engine
    2. Clears the DBState
    """
    if DBState.engine is not None:
        await DBState.engine.dispose()
        DBState.engine = None
        DBState.async_session_maker = None
        logger.info("Database connection closed")
