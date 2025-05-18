"""Tests for database initialization and configuration."""

import os
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from apikey import db
from apikey.db import DBState, close_db, get_async_session, init_db


@pytest.fixture(autouse=True)
async def setup_teardown():
    """Setup and teardown for each test."""
    # Setup: Initialize DB with test configuration
    os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
    os.environ["SQL_ECHO"] = "false"
    await init_db()
    yield
    # Teardown: Close DB connection
    await close_db()


@pytest.fixture(autouse=True)
def reset_db_state():
    """Reset DBState before and after each test."""
    DBState.engine = None
    DBState.async_session_maker = None
    yield
    DBState.engine = None
    DBState.async_session_maker = None


@pytest.mark.asyncio
async def test_init_db():
    """Test database initialization."""
    # Verify DBState is properly initialized
    assert DBState.engine is not None
    assert DBState.async_session_maker is not None

    # Test that we can execute a query
    async with DBState.async_session_maker() as session:
        result = await session.execute(text("SELECT 1"))
        assert result.scalar() == 1


@pytest.mark.asyncio
async def test_get_async_session():
    """Test getting an async session."""
    async for session in get_async_session():
        assert isinstance(session, AsyncSession)
        # Test that session is working
        result = await session.execute(text("SELECT 1"))
        assert result.scalar() == 1


@pytest.mark.asyncio
async def test_close_db():
    """Test closing the database connection."""
    await close_db()
    assert DBState.engine is None
    assert DBState.async_session_maker is None


@pytest.mark.asyncio
async def test_table_creation():
    """Test that tables are created during initialization."""
    async with DBState.async_session_maker() as session:
        # Check if api_keys table exists
        result = await session.execute(
            text(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='api_keys'"
            )
        )
        assert result.scalar() == "api_keys"


@pytest.mark.asyncio
async def test_connection_pooling():
    """Test that connection pooling is working."""
    # Create multiple sessions to test pool
    async with DBState.async_session_maker() as session1:
        async with DBState.async_session_maker() as session2:
            # Both sessions should work independently
            result1 = await session1.execute(text("SELECT 1"))
            result2 = await session2.execute(text("SELECT 1"))
            assert result1.scalar() == 1
            assert result2.scalar() == 1


@pytest.mark.asyncio
async def test_error_handling():
    """Test error handling in session management."""
    async with DBState.async_session_maker() as session:
        # Test invalid query
        with pytest.raises(OperationalError):
            await session.execute(text("SELECT * FROM nonexistent_table"))


@pytest.mark.asyncio
async def test_init_db_error_handling():
    """Test error handling during database initialization."""
    # First close any existing connection
    await close_db()

    with patch("apikey.db.create_async_engine") as mock_create_engine:
        mock_create_engine.side_effect = SQLAlchemyError("Test error")

        with pytest.raises(RuntimeError) as exc_info:
            await init_db()

        assert "Database initialization failed" in str(exc_info.value)
        assert DBState.engine is None
        assert DBState.async_session_maker is None


@pytest.mark.asyncio
async def test_get_async_session_not_initialized():
    """Test getting a session when database is not initialized."""
    # First close any existing connection
    await close_db()

    with pytest.raises(RuntimeError) as exc_info:
        async for _ in get_async_session():
            pass

    assert "Database not initialized" in str(exc_info.value)


@pytest.mark.asyncio
async def test_get_async_session_error_handling():
    """Test error handling during session usage."""
    mock_session = AsyncMock(spec=AsyncSession)
    mock_session.rollback = AsyncMock()
    mock_session.close = AsyncMock()

    @asynccontextmanager
    async def mock_session_maker():
        yield mock_session

    # Store original session maker
    original_session_maker = DBState.async_session_maker
    DBState.async_session_maker = mock_session_maker

    try:

        class CustomError(Exception):
            pass

        agen = get_async_session()
        await agen.__anext__()
        with pytest.raises(CustomError):
            await agen.athrow(CustomError("Simulated error inside session context"))

        mock_session.rollback.assert_awaited_once()
        mock_session.close.assert_awaited_once()
    finally:
        DBState.async_session_maker = original_session_maker


@pytest.mark.asyncio
async def test_close_db_error_handling():
    """Test error handling during database closure."""
    # Mock the engine
    mock_engine = AsyncMock(spec=AsyncEngine)
    mock_engine.dispose.side_effect = SQLAlchemyError("Test error")

    # Store original engine
    original_engine = DBState.engine
    DBState.engine = mock_engine
    DBState.async_session_maker = MagicMock()

    try:
        # Should not raise an error
        await close_db()

        # State should be cleared even if dispose fails
        assert DBState.engine is None
        assert DBState.async_session_maker is None
    finally:
        # Restore original engine
        DBState.engine = original_engine


@pytest.mark.asyncio
async def test_close_db_no_engine():
    """Test closing database when no engine exists."""
    # Should not raise an error
    await close_db()

    # State should remain None
    assert DBState.engine is None
    assert DBState.async_session_maker is None


@pytest.mark.asyncio
async def test_init_db_async_sqlite_branch(monkeypatch):
    """Ensure the async sqlite branch in init_db is covered."""
    monkeypatch.setattr(db, "DB_URL", "sqlite:///:memory:")
    monkeypatch.setattr(db, "_is_async_sqlite", lambda x: True)
    # Patch create_async_engine to avoid real engine creation
    with patch("apikey.db.create_async_engine", return_value=MagicMock()):
        # Patch async_sessionmaker to avoid real session creation
        with patch("apikey.db.async_sessionmaker", return_value=MagicMock()):
            DBState.engine = None
            DBState.async_session_maker = None
            await init_db()
            assert DBState.engine is not None
            assert DBState.async_session_maker is not None
            await close_db()
