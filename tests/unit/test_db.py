"""Tests for database initialization and configuration."""

import os

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

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
        with pytest.raises(Exception):
            await session.execute(text("SELECT * FROM nonexistent_table"))
