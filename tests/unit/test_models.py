"""Unit tests for the API key models."""

import os
from datetime import datetime, timezone

import pytest

from apikey.db import close_db, init_db
from apikey.models import APIKey, APIKeyStatus, User


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


def test_api_key_string_representation():
    """Test the string representation methods of APIKey."""
    api_key = APIKey(
        id="test-key-1",
        user_id="test-user-1",
        key_hash="hashed_key",
        name="Test Key",
        created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        service_id="test-service",
        status=APIKeyStatus.ACTIVE,
        expires_at=datetime(2024, 2, 1, tzinfo=timezone.utc),
        last_used_at=None,
    )
    s = str(api_key)
    assert s.startswith(
        "APIKey(id='test-key...",
    )
    assert "status='active'" in s
    r = repr(api_key)
    assert r.startswith(
        "APIKey(id='test-key...",
    )
    assert "status='active'" in r
    assert "created_at=" in r
    assert "expires_at=" in r


def test_api_key_str():
    """Test the string representation of an API key."""
    api_key = APIKey(
        id="test-key-1",
        user_id="test-user-1",
        key_hash="hashed_key",
        name="Test Key",
        created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        service_id="test-service",
        status=APIKeyStatus.ACTIVE,
        expires_at=datetime(2024, 2, 1, tzinfo=timezone.utc),
        last_used_at=None,
    )
    s = str(api_key)
    assert s.startswith(
        "APIKey(id='test-key...",
    )
    assert "status='active'" in s


def test_api_key_repr():
    """Test the repr representation of an API key."""
    api_key = APIKey(
        id="test-key-1",
        user_id="test-user-1",
        key_hash="hashed_key",
        name="Test Key",
        created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        service_id="test-service",
        status=APIKeyStatus.ACTIVE,
        expires_at=datetime(2024, 2, 1, tzinfo=timezone.utc),
        last_used_at=None,
    )
    r = repr(api_key)
    assert r.startswith(
        "APIKey(id='test-key...",
    )
    assert "status='active'" in r
    assert "created_at=" in r
    assert "expires_at=" in r


def test_api_key_str_with_last_used():
    """Test the string representation of an API key with last_used_at set."""
    api_key = APIKey(
        id="test-key-1",
        user_id="test-user-1",
        key_hash="hashed_key",
        name="Test Key",
        created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        service_id="test-service",
        status=APIKeyStatus.ACTIVE,
        expires_at=datetime(2024, 2, 1, tzinfo=timezone.utc),
        last_used_at=datetime(2024, 1, 15, tzinfo=timezone.utc),
    )
    s = str(api_key)
    assert s.startswith(
        "APIKey(id='test-key...",
    )
    assert "status='active'" in s


def test_api_key_repr_with_last_used():
    """Test the repr representation of an API key with last_used_at set."""
    api_key = APIKey(
        id="test-key-1",
        user_id="test-user-1",
        key_hash="hashed_key",
        name="Test Key",
        created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        service_id="test-service",
        status=APIKeyStatus.ACTIVE,
        expires_at=datetime(2024, 2, 1, tzinfo=timezone.utc),
        last_used_at=datetime(2024, 1, 15, tzinfo=timezone.utc),
    )
    r = repr(api_key)
    assert r.startswith(
        "APIKey(id='test-key...",
    )
    assert "status='active'" in r
    assert "created_at=" in r
    assert "expires_at=" in r


def test_user_equality():
    """Test the __eq__ method of User."""
    user1 = User(id="u1", sub="sub1", email="a@b.com", aud="aud1")
    user2 = User(id="u1", sub="sub1", email="a@b.com", aud="aud1")
    user3 = User(id="u2", sub="sub2", email="b@c.com", aud="aud2")
    assert user1 == user2
    assert not (user1 == user3)
    assert user1 != user3
    assert user1 != object()  # Not a User instance


def test_user_repr():
    """Test the __repr__ method of User."""
    user = User(id="u1", sub="sub1", email="a@b.com", aud="aud1")
    r = repr(user)
    assert r == "User(id='u1', sub='sub1', email='a@b.com', aud='aud1')"
