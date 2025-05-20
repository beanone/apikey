"""Integration tests for the API key service."""

import logging
import os
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.security import OAuth2PasswordBearer
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient
from jose import jwt
from sqlalchemy import text

from apikey.db import DBState, close_db, init_db
from apikey.service import create_app
from apikey.utils import hash_api_key

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class TestOAuth2PasswordBearer(OAuth2PasswordBearer):
    """Test-specific OAuth2 scheme that doesn't require a login service."""

    async def __call__(self, request):
        """Get the token from the Authorization header."""
        return request.headers.get("Authorization", "").replace("Bearer ", "")


@pytest.fixture(autouse=True)
async def setup_teardown():
    """Setup and teardown for each test."""
    # Setup: Use a real SQLite database for testing
    os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test.db"
    os.environ["SQL_ECHO"] = "false"
    os.environ["JWT_SECRET"] = "supersecretjwtkey"
    os.environ["JWT_ALGORITHM"] = "HS256"
    # For local testing only
    # os.environ["LOGIN_URL"] = "http://localhost:8001"

    # Initialize the real database
    await init_db()

    # Create tables
    async with DBState.async_session_maker() as session:
        # Create users table
        await session.execute(
            text(
                """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT,
                hashed_password TEXT,
                is_active BOOLEAN
            )
        """
            )
        )

        # Create API keys table
        await session.execute(
            text(
                """
            CREATE TABLE IF NOT EXISTS api_keys (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                key_hash TEXT NOT NULL UNIQUE,
                name TEXT,
                created_at TIMESTAMP NOT NULL,
                service_id TEXT NOT NULL,
                status TEXT NOT NULL,
                expires_at TIMESTAMP,
                last_used_at TIMESTAMP
            )
        """
            )
        )
        await session.commit()

        # Create test user
        user_id = "test-user-1"
        result = await session.execute(
            text("SELECT id FROM users WHERE id = :user_id"), {"user_id": user_id}
        )
        if not result.first():
            await session.execute(
                text(
                    """
                INSERT INTO users (id, email, hashed_password, is_active)
                VALUES (:user_id, :email, :password, :is_active)
            """
                ),
                {
                    "user_id": user_id,
                    "email": "test@example.com",
                    "password": "hashedpass",
                    "is_active": True,
                },
            )
            await session.commit()

    yield

    # Teardown: Clean up database
    async with DBState.async_session_maker() as session:
        await session.execute(text("DELETE FROM api_keys"))
        await session.execute(text("DELETE FROM users"))
        await session.commit()

    # Close DB connection and remove test database
    await close_db()
    if os.path.exists("./test.db"):
        os.remove("./test.db")


@pytest.fixture
def app():
    """Create a test application instance."""
    app = create_app()

    # Override the OAuth2 scheme for testing
    app.dependency_overrides[OAuth2PasswordBearer] = TestOAuth2PasswordBearer

    # Override the settings to not require a login service
    from apikey.dependencies import get_settings

    original_settings = get_settings()
    original_settings.login_url = (
        "http://test"  # Use a dummy URL since we're mocking the auth
    )
    app.dependency_overrides[get_settings] = lambda: original_settings

    return app


@pytest.fixture
def client(app):
    """Create a test client."""
    return TestClient(app)


@pytest.fixture
async def async_client(app):
    """Create an async test client."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac


@pytest.fixture
def test_token():
    """Create a test JWT token."""
    secret = os.environ["JWT_SECRET"]
    algorithm = os.environ["JWT_ALGORITHM"]
    payload = {
        "sub": "test-user-1",
        "email": "test@example.com",
        "aud": "fastapi-users:auth",
    }

    logger.debug(f"Creating token with payload: {payload}")
    logger.debug(f"Using secret: {secret}")
    logger.debug(f"Using algorithm: {algorithm}")

    token = jwt.encode(payload, secret, algorithm=algorithm)
    logger.debug(f"Generated token: {token}")

    # Verify the token can be decoded with the same secret
    try:
        decoded = jwt.decode(
            token, secret, algorithms=[algorithm], audience="fastapi-users:auth"
        )
        logger.debug(f"Successfully decoded token: {decoded}")
    except Exception as e:
        logger.error(f"Failed to decode token: {e}")
        raise

    return token


@pytest.fixture
async def test_user():
    """Get the test user ID."""
    return "test-user-1"


@pytest.fixture
async def test_api_key(test_user):
    """Create a test API key in the database."""
    key_id = "test-key-1"
    async with DBState.async_session_maker() as session:
        # Check if key already exists
        result = await session.execute(
            text("SELECT id FROM api_keys WHERE id = :key_id"), {"key_id": key_id}
        )
        if not result.first():
            key_hash = hash_api_key("test-api-key")
            await session.execute(
                text(
                    """
                INSERT INTO api_keys (
                    id, user_id, key_hash, name, created_at,
                    service_id, status, expires_at
                ) VALUES (
                    :key_id, :user_id, :key_hash, :name,
                    :created_at, :service_id, :status, :expires_at
                )
            """
                ),
                {
                    "key_id": key_id,
                    "user_id": test_user,
                    "key_hash": key_hash,
                    "name": "Test Key",
                    "created_at": datetime.now(timezone.utc),
                    "service_id": "test-service",
                    "status": "ACTIVE",
                    "expires_at": datetime.now(timezone.utc) + timedelta(days=30),
                },
            )
            await session.commit()
    return "test-api-key"


@pytest.mark.asyncio
async def test_service_startup():
    """Test that the service starts up correctly with database initialization."""
    app = create_app()

    # Verify database is actually initialized
    assert DBState.engine is not None
    assert DBState.async_session_maker is not None

    # Test we can actually use the database
    async with DBState.async_session_maker() as session:
        # Create a test table
        await session.execute(
            text(
                """
            CREATE TABLE IF NOT EXISTS test_table (
                id INTEGER PRIMARY KEY,
                name TEXT
            )
        """
            )
        )
        await session.commit()

        # Insert test data
        await session.execute(
            text(
                """
            INSERT INTO test_table (name) VALUES ('test')
        """
            )
        )
        await session.commit()

        # Query test data
        result = await session.execute(text("SELECT name FROM test_table"))
        assert result.scalar() == "test"

    # Test the API endpoints
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        # Health check should work
        response = await ac.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}

        # OpenAPI docs should be available
        response = await ac.get("/docs")
        assert response.status_code == 200

        # API endpoints should be available
        response = await ac.get("/openapi.json")
        assert response.status_code == 200
        assert "API Key Management Service" in response.text


@pytest.mark.asyncio
async def test_list_api_keys(async_client, test_user, test_api_key, test_token):
    """Test listing API keys with a real database."""
    logger.debug(f"Testing list API keys with token: {test_token}")
    response = await async_client.get(
        "/api/v1/api-keys/", headers={"Authorization": f"Bearer {test_token}"}
    )
    logger.debug(f"Response status: {response.status_code}")
    logger.debug(f"Response body: {response.text}")
    assert response.status_code == 200
    keys = response.json()
    assert len(keys) == 1
    assert keys[0]["id"] == "test-key-1"
    assert keys[0]["name"] == "Test Key"


@pytest.mark.asyncio
async def test_create_api_key(async_client, test_user, test_token):
    """Test creating an API key with a real database."""
    logger.debug(f"Testing create API key with token: {test_token}")
    response = await async_client.post(
        "/api/v1/api-keys/",
        headers={"Authorization": f"Bearer {test_token}"},
        json={
            "name": "New Test Key",
            "service_id": "test-service",
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
        },
    )
    logger.debug(f"Response status: {response.status_code}")
    logger.debug(f"Response body: {response.text}")
    assert response.status_code == 201
    key_data = response.json()
    assert key_data["name"] == "New Test Key"
    assert "plaintext_key" in key_data

    # Verify the key was actually created in the database
    async with DBState.async_session_maker() as session:
        result = await session.execute(
            text(
                """
            SELECT name, service_id, status
            FROM api_keys
            WHERE id = :key_id
        """
            ),
            {"key_id": key_data["id"]},
        )
        row = result.first()
        assert row is not None
        assert row.name == "New Test Key"
        assert row.service_id == "test-service"
        assert row.status.lower() == "active"


@pytest.mark.asyncio
async def test_delete_api_key(async_client, test_user, test_api_key, test_token):
    """Test deleting an API key with a real database."""
    logger.debug(f"Testing delete API key with token: {test_token}")
    response = await async_client.delete(
        "/api/v1/api-keys/test-key-1", headers={"Authorization": f"Bearer {test_token}"}
    )
    logger.debug(f"Response status: {response.status_code}")
    logger.debug(f"Response body: {response.text}")
    assert response.status_code == 204

    # Verify the key was actually deleted
    async with DBState.async_session_maker() as session:
        result = await session.execute(
            text("SELECT id FROM api_keys WHERE id = :key_id"), {"key_id": "test-key-1"}
        )
        assert result.first() is None


@pytest.mark.asyncio
async def test_auth_jwt(async_client, test_user, test_api_key, test_token):
    """Test deleting an API key with a real database."""
    logger.debug(f"Testing delete API key with token: {test_token}")
    response = await async_client.get(
        "/api/v1/api-keys/test-auth", headers={"Authorization": f"Bearer {test_token}"}
    )
    logger.debug(f"Response status: {response.status_code}")
    logger.debug(f"Response body: {response.text}")
    assert response.status_code == 200
    assert response.json() == {"status": "success"}


@pytest.mark.asyncio
async def test_auth_api_key(async_client, test_user, test_api_key, test_token):
    """Test deleting an API key with a real database."""
    logger.debug(f"Testing delete API key with token: {test_token}")
    response = await async_client.get(
        "/api/v1/api-keys/test-auth", headers={"X-API-Key": f"{test_api_key}"}
    )
    logger.debug(f"Response status: {response.status_code}")
    logger.debug(f"Response body: {response.text}")
    assert response.status_code == 200
    assert response.json() == {"status": "success"}
