"""Unit tests for the API key router."""

from datetime import datetime, timedelta
from http import HTTPStatus
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import FastAPI, HTTPException, status
from httpx import ASGITransport, AsyncClient
from jose import JWTError
from keylin.db import get_async_session as keylin_get_async_session
from keylin.models import APIKey
from sqlalchemy.ext.asyncio import AsyncSession

from apikey import api_key_router
from apikey.dependencies import get_current_user

# Constants for test assertions
EXPECTED_EXECUTE_CALLS = 2
UNAUTHORIZED_STATUS = HTTPStatus.UNAUTHORIZED


@pytest.fixture(autouse=True)
def ensure_in_memory_db(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure DATABASE_URL is set to in-memory SQLite for these unit tests."""
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def app() -> FastAPI:
    """Create a test FastAPI application."""
    app = FastAPI()
    app.include_router(api_key_router)
    return app


@pytest.fixture
def fake_user() -> Any:
    """Create a fake user for testing."""

    class User:
        id = "user-123"
        email = "test@example.com"

    return User()


@pytest.fixture
def fake_api_key_instance() -> APIKey:
    """Create a fake API key instance for testing."""
    return APIKey(
        user_id="user-123",
        key_hash="fake_hashed_key",
        service_id="svc",
        name="test key",
        status="active",
        created_at=datetime.now(),
        expires_at=datetime.now() + timedelta(days=1),
        last_used_at=None,
        id="key-1",
    )


@pytest.mark.asyncio
@patch("keylin.apikey_manager.create_api_key_record")
async def test_create_api_key(
    mock_create_api_key_record: AsyncMock,
    app: FastAPI,
    fake_user: Any,
    fake_api_key_instance: APIKey,
) -> None:
    """Test creating an API key."""
    app.dependency_overrides[get_current_user] = lambda: fake_user

    mock_db_session = AsyncMock(spec=AsyncSession)
    mock_db_session.add = Mock()
    mock_db_session.commit = AsyncMock()
    mock_db_session.refresh = AsyncMock()
    app.dependency_overrides[keylin_get_async_session] = lambda: mock_db_session

    mock_create_api_key_record.return_value = (
        "plaintext_example_key",
        fake_api_key_instance,
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.post(
            "/api-keys/", json={"service_id": "svc", "name": "test key"}
        )

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["id"] == fake_api_key_instance.id
    assert data["plaintext_key"] == "plaintext_example_key"
    assert data["name"] == fake_api_key_instance.name
    mock_db_session.add.assert_called_once_with(fake_api_key_instance)
    mock_db_session.commit.assert_awaited_once()
    mock_db_session.refresh.assert_awaited_once_with(fake_api_key_instance)

    app.dependency_overrides = {}


@pytest.mark.asyncio
async def test_list_api_keys(
    app: FastAPI, fake_user: Any, fake_api_key_instance: APIKey
) -> None:
    """Test listing API keys."""
    app.dependency_overrides[get_current_user] = lambda: fake_user

    mock_db_session = AsyncMock(spec=AsyncSession)

    # Mock for the .scalars().all() chain
    mock_scalars_result = AsyncMock()
    # .all() is synchronous
    mock_scalars_result.all = Mock(return_value=[fake_api_key_instance])

    mock_execute_result = AsyncMock()
    # .scalars() is synchronous
    mock_execute_result.scalars = Mock(return_value=mock_scalars_result)

    mock_db_session.execute = AsyncMock(return_value=mock_execute_result)
    app.dependency_overrides[keylin_get_async_session] = lambda: mock_db_session

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.get("/api-keys/")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["id"] == fake_api_key_instance.id
    assert data[0]["name"] == fake_api_key_instance.name
    mock_db_session.execute.assert_awaited_once()

    app.dependency_overrides = {}


@pytest.mark.asyncio
async def test_delete_api_key_success(
    app: FastAPI, fake_user: Any, fake_api_key_instance: APIKey
) -> None:
    """Test deleting an API key successfully."""
    app.dependency_overrides[get_current_user] = lambda: fake_user

    mock_db_session = AsyncMock(spec=AsyncSession)

    # This mock represents the result of the first session.execute() call
    # (the SELECT query)
    # It needs a .first() method.
    mock_select_result = Mock()
    mock_select_result.first.return_value = fake_api_key_instance

    # This mock represents the result of the second session.execute() call
    # (the DELETE query)
    # Its specific return value/attributes might not be used by the handler.
    mock_delete_result = Mock()

    # mock_db_session.execute is an AsyncMock. When awaited, it will yield values
    # from side_effect.
    mock_db_session.execute = AsyncMock(
        side_effect=[
            mock_select_result,  # Result for the SELECT
            mock_delete_result,  # Result for the DELETE
        ]
    )
    mock_db_session.commit = AsyncMock()
    app.dependency_overrides[keylin_get_async_session] = lambda: mock_db_session

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.delete(f"/api-keys/{fake_api_key_instance.id}")

    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert mock_db_session.execute.call_count == EXPECTED_EXECUTE_CALLS
    mock_db_session.commit.assert_awaited_once()

    app.dependency_overrides = {}


@pytest.mark.asyncio
@patch("apikey.router.handler_delete_api_key")
async def test_delete_api_key_not_found(
    mock_handler_delete_api_key: AsyncMock, app: FastAPI, fake_user: Any
) -> None:
    """Test deleting a nonexistent API key."""
    app.dependency_overrides[get_current_user] = lambda: fake_user

    # Configure the patched handler to simulate "not found"
    mock_handler_delete_api_key.return_value = False

    # The DB session still needs to be mocked for the app's dependency resolution,
    # even if the handler that uses it is mocked.
    mock_db_session = AsyncMock(spec=AsyncSession)
    app.dependency_overrides[keylin_get_async_session] = lambda: mock_db_session

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.delete("/api-keys/non_existent_key_id")

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "API key not found"
    mock_handler_delete_api_key.assert_awaited_once_with(
        key_id="non_existent_key_id",
        user_id=fake_user.id,
        # Check it was called with a session
        session=mock_handler_delete_api_key.call_args[1]["session"],
    )

    app.dependency_overrides = {}


@pytest.mark.asyncio
@patch("apikey.dependencies.jwt.decode")
async def test_get_current_user_success(mock_jwt_decode: Mock, app: FastAPI) -> None:
    """Test successful user authentication."""
    # Mock a valid JWT payload
    mock_jwt_decode.return_value = {
        "sub": "user-123",
        "email": "test@example.com",
        "aud": "fastapi-users:auth",
    }

    # Create a test request
    request = Mock()
    token = "valid.jwt.token"

    # Call the dependency
    user = await get_current_user(request, token)

    # Verify the result
    assert user["sub"] == "user-123"
    assert user["email"] == "test@example.com"
    mock_jwt_decode.assert_called_once_with(
        token,
        "changeme",  # Default JWT_SECRET
        algorithms=["HS256"],  # Default ALGORITHM
        audience="fastapi-users:auth",
    )


@pytest.mark.asyncio
@patch("apikey.dependencies.jwt.decode")
async def test_get_current_user_missing_sub(
    mock_jwt_decode: Mock, app: FastAPI
) -> None:
    """Test authentication with missing sub claim."""
    # Mock a JWT payload without 'sub'
    mock_jwt_decode.return_value = {
        "email": "test@example.com",
        "aud": "fastapi-users:auth",
    }

    # Create a test request
    request = Mock()
    token = "invalid.jwt.token"

    # Verify the dependency raises the correct exception
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(request, token)

    assert exc_info.value.status_code == UNAUTHORIZED_STATUS
    assert exc_info.value.detail == "Invalid token"


@pytest.mark.asyncio
@patch("apikey.dependencies.jwt.decode")
async def test_get_current_user_jwt_error(mock_jwt_decode: Mock, app: FastAPI) -> None:
    """Test authentication with JWT decode error."""
    # Mock JWT decode error
    mock_jwt_decode.side_effect = JWTError("Invalid token")

    # Create a test request
    request = Mock()
    token = "invalid.jwt.token"

    # Verify the dependency raises the correct exception
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(request, token)

    assert exc_info.value.status_code == UNAUTHORIZED_STATUS
    assert exc_info.value.detail == "Invalid token"
