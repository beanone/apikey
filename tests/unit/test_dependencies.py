"""Unit tests for authentication dependencies."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from jose import jwt
from starlette.requests import Request

from apikey.dependencies import (
    ALGORITHM,
    API_KEY_HEADER,
    API_KEY_QUERY,
    JWT_SECRET,
    Settings,
    get_current_user,
    get_settings,
    validate_api_key,
    validate_jwt,
)
from apikey.models import APIKeyStatus, User


def make_request(headers=None, query_string=b""):
    """Create a test request with optional headers and query string."""
    headers = headers or []
    return Request({"type": "http", "headers": headers, "query_string": query_string})


# Settings Tests
def test_get_settings():
    """Test settings initialization and environment variable handling."""
    settings = get_settings()
    assert isinstance(settings, Settings)
    assert settings.cors_origins == ["*"]
    assert settings.jwt_algorithm == "HS256"


# JWT Validation Tests
@pytest.mark.asyncio
async def test_validate_jwt_success():
    """Test successful JWT validation."""
    payload = {
        "sub": "test-user-id",
        "email": "test@example.com",
        "aud": "fastapi-users:auth",
        "exp": datetime.now(UTC).timestamp() + 3600,
    }
    # Create a properly formatted JWT token
    token = jwt.encode(payload, "supersecretjwtkey", algorithm="HS256")
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    with patch("apikey.dependencies.JWT_SECRET", "supersecretjwtkey"):
        user = await validate_jwt(credentials)
        assert isinstance(user, User)
        assert user.id == payload["sub"]
        assert user.email == payload["email"]
        assert user.aud == payload["aud"]


@pytest.mark.asyncio
async def test_validate_jwt_missing_sub():
    """Test JWT validation with missing sub claim."""
    payload = {"email": "test@example.com"}
    token = jwt.encode(payload, "supersecretjwtkey", algorithm="HS256")
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    with patch("apikey.dependencies.JWT_SECRET", "supersecretjwtkey"):
        with pytest.raises(HTTPException) as exc:
            await validate_jwt(credentials)
        assert exc.value.status_code == 401
        assert exc.value.detail == "Invalid token"


@pytest.mark.asyncio
async def test_validate_jwt_decode_error():
    """Test JWT validation with decode error."""
    credentials = HTTPAuthorizationCredentials(
        scheme="Bearer", credentials="invalid-token"
    )

    with patch("apikey.dependencies.JWT_SECRET", "supersecretjwtkey"):
        with pytest.raises(HTTPException) as exc:
            await validate_jwt(credentials)
        assert exc.value.status_code == 401
        assert exc.value.detail == "Invalid token"


def test_validate_jwt_missing_exp():
    """Test JWT validation fails if 'exp' is missing from payload."""
    payload = {
        "sub": "test-user-1",
        "email": "test@example.com",
        "aud": "fastapi-users:auth",
        # 'exp' intentionally omitted
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    with pytest.raises(HTTPException) as exc:
        # validate_jwt is async
        import asyncio

        asyncio.run(validate_jwt(credentials))
    assert exc.value.status_code == 401
    assert exc.value.detail == "Token missing expiration"


# API Key Validation Tests
@pytest.mark.asyncio
async def test_validate_api_key_success():
    """Test successful API key validation."""
    api_key = "valid-key"
    key_hash = "hashed-key"
    user_id = "test-user-id"

    api_key_obj = MagicMock()
    api_key_obj.key_hash = key_hash
    api_key_obj.status = APIKeyStatus.ACTIVE
    api_key_obj.expires_at = None
    api_key_obj.user_id = user_id

    session = AsyncMock()
    session.execute = AsyncMock(
        return_value=MagicMock(scalar_one_or_none=lambda: api_key_obj)
    )

    with patch("apikey.utils.hash_api_key", return_value=key_hash):
        user = await validate_api_key(api_key, session)
        assert isinstance(user, User)
        assert user.id == user_id
        assert user.email == ""


@pytest.mark.asyncio
async def test_validate_api_key_not_found():
    """Test API key validation with non-existent key."""
    api_key = "invalid-key"
    session = AsyncMock()
    session.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=lambda: None))

    with patch("apikey.utils.hash_api_key", return_value="bad-hash"):
        with pytest.raises(HTTPException) as exc:
            await validate_api_key(api_key, session)
        assert exc.value.status_code == 401
        assert exc.value.detail == "Invalid API key"


@pytest.mark.asyncio
async def test_validate_api_key_expired():
    """Test API key validation with expired key."""
    api_key = "expired-key"
    key_hash = "hashed-key"

    api_key_obj = MagicMock()
    api_key_obj.key_hash = key_hash
    api_key_obj.status = APIKeyStatus.ACTIVE
    api_key_obj.expires_at = datetime.now(UTC) - timedelta(days=1)

    session = AsyncMock()
    session.execute = AsyncMock(
        return_value=MagicMock(scalar_one_or_none=lambda: api_key_obj)
    )

    with patch("apikey.utils.hash_api_key", return_value=key_hash):
        with pytest.raises(HTTPException) as exc:
            await validate_api_key(api_key, session)
        assert exc.value.status_code == 401
        assert exc.value.detail == "API key has expired"


# Main Authentication Flow Tests
@pytest.mark.asyncio
async def test_get_current_user_api_key_header():
    """Test authentication with API key in header."""
    api_key = "test-key"
    user_id = "test-user-id"

    headers = [(API_KEY_HEADER.lower().encode(), api_key.encode())]
    request = make_request(headers=headers)

    mock_user = User(id=user_id, sub=user_id, email="", aud="fastapi-users:auth")
    with patch("apikey.dependencies.validate_api_key", return_value=mock_user):
        user = await get_current_user(
            request,
            credentials=None,
            api_key_header_val=api_key,
            api_key_query_val=None,
            session=AsyncMock(),
        )
        assert user == mock_user


@pytest.mark.asyncio
async def test_get_current_user_api_key_query():
    """Test authentication with API key in query parameters."""
    api_key = "test-key"
    user_id = "test-user-id"

    request = make_request(query_string=f"{API_KEY_QUERY}={api_key}".encode())

    mock_user = User(id=user_id, sub=user_id, email="", aud="fastapi-users:auth")
    with patch("apikey.dependencies.validate_api_key", return_value=mock_user):
        user = await get_current_user(
            request,
            credentials=None,
            api_key_header_val=None,
            api_key_query_val=api_key,
            session=AsyncMock(),
        )
        assert user == mock_user


@pytest.mark.asyncio
async def test_get_current_user_jwt():
    """Test authentication with JWT token."""
    user_id = "test-user-id"
    credentials = HTTPAuthorizationCredentials(
        scheme="Bearer", credentials="valid-token"
    )

    request = make_request(headers=[(b"authorization", b"Bearer valid-token")])

    mock_user = User(
        id=user_id, sub=user_id, email="test@example.com", aud="fastapi-users:auth"
    )
    with patch("apikey.dependencies.validate_jwt", return_value=mock_user):
        user = await get_current_user(
            request,
            credentials=credentials,
            api_key_header_val=None,
            api_key_query_val=None,
            session=AsyncMock(),
        )
        assert user == mock_user


@pytest.mark.asyncio
async def test_get_current_user_no_auth():
    """Test authentication with no credentials."""
    request = make_request()

    with pytest.raises(HTTPException) as exc:
        await get_current_user(
            request,
            credentials=None,
            api_key_header_val=None,
            api_key_query_val=None,
            session=AsyncMock(),
        )
    assert exc.value.status_code == 401
    assert exc.value.detail == "No authentication provided"
