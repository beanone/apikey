from datetime import UTC
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException
from jose import JWTError, jwt
from starlette.requests import Request

from apikey.dependencies import (
    API_KEY_HEADER,
    CustomSecurityScheme,
    get_api_key_from_request,
    get_current_user,
    validate_api_key,
)
from apikey.models import User


def make_request(headers=None, query_string=b""):
    headers = headers or []
    return Request({"type": "http", "headers": headers, "query_string": query_string})


@pytest.mark.asyncio
async def test_get_current_user_valid(monkeypatch):
    payload = {
        "sub": "123e4567-e89b-12d3-a456-426614174000",
        "email": "test@example.com",
    }

    def fake_decode(token, secret, algorithms, **kwargs):
        assert token == "validtoken"
        return payload

    monkeypatch.setattr(jwt, "decode", fake_decode)
    request = make_request(headers=[(b"authorization", b"Bearer validtoken")])
    result = await get_current_user(request, session=AsyncMock())
    assert isinstance(result, User)
    assert result.id == payload["sub"]
    assert result.sub == payload["sub"]
    assert result.email == payload["email"]
    assert result.aud == "fastapi-users:auth"


@pytest.mark.asyncio
async def test_get_current_user_invalid_token(monkeypatch):
    def fake_decode(token, secret, algorithms, **kwargs):
        raise JWTError("bad token")

    monkeypatch.setattr(jwt, "decode", fake_decode)
    request = make_request(headers=[(b"authorization", b"Bearer invalidtoken")])
    with pytest.raises(HTTPException) as exc:
        await get_current_user(request, session=AsyncMock())
    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid token"


@pytest.mark.asyncio
async def test_get_current_user_missing_sub(monkeypatch):
    payload = {"email": "test@example.com"}

    def fake_decode(token, secret, algorithms, **kwargs):
        return payload

    monkeypatch.setattr(jwt, "decode", fake_decode)
    request = make_request(headers=[(b"authorization", b"Bearer validtoken")])
    with pytest.raises(HTTPException) as exc:
        await get_current_user(request, session=AsyncMock())
    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid token"


@pytest.mark.asyncio
async def test_get_api_key_from_request_header():
    api_key = "testkey123"
    # ASGI headers are lower-case, bytes
    headers = [(API_KEY_HEADER.lower().encode(), api_key.encode())]
    request = make_request(headers=headers)
    result = await get_api_key_from_request(request)
    assert result == api_key


@pytest.mark.asyncio
async def test_validate_api_key_valid(monkeypatch):
    # Mock APIKey and User objects
    api_key = "validkey"
    key_hash = "hashedkey"
    user_id = "user-1"
    api_key_obj = MagicMock()
    api_key_obj.key_hash = key_hash
    api_key_obj.status = "active"
    api_key_obj.expires_at = None
    api_key_obj.user_id = user_id
    api_key_obj.id = "key-1"
    user_obj = MagicMock()
    user_obj.email = "user@example.com"
    # Mock session
    session = AsyncMock()
    session.execute = AsyncMock(
        side_effect=[
            MagicMock(scalar_one_or_none=lambda: api_key_obj),
            MagicMock(scalar_one_or_none=lambda: user_obj),
        ]
    )
    # Patch hash_api_key to return the expected hash
    monkeypatch.setattr("apikey.utils.hash_api_key", lambda k: key_hash)
    result = await validate_api_key(api_key, session)
    assert result["user_id"] == user_id
    assert result["api_key_id"] == api_key_obj.id


@pytest.mark.asyncio
async def test_validate_api_key_invalid(monkeypatch):
    api_key = "invalidkey"
    session = AsyncMock()
    session.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=lambda: None))
    monkeypatch.setattr("apikey.utils.hash_api_key", lambda k: "bad_hash")
    with pytest.raises(HTTPException) as exc:
        await validate_api_key(api_key, session)
    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid API key"


@pytest.mark.asyncio
async def test_validate_api_key_expired(monkeypatch):
    from datetime import datetime, timedelta

    api_key = "expiredkey"
    key_hash = "expired_hash"
    api_key_obj = MagicMock()
    api_key_obj.key_hash = key_hash
    api_key_obj.status = "active"
    api_key_obj.expires_at = datetime.now(UTC) - timedelta(days=1)
    api_key_obj.user_id = "user-2"
    api_key_obj.id = "key-2"
    session = AsyncMock()
    session.execute = AsyncMock(
        side_effect=[
            MagicMock(scalar_one_or_none=lambda: api_key_obj),
        ]
    )
    monkeypatch.setattr("apikey.utils.hash_api_key", lambda k: key_hash)
    with pytest.raises(HTTPException) as exc:
        await validate_api_key(api_key, session)
    assert exc.value.status_code == 401
    assert exc.value.detail == "API key has expired"


@pytest.mark.asyncio
async def test_validate_api_key_user_not_found(monkeypatch):
    api_key = "validkey"
    key_hash = "hashedkey"
    api_key_obj = MagicMock()
    api_key_obj.key_hash = key_hash
    api_key_obj.status = "active"
    api_key_obj.expires_at = None
    api_key_obj.user_id = "user-3"
    api_key_obj.id = "key-3"
    session = AsyncMock()
    session.execute = AsyncMock(
        side_effect=[
            MagicMock(scalar_one_or_none=lambda: api_key_obj),
            MagicMock(scalar_one_or_none=lambda: None),
        ]
    )
    monkeypatch.setattr("apikey.utils.hash_api_key", lambda k: key_hash)
    result = await validate_api_key(api_key, session)
    assert result["user_id"] == api_key_obj.user_id
    assert result["api_key_id"] == api_key_obj.id


@pytest.mark.asyncio
async def test_get_current_user_jwt_decode_error(monkeypatch):
    request = make_request(headers=[(b"authorization", b"Bearer badtoken")])

    def fake_decode(token, secret, algorithms, **kwargs):
        raise JWTError("bad token")

    monkeypatch.setattr(jwt, "decode", fake_decode)
    with pytest.raises(HTTPException) as exc:
        await get_current_user(request, session=AsyncMock())
    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid token"


@pytest.mark.asyncio
async def test_get_current_user_with_api_key(monkeypatch):
    api_key = "testkey123"
    expected_user_info = {
        "user_id": "user-xyz",
        "api_key_id": "key-xyz",
    }
    monkeypatch.setattr(
        "apikey.dependencies.validate_api_key",
        AsyncMock(return_value=expected_user_info),
    )
    headers = [(API_KEY_HEADER.lower().encode(), api_key.encode())]
    request = make_request(headers=headers)
    result = await get_current_user(request, session=AsyncMock())
    assert isinstance(result, User)
    assert result.id == expected_user_info["user_id"]
    assert result.sub == expected_user_info["user_id"]
    assert result.email == ""
    assert result.aud == "fastapi-users:auth"


@pytest.mark.asyncio
async def test_get_current_user_no_auth():
    """Test get_current_user with no authentication provided."""
    request = make_request()  # No headers or query params
    with pytest.raises(HTTPException) as exc:
        await get_current_user(request, session=AsyncMock())
    assert exc.value.status_code == 401
    assert exc.value.detail == "No authentication provided"


@pytest.mark.asyncio
async def test_get_current_user_invalid_auth_header():
    """Test get_current_user with invalid Authorization header format."""
    # Test with non-Bearer token
    request = make_request(headers=[(b"authorization", b"InvalidFormat token")])
    with pytest.raises(HTTPException) as exc:
        await get_current_user(request, session=AsyncMock())
    assert exc.value.status_code == 401
    assert exc.value.detail == "No authentication provided"

    # Test with empty token
    request = make_request(headers=[(b"authorization", b"Bearer ")])
    with pytest.raises(HTTPException) as exc:
        await get_current_user(request, session=AsyncMock())
    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid token"  # Empty token is treated as invalid JWT


@pytest.mark.asyncio
async def test_get_api_key_from_request_query():
    """Test getting API key from query parameters."""
    # Test with API key in query parameters
    request = make_request(query_string=b"api_key=testkey123")
    result = await get_api_key_from_request(request)
    assert result == "testkey123"

    # Test with no API key in query parameters
    request = make_request(query_string=b"")
    result = await get_api_key_from_request(request)
    assert result is None

    # Test with other query parameters but no API key
    request = make_request(query_string=b"other=value")
    result = await get_api_key_from_request(request)
    assert result is None


@pytest.mark.asyncio
async def test_custom_security_scheme_valid_bearer_token():
    """Test CustomSecurityScheme with valid Bearer token.

    Verifies that a valid Bearer token is correctly extracted from the
    Authorization header.
    """
    # Arrange: Create request with valid Bearer token
    request = make_request(headers=[(b"authorization", b"Bearer validtoken")])
    security_scheme = CustomSecurityScheme()

    # Act: Call the security scheme
    token = await security_scheme.__call__(request)

    # Assert: Token is extracted correctly
    assert token == "validtoken"


@pytest.mark.asyncio
async def test_custom_security_scheme_no_auth_header():
    """Test CustomSecurityScheme with missing Authorization header.

    Verifies that None is returned when no Authorization header is present.
    """
    # Arrange: Create request with no Authorization header
    request = make_request(headers=[])
    security_scheme = CustomSecurityScheme()

    # Act: Call the security scheme
    token = await security_scheme.__call__(request)

    # Assert: Returns None
    assert token is None


@pytest.mark.asyncio
async def test_custom_security_scheme_invalid_auth_header():
    """Test CustomSecurityScheme with invalid Authorization header.

    Verifies that None is returned when Authorization header doesn't use Bearer scheme.
    """
    # Arrange: Create request with invalid Authorization header (no Bearer)
    request = make_request(headers=[(b"authorization", b"Basic credentials")])
    security_scheme = CustomSecurityScheme()

    # Act: Call the security scheme
    token = await security_scheme.__call__(request)

    # Assert: Returns None
    assert token is None
