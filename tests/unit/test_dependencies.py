from datetime import UTC
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException
from jose import JWTError, jwt
from starlette.requests import Request

from apikey.dependencies import (
    API_KEY_HEADER,
    get_api_key_from_request,
    get_current_user,
    validate_api_key,
)


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
    request = make_request()
    result = await get_current_user(request, token="validtoken")
    expected = {
        "id": payload["sub"],
        "sub": payload["sub"],
        "email": payload["email"],
        "aud": "fastapi-users:auth",
    }
    assert dict(result) == expected


@pytest.mark.asyncio
async def test_get_current_user_invalid_token(monkeypatch):
    def fake_decode(token, secret, algorithms, **kwargs):
        raise JWTError("bad token")

    monkeypatch.setattr(jwt, "decode", fake_decode)
    request = make_request()
    with pytest.raises(HTTPException) as exc:
        await get_current_user(request, token="invalidtoken")
    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid token"


@pytest.mark.asyncio
async def test_get_current_user_missing_sub(monkeypatch):
    payload = {"email": "test@example.com"}

    def fake_decode(token, secret, algorithms, **kwargs):
        return payload

    monkeypatch.setattr(jwt, "decode", fake_decode)
    request = make_request()
    with pytest.raises(HTTPException) as exc:
        await get_current_user(request, token="validtoken")
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
    assert exc.value.detail == "API key expired"


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
    request = make_request()

    def fake_decode(token, secret, algorithms, **kwargs):
        raise JWTError("bad token")

    monkeypatch.setattr(jwt, "decode", fake_decode)
    with pytest.raises(HTTPException) as exc:
        await get_current_user(request, token="badtoken", session=AsyncMock())
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
    result = await get_current_user(request, token="any", session=AsyncMock())
    expected = {
        "id": expected_user_info["user_id"],
        "sub": expected_user_info["user_id"],
        "email": "",
        "aud": "fastapi-users:auth",
    }
    assert dict(result) == expected
