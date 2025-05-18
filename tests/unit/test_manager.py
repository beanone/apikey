from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, Mock
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from apikey.manager import create_api_key, delete_api_key, list_api_keys, create_api_key_record
from apikey.models import APIKey, APIKeyStatus


@pytest.fixture
def fake_user_id():
    return "user-123"


@pytest.fixture
def fake_api_key_instance():
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
async def test_create_api_key(fake_user_id, fake_api_key_instance, monkeypatch):
    mock_db_session = AsyncMock(spec=AsyncSession)
    mock_db_session.add = Mock()
    mock_db_session.commit = AsyncMock()
    mock_db_session.refresh = AsyncMock()

    monkeypatch.setattr(
        "apikey.manager.create_api_key_record",
        lambda **kwargs: ("plaintext_example_key", fake_api_key_instance),
    )

    result = await create_api_key(
        user_id=fake_user_id,
        service_id="svc",
        session=mock_db_session,
        name="test key",
        expires_at=fake_api_key_instance.expires_at,
    )

    assert result["id"] == fake_api_key_instance.id
    assert result["plaintext_key"] == "plaintext_example_key"
    assert result["name"] == fake_api_key_instance.name
    mock_db_session.add.assert_called_once_with(fake_api_key_instance)
    mock_db_session.commit.assert_awaited_once()
    mock_db_session.refresh.assert_awaited_once_with(fake_api_key_instance)


@pytest.mark.asyncio
async def test_list_api_keys(fake_user_id, fake_api_key_instance):
    mock_db_session = AsyncMock(spec=AsyncSession)
    mock_execute_result = Mock()
    mock_scalar_result = Mock()
    mock_scalar_result.all.return_value = [fake_api_key_instance]
    mock_execute_result.scalars.return_value = mock_scalar_result
    mock_db_session.execute = AsyncMock(return_value=mock_execute_result)

    result = await list_api_keys(user_id=fake_user_id, session=mock_db_session)
    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["id"] == fake_api_key_instance.id
    assert result[0]["name"] == fake_api_key_instance.name
    mock_db_session.execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_delete_api_key_success(fake_user_id, fake_api_key_instance):
    mock_db_session = AsyncMock(spec=AsyncSession)

    mock_result_for_find = MagicMock()
    mock_result_for_find.first.return_value = fake_api_key_instance

    mock_result_for_delete = MagicMock()

    # Revert to side_effect providing the resolved MagicMock objects directly
    mock_db_session.execute = AsyncMock(
        side_effect=[mock_result_for_find, mock_result_for_delete]
    )

    mock_db_session.commit = AsyncMock()

    result = await delete_api_key(
        key_id=fake_api_key_instance.id,
        user_id=fake_user_id,
        session=mock_db_session,
    )
    assert result is True
    assert mock_db_session.execute.call_count == 2
    mock_db_session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_delete_api_key_not_found(fake_user_id):
    mock_db_session = AsyncMock(spec=AsyncSession)
    mock_execute_result_first = Mock()
    mock_execute_result_first.first.return_value = None
    mock_db_session.execute = AsyncMock(return_value=mock_execute_result_first)

    result = await delete_api_key(
        key_id="non_existent_key_id",
        user_id=fake_user_id,
        session=mock_db_session,
    )
    assert result is False
    mock_db_session.execute.assert_awaited_once()


def test_create_api_key_record_basic() -> None:
    """Test basic API key record creation with minimal parameters."""
    user_id = "user-123"

    plaintext_key, record = create_api_key_record(
        user_id=user_id,
    )

    assert isinstance(plaintext_key, str)
    assert len(plaintext_key) == 40  # Default key length
    assert isinstance(record, APIKey)
    assert record.user_id == user_id
    assert record.service_id == "home-service"  # Verify default service_id
    assert record.status == APIKeyStatus.ACTIVE
    assert record.name is None
    assert record.expires_at is None
    assert record.last_used_at is None
    assert record.id is not None
    assert isinstance(record.created_at, datetime)
    assert record.created_at.tzinfo is None  # Should be naive UTC


def test_create_api_key_service_id_null() -> None:
    """Test basic API key record creation with minimal parameters."""
    user_id = "user-123"

    with pytest.raises(ValueError):
        APIKey(
            user_id=user_id,
            service_id=None,
            key_hash="fake_hashed_key",
        )


def test_create_api_key_record_with_all_params() -> None:
    """Test API key record creation with all optional parameters."""
    user_id = "user-123"
    service_id = "svc-123"
    name = "Test Key"
    status = APIKeyStatus.INACTIVE
    key_id = "key-123"
    created_at = datetime.now(timezone.utc)
    expires_at = created_at + timedelta(days=30)
    last_used_at = created_at + timedelta(hours=1)
    key_length = 32

    plaintext_key, record = create_api_key_record(
        user_id=user_id,
        service_id=service_id,
        name=name,
        status=status,
        expires_at=expires_at,
        last_used_at=last_used_at,
        id=key_id,
        created_at=created_at,
        key_length=key_length,
    )

    assert isinstance(plaintext_key, str)
    assert len(plaintext_key) == key_length
    assert isinstance(record, APIKey)
    assert record.user_id == user_id
    assert record.service_id == service_id
    assert record.status == status
    assert record.name == name
    assert record.id == key_id
    assert record.created_at == created_at.replace(tzinfo=None)
    assert record.expires_at == expires_at.replace(tzinfo=None)
    assert record.last_used_at == last_used_at.replace(tzinfo=None)


def test_create_api_key_record_timezone_handling() -> None:
    """Test timezone handling in API key record creation."""
    # Test with timezone-aware datetime
    tz_aware = datetime.now(timezone.utc)
    _, record = create_api_key_record(
        user_id="user-123",
        service_id="svc-123",
        created_at=tz_aware,
        expires_at=tz_aware,
        last_used_at=tz_aware,
    )

    assert record.created_at.tzinfo is None
    assert record.expires_at.tzinfo is None
    assert record.last_used_at.tzinfo is None

    # Test with naive datetime
    naive = datetime.now()
    _, record = create_api_key_record(
        user_id="user-123",
        service_id="svc-123",
        created_at=naive,
        expires_at=naive,
        last_used_at=naive,
    )

    assert record.created_at == naive
    assert record.expires_at == naive
    assert record.last_used_at == naive


def test_create_api_key_record_custom_key_length() -> None:
    """Test API key record creation with custom key length."""
    key_length = 64
    plaintext_key, _ = create_api_key_record(
        user_id="user-123",
        service_id="svc-123",
        key_length=key_length,
    )

    assert len(plaintext_key) == key_length
