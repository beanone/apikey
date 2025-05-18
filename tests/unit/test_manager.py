from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from apikey.manager import create_api_key, delete_api_key, list_api_keys
from apikey.models import APIKey


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
