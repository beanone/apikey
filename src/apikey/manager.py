from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import APIKey, APIKeyStatus
from .utils import generate_api_key, hash_api_key


def create_api_key_record(  # noqa: PLR0913
    user_id: str,
    service_id: str = "home-service",
    name: str | None = None,
    status: APIKeyStatus = APIKeyStatus.ACTIVE,
    expires_at: datetime | None = None,
    last_used_at: datetime | None = None,
    id: str | None = None,
    created_at: datetime | None = None,
    key_length: int = 40,
) -> tuple[str, APIKey]:
    """Generate a new API key, hash it, and create an APIKey record.

    Args:
        user_id: The user ID.
        service_id: The target service ID.
        name: Optional label for the key.
        status: Key status (default ACTIVE).
        expires_at: Optional expiry.
        last_used_at: Optional last used.
        id: Optional key ID.
        created_at: Optional creation time.
        key_length: Length of the generated API key.

    Returns:
        tuple[str, APIKey]: (plaintext API key, APIKey record with hash)
    """
    api_key = generate_api_key(length=key_length)
    key_hash = hash_api_key(api_key)

    # Ensure created_at is naive UTC
    final_created_at: datetime | None
    if created_at:
        final_created_at = (
            created_at.replace(tzinfo=None) if created_at.tzinfo else created_at
        )
    else:
        final_created_at = datetime.now(timezone.utc).replace(tzinfo=None)

    # Ensure expires_at is timezone-aware UTC if provided
    final_expires_at: datetime | None = None
    if expires_at:
        final_expires_at = (
            expires_at.astimezone(timezone.utc)
            if expires_at.tzinfo
            else expires_at.replace(tzinfo=timezone.utc)
        )

    # Ensure last_used_at is naive UTC if provided
    final_last_used_at: datetime | None = None
    if last_used_at:
        final_last_used_at = (
            last_used_at.replace(tzinfo=None) if last_used_at.tzinfo else last_used_at
        )

    record = APIKey(
        user_id=user_id,
        key_hash=key_hash,
        service_id=service_id,
        name=name,
        status=status,
        expires_at=final_expires_at,
        last_used_at=final_last_used_at,
        id=id,
        created_at=final_created_at,
    )
    return api_key, record


async def create_api_key(
    user_id: str,
    service_id: str,
    session: AsyncSession,
    name: str | None = None,
    expires_at: datetime | None = None,
) -> dict[str, Any]:
    """Create a new API key for the given user.

    Args:
        user_id: The user's stringified UUID.
        service_id: The service identifier.
        session: SQLAlchemy async session.
        name: Optional name for the key.
        expires_at: Optional expiration.

    Returns:
        dict: API key info including plaintext key.
    """
    plaintext_key, api_key_obj = create_api_key_record(
        user_id=user_id,
        service_id=service_id,
        name=name,
        expires_at=expires_at,
    )
    session.add(api_key_obj)
    await session.commit()
    await session.refresh(api_key_obj)
    return {
        "id": api_key_obj.id,
        "name": api_key_obj.name,
        "service_id": api_key_obj.service_id,
        "status": api_key_obj.status,
        "created_at": api_key_obj.created_at,
        "expires_at": api_key_obj.expires_at,
        "last_used_at": api_key_obj.last_used_at,
        "plaintext_key": plaintext_key,
    }


async def list_api_keys(
    user_id: str,
    session: AsyncSession,
) -> list[dict[str, Any]]:
    """List all API keys for the given user.

    Args:
        user_id: The user's stringified UUID.
        session: SQLAlchemy async session.

    Returns:
        List[dict]: List of API key info dicts.
    """
    result = await session.execute(select(APIKey).where(APIKey.user_id == user_id))
    keys = result.scalars().all()
    return [
        {
            "id": row.id,
            "name": row.name,
            "service_id": row.service_id,
            "status": row.status,
            "created_at": row.created_at,
            "expires_at": row.expires_at,
            "last_used_at": row.last_used_at,
        }
        for row in keys
    ]


async def delete_api_key(
    key_id: str,
    user_id: str,
    session: AsyncSession,
) -> bool:
    """Delete (revoke) an API key by ID for the given user.

    Args:
        key_id: The API key ID.
        user_id: The user's stringified UUID.
        session: SQLAlchemy async session.

    Returns:
        bool: True if deleted, False if not found.
    """
    result = await session.execute(
        select(APIKey).where(APIKey.id == key_id, APIKey.user_id == user_id)
    )
    row = result.first()
    if not row:
        return False
    await session.execute(
        APIKey.__table__.delete().where(APIKey.id == key_id, APIKey.user_id == user_id)
    )
    await session.commit()
    return True
