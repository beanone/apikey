import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import TypedDict

from sqlalchemy import Column, DateTime, Index, String
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.orm import DeclarativeBase


class DBState:
    """Database state."""

    engine = None
    async_session_maker = None


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""

    pass


class User(TypedDict):
    """User information from JWT."""

    id: str
    sub: str
    email: str
    aud: str


class APIKeyStatus(str, Enum):
    """Enum for API key status values."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    REVOKED = "revoked"
    EXPIRED = "expired"


class APIKey(Base):
    """
    API Key model for managing user API keys.

    Attributes:
        id: Unique identifier for the API key
        user_id: String version of the user's UUID (no foreign key constraint)
        key_hash: Hashed version of the API key
        name: Optional name for the API key
        created_at: Timestamp when the key was created
        service_id: Identifier for the service this key is associated with
        status: Current status of the API key (active/inactive/revoked/expired)
        expires_at: Optional timestamp when the key expires
        last_used_at: Timestamp of the last time the key was used
    """

    __tablename__ = "api_keys"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), nullable=False)
    key_hash = Column(String, nullable=False, unique=True)
    name = Column(String)
    created_at = Column(DateTime, default=datetime.now(UTC))
    service_id = Column(String, nullable=False)
    status = Column(SQLEnum(APIKeyStatus), default=APIKeyStatus.ACTIVE, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    __table_args__ = (Index("ix_api_keys_user_id", "user_id"),)

    def __init__(
        self,
        user_id: str,
        key_hash: str,
        service_id: str,
        name: str | None = None,
        status: APIKeyStatus = APIKeyStatus.ACTIVE,
        expires_at: datetime | None = None,
        last_used_at: datetime | None = None,
        id: str | None = None,
        created_at: datetime | None = None,
    ) -> None:
        """
        Initialize a new API key.

        Args:
            user_id: String version of the user's UUID
            key_hash: Hashed version of the API key
            service_id: Identifier for the service this key is associated with
            name: Optional name for the API key
            status: Current status of the API key
            expires_at: Optional timestamp when the key expires
            last_used_at: Timestamp of the last time the key was used
            id: Optional custom ID for the key
            created_at: Optional custom creation timestamp

        Raises:
            ValueError: If service_id is empty
        """
        if not service_id:
            raise ValueError("service_id is required for APIKey")
        self.id = id or str(uuid.uuid4())
        self.user_id = user_id
        self.key_hash = key_hash
        self.name = name
        self.created_at = created_at or datetime.now(UTC)
        self.service_id = service_id
        self.status = status
        self.expires_at = expires_at
        self.last_used_at = last_used_at
