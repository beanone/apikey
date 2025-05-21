import logging
import os
from datetime import datetime, timezone
from typing import ClassVar

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import (
    APIKeyHeader,
    APIKeyQuery,
    HTTPAuthorizationCredentials,
    HTTPBearer,
)
from jose import JWTError, jwt
from pydantic import ConfigDict
from pydantic_settings import BaseSettings
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .db import get_async_session
from .models import APIKey, APIKeyStatus, User
from .utils import hash_api_key

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """Application settings.

    Attributes:
        cors_origins: List of allowed CORS origins
        login_url: URL of the login service
        jwt_secret: Secret for JWT signing
        jwt_algorithm: Algorithm for JWT signing
    """

    cors_origins: ClassVar[list[str]] = ["*"]
    login_url: str = os.getenv("LOGIN_URL", "http://localhost:8001")
    jwt_secret: str = os.getenv("JWT_SECRET", "changeme")
    jwt_algorithm: str = os.getenv("JWT_ALGORITHM", "HS256")

    model_config = ConfigDict()


def get_settings() -> Settings:
    """Get application settings.

    Returns:
        Settings: Application settings instance.
    """
    return Settings()


# Configuration
LOGIN_URL = get_settings().login_url
JWT_SECRET = get_settings().jwt_secret
ALGORITHM = get_settings().jwt_algorithm

# Dependencies
get_db_session = Depends(get_async_session)

API_KEY_HEADER = "X-API-Key"
API_KEY_QUERY = "api_key"

# Security Schemes
bearer_auth = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name=API_KEY_HEADER, auto_error=False)
api_key_query = APIKeyQuery(name=API_KEY_QUERY, auto_error=False)


async def validate_jwt(credentials: HTTPAuthorizationCredentials) -> User:
    """Validate JWT token."""
    token = credentials.credentials
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[ALGORITHM],
            audience="fastapi-users:auth",
        )
        logger.debug(f"JWT decode successful, payload: {payload}")
        if "sub" not in payload:
            logger.warning("Token missing 'sub' claim.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            )
        if "exp" not in payload:
            logger.warning("Token missing 'exp' claim.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token missing expiration",
            )
        return User(
            id=payload["sub"],
            sub=payload["sub"],
            email=payload.get("email", ""),
            aud=payload.get("aud", "fastapi-users:auth"),
        )
    except JWTError as e:
        logger.error(f"JWT decode error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        ) from e


async def validate_api_key(api_key: str, session: AsyncSession) -> User:
    """Validate an API key.

    Args:
        api_key: The API key to validate.
        session: The database session.

    Returns:
        User: The authenticated user.

    Raises:
        HTTPException: If the API key is invalid or expired.
    """
    key_hash = hash_api_key(api_key)
    stmt = select(APIKey).where(
        APIKey.key_hash == key_hash, APIKey.status == APIKeyStatus.ACTIVE
    )
    result = await session.execute(stmt)
    api_key_obj = result.scalar_one_or_none()
    if api_key_obj is None:
        logger.warning("API key not found or invalid.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
    # Check if key is expired
    if api_key_obj.expires_at is not None:
        # Convert expires_at to timezone-aware UTC if it's naive
        expires_at = (
            api_key_obj.expires_at.replace(tzinfo=timezone.utc)
            if api_key_obj.expires_at.tzinfo is None
            else api_key_obj.expires_at
        )
        if expires_at < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key has expired",
            )
    return User(
        id=api_key_obj.user_id,
        sub=api_key_obj.user_id,
        email="",
        aud="fastapi-users:auth",
    )


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_auth),  # noqa: B008
    api_key_header_val: str | None = Depends(api_key_header),
    api_key_query_val: str | None = Depends(api_key_query),
    session: AsyncSession = Depends(get_async_session),  # noqa: B008
) -> User:
    """Get the current authenticated user from JWT or API key."""
    # Try API key authentication (header or query)
    api_key = api_key_header_val or api_key_query_val
    if api_key:
        logger.debug(f"Found API key: {api_key}")
        return await validate_api_key(api_key, session)

    # Try JWT authentication
    if credentials:
        logger.debug("Found JWT credentials")
        return await validate_jwt(credentials)

    logger.warning("No valid authentication provided")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No authentication provided",
    )
