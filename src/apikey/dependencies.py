"""Dependencies for the API key router."""

import logging
import os
from datetime import datetime, timezone
from typing import ClassVar

from fastapi import Depends, HTTPException, Request, status
from jose import JWTError, jwt
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

    class Config:
        """Pydantic config."""

        env_prefix = "APIKEY_"


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


class CustomSecurityScheme:
    """Custom security scheme that doesn't automatically validate JWT tokens."""

    def __init__(self):
        """Initialize the security scheme."""
        self.scheme_name = "CustomSecurity"

    async def __call__(self, request: Request) -> str | None:
        """Get the token from the Authorization header without validation.

        Args:
            request: The FastAPI request.

        Returns:
            The token if present, None otherwise.
        """
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return None
        return auth_header.replace("Bearer ", "")


# Create custom security scheme instance
custom_security = CustomSecurityScheme()


async def get_current_user(
    request: Request,
    session: AsyncSession = get_db_session,
) -> User:
    """Get the current authenticated user from JWT or API key.

    Args:
        request: The FastAPI request.
        session: The database session.

    Returns:
        User information from JWT or API key.

    Raises:
        HTTPException: If the user is not authenticated.
    """
    # First try API key authentication
    api_key = await get_api_key_from_request(request)
    if api_key:
        print(f"Found API key in request: {api_key}")
        user_info = await validate_api_key(api_key, session)
        return User(
            id=user_info["user_id"],
            sub=user_info["user_id"],
            email="",
            aud="fastapi-users:auth",
        )

    # If no API key, try JWT authentication
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        logger.warning("No valid authentication provided")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No authentication provided",
        )

    token = auth_header.replace("Bearer ", "")
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


async def get_api_key_from_request(request: Request) -> str | None:
    """Get API key from request headers or query parameters.

    Args:
        request: The FastAPI request.

    Returns:
        The API key if found, None otherwise.
    """
    api_key = request.headers.get(API_KEY_HEADER)
    print(f"API key from request: {api_key}")
    if api_key:
        return api_key
    api_key = request.query_params.get(API_KEY_QUERY)
    return api_key


async def validate_api_key(api_key: str, session: AsyncSession) -> dict[str, str]:
    """Validate an API key.

    Args:
        api_key: The API key to validate.
        session: The database session.

    Returns:
        Dict containing user_id and api_key_id.

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
        raise HTTPException(status_code=401, detail="Invalid API key")
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
    return {"user_id": api_key_obj.user_id, "api_key_id": api_key_obj.id}
