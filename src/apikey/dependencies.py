"""Dependencies for the API key router."""

import logging
import os
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .db import get_async_session
from .models import APIKey, User
from .utils import hash_api_key

logger = logging.getLogger(__name__)

# Configuration
LOGIN_URL = os.getenv("LOGIN_URL", "http://localhost:8001")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{LOGIN_URL}/auth/jwt/login")
JWT_SECRET = os.getenv("JWT_SECRET", "changeme")  # Should match Locksmitha's secret
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

# Dependencies
get_token = Depends(oauth2_scheme)
get_db_session = Depends(get_async_session)

API_KEY_HEADER = "X-API-Key"
API_KEY_QUERY = "api_key"


async def get_current_user(
    request: Request,
    token: str = get_token,
    session: AsyncSession = get_db_session,
) -> User:
    """Get the current authenticated user from JWT.

    Args:
        request: The FastAPI request.
        token: The JWT token.
        session: The database session.

    Returns:
        User information from JWT.

    Raises:
        HTTPException: If the user is not authenticated.
    """
    logger.debug(f"Received token: {token}")
    api_key = await get_api_key_from_request(request)
    if api_key:
        # Prefer API key if present
        user_info = await validate_api_key(api_key, session)
        return User(
            id=user_info["user_id"],
            sub=user_info["user_id"],
            email="",
            aud="fastapi-users:auth",
        )
    # Fallback to JWT
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[ALGORITHM],
            audience="fastapi-users:auth",
        )
        if "sub" not in payload:
            logger.warning("Token missing 'sub' claim.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            )
        logger.debug(f"Token payload: {payload}")
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
    stmt = select(APIKey).where(APIKey.key_hash == key_hash, APIKey.status == "active")
    result = await session.execute(stmt)
    api_key_obj = result.scalar_one_or_none()
    if api_key_obj is None:
        logger.warning("API key not found or invalid.")
        raise HTTPException(status_code=401, detail="Invalid API key")
    # Optionally check expiry
    if api_key_obj.expires_at is not None and api_key_obj.expires_at < datetime.now(
        timezone.utc
    ):
        logger.warning("API key expired.")
        raise HTTPException(status_code=401, detail="API key expired")
    return {
        "user_id": api_key_obj.user_id,
        "api_key_id": api_key_obj.id,
    }
