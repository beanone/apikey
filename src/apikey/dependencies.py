"""Dependencies for the API key router."""

import logging
import os

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
LOCKSMITHA_URL = os.getenv("LOCKSMITHA_URL", "http://localhost:8001")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{LOCKSMITHA_URL}/auth/jwt/login")
JWT_SECRET = os.getenv("JWT_SECRET", "changeme")  # Should match Locksmitha's secret
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")


API_KEY_HEADER = "X-API-Key"
API_KEY_QUERY = "api_key"


async def get_current_user(
    request: Request,
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_async_session),
) -> User:
    """Get the current authenticated user from JWT.

    Args:
        request: The FastAPI request.
        token: The JWT token.

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
    api_key = request.headers.get(API_KEY_HEADER)
    if api_key:
        return api_key
    api_key = request.query_params.get(API_KEY_QUERY)
    return api_key


async def validate_api_key(api_key: str, session: AsyncSession) -> dict:
    from datetime import UTC, datetime

    key_hash = hash_api_key(api_key)
    stmt = select(APIKey).where(APIKey.key_hash == key_hash, APIKey.status == "active")
    result = await session.execute(stmt)
    api_key_obj = result.scalar_one_or_none()
    if api_key_obj is None:
        logger.warning("API key not found or invalid.")
        raise HTTPException(status_code=401, detail="Invalid API key")
    # Optionally check expiry
    if api_key_obj.expires_at is not None and api_key_obj.expires_at < datetime.now(
        UTC
    ):
        logger.warning("API key expired.")
        raise HTTPException(status_code=401, detail="API key expired")
    return {
        "user_id": api_key_obj.user_id,
        "api_key_id": api_key_obj.id,
    }
