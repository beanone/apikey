"""Dependencies for the API key router."""

import logging
import os
from typing import TypedDict

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

logger = logging.getLogger(__name__)

# Configuration
LOCKSMITHA_URL = os.getenv("LOCKSMITHA_URL", "http://localhost:8001")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{LOCKSMITHA_URL}/auth/jwt/login")
JWT_SECRET = os.getenv("JWT_SECRET", "changeme")  # Should match Locksmitha's secret
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")


class User(TypedDict):
    """User information from JWT."""

    id: str
    sub: str
    email: str
    aud: str


async def get_current_user(
    request: Request,
    token: str = Depends(oauth2_scheme),
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
            id=payload["sub"],  # Use sub as id to match test expectations
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
