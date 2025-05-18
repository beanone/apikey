"""API key router implementation."""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from .db import get_async_session
from .dependencies import get_current_user
from .manager import create_api_key as handler_create_api_key
from .manager import delete_api_key as handler_delete_api_key
from .manager import list_api_keys as handler_list_api_keys
from .models import User


class APIKeyCreateRequest(BaseModel):
    """Request model for creating an API key."""

    model_config = ConfigDict(from_attributes=True, extra="forbid")

    name: str | None = None
    service_id: str
    expires_at: datetime | None = None


class APIKeyReadResponse(BaseModel):
    """Response model for API key information."""

    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: str
    name: str | None
    service_id: str
    status: str
    created_at: datetime
    expires_at: datetime | None
    last_used_at: datetime | None


class APIKeyCreateResponse(APIKeyReadResponse):
    """Response model for API key creation."""

    model_config = ConfigDict(from_attributes=True, extra="forbid")

    plaintext_key: str


api_key_router = APIRouter(prefix="/api-keys", tags=["api-keys"])


@api_key_router.post(
    "/", response_model=APIKeyCreateResponse, status_code=status.HTTP_201_CREATED
)
async def create_api_key(
    req: APIKeyCreateRequest,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> APIKeyCreateResponse:
    """Create a new API key for the authenticated user."""
    user_id = str(user.id)  # type: ignore[attr-defined]
    result = await handler_create_api_key(
        user_id=user_id,
        service_id=req.service_id,
        session=session,
        name=req.name,
        expires_at=req.expires_at,
    )
    return APIKeyCreateResponse(**result)


@api_key_router.get("/", response_model=list[APIKeyReadResponse])
async def list_api_keys(
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> list[APIKeyReadResponse]:
    """List all API keys for the authenticated user."""
    user_id = str(user.id)  # type: ignore[attr-defined]
    keys = await handler_list_api_keys(user_id=user_id, session=session)
    return [APIKeyReadResponse(**k) for k in keys]


@api_key_router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_api_key(
    key_id: str,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> None:
    """Delete (revoke) an API key by ID for the authenticated user."""
    user_id = str(user.id)  # type: ignore[attr-defined]
    deleted = await handler_delete_api_key(
        key_id=key_id, user_id=user_id, session=session
    )
    if not deleted:
        raise HTTPException(status_code=404, detail="API key not found")
