"""API key authentication for PawSec Server."""

from fastapi import Header, HTTPException, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from database.db import get_db
from database import crud
from database.models import User

_LOCALHOST_IPS = frozenset({"127.0.0.1", "::1", "localhost"})


async def require_api_key(
    request: Request,
    x_api_key: str = Header(None, alias="X-API-Key"),
    db: AsyncSession = Depends(get_db),
) -> User:
    """FastAPI dependency: validate the X-API-Key header against the users table.

    Localhost trusted bypass: if the request originates from 127.0.0.1 / ::1
    and no API key is supplied, the first active admin user is returned
    automatically so the admin dashboard works without any credentials.
    """
    client_ip = (request.client.host if request.client else "") or ""

    if client_ip in _LOCALHOST_IPS and not x_api_key:
        admin = await crud.get_first_admin(db)
        if admin:
            return admin
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "no_admin", "message": "No admin account found. Create one via CLI first."},
        )

    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "unauthorized", "message": "Missing API key"},
        )
    user = await crud.get_user_by_api_key(db, x_api_key)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "unauthorized", "message": "Invalid or inactive API key"},
        )
    # Update last_used_at without blocking the request
    await crud.touch_user_last_used(db, user.user_id)
    return user


async def require_admin(current_user: User = Depends(require_api_key)) -> User:
    """FastAPI dependency: require the authenticated user to be an admin."""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "forbidden", "message": "Admin privileges required"},
        )
    return current_user
