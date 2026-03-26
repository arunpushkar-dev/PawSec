"""Admin routes at /api/v1/admin/ — require admin privileges."""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import require_admin
from api.models import (
    UserResponse, UserCreateRequest, UserUpdateRequest,
    UserListResponse, AdminStatsResponse, AdminSessionListResponse,
)
from database.db import get_db
from database import crud
from database.models import User

router = APIRouter(prefix="/api/v1/admin", tags=["Admin"])


def _user_to_response(u: User) -> dict:
    return {
        "user_id":      u.user_id,
        "name":         u.name,
        "company_id":   u.company_id,
        "email":        u.email,
        "api_key":      u.api_key,
        "is_admin":     u.is_admin,
        "is_active":    u.is_active,
        "created_at":   u.created_at,
        "last_used_at": u.last_used_at,
        "notes":        u.notes,
    }


@router.get("/users", response_model=UserListResponse)
async def list_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    users, total = await crud.list_users(db, page=page, page_size=page_size)
    return UserListResponse(
        total=total,
        page=page,
        page_size=page_size,
        users=[_user_to_response(u) for u in users],
    )


@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserCreateRequest,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    existing = await crud.get_user_by_email(db, body.email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "conflict", "message": "Email already in use"},
        )
    user = await crud.create_user(
        db,
        name=body.name,
        email=body.email,
        company_id=body.company_id,
        notes=body.notes,
    )
    return _user_to_response(user)


@router.put("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    body: UserUpdateRequest,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    user = await crud.update_user(
        db,
        user_id=user_id,
        name=body.name,
        email=body.email,
        company_id=body.company_id,
        is_active=body.is_active,
        notes=body.notes,
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return _user_to_response(user)


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    if user_id == admin.user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "bad_request", "message": "Cannot delete your own account"},
        )
    deleted = await crud.delete_user(db, user_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="User not found")


@router.post("/users/{user_id}/rotate-key", response_model=UserResponse)
async def rotate_key(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    user = await crud.rotate_user_api_key(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return _user_to_response(user)


@router.delete("/users/{user_id}/records", status_code=status.HTTP_200_OK)
async def delete_user_records(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Admin-only: permanently delete all prompt records for a user from the server."""
    user = await crud.get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    deleted = await crud.delete_user_records(db, user_id)
    return {"deleted": deleted, "user_id": user_id}


@router.get("/stats", response_model=AdminStatsResponse)
async def admin_stats(
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    return await crud.get_admin_stats(db)


@router.get("/trends")
async def admin_trends(
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Daily security trend counts for the last 7 days."""
    return {"trends": await crud.get_admin_trends(db)}


@router.get("/top-blocked")
async def admin_top_blocked(
    days: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Top 10 users by blocked prompt count. days=0 means all time."""
    return {"users": await crud.get_top_blocked_users(db, days=days)}


@router.get("/sessions", response_model=AdminSessionListResponse)
async def admin_sessions(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    sessions, total = await crud.get_admin_sessions(db, page=page, page_size=page_size)
    return AdminSessionListResponse(
        total=total,
        page=page,
        page_size=page_size,
        sessions=sessions,
    )
