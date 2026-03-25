"""GET /api/v1/stats — aggregated statistics scoped to the current user."""

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import require_api_key
from api.models import StatsResponse
from database.db import get_db
from database import crud
from database.models import User

router = APIRouter(dependencies=[Depends(require_api_key)])


@router.get("/api/v1/stats", response_model=StatsResponse, tags=["Stats"])
async def get_stats(
    current_user: User = Depends(require_api_key),
    db: AsyncSession = Depends(get_db),
    since: Optional[str] = Query(default=None, description="ISO-8601 timestamp — return only records after this time (used by dashboard Clear View)"),
):
    # Admins see global stats; regular users see only their own
    filter_user_id = None if current_user.is_admin else current_user.user_id
    return await crud.get_stats(db, user_id=filter_user_id, since=since)
