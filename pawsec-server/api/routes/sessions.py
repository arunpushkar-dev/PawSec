"""Session CRUD routes — scoped to the authenticated user."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import require_api_key
from api.models import (
    SessionCreateRequest,
    SessionCreateResponse,
    SessionListResponse,
    UserMeResponse,
)
from database.db import get_db
from database import crud
from database.models import User

router = APIRouter(dependencies=[Depends(require_api_key)])


@router.get("/api/v1/me", response_model=UserMeResponse, tags=["Users"])
async def get_me(
    current_user: User = Depends(require_api_key),
):
    return UserMeResponse(
        user_id=current_user.user_id,
        name=current_user.name,
        email=current_user.email,
        company_id=current_user.company_id,
        is_admin=current_user.is_admin,
    )


@router.post(
    "/api/v1/sessions",
    response_model=SessionCreateResponse,
    status_code=201,
    tags=["Sessions"],
)
async def create_session(
    body: SessionCreateRequest,
    current_user: User = Depends(require_api_key),
    db: AsyncSession = Depends(get_db),
):
    session = await crud.create_session(
        db,
        user_agent=body.user_agent,
        extension_version=body.extension_version,
        platform_hint=body.platform_hint,
        user_id=current_user.user_id,
    )
    return SessionCreateResponse(
        session_id=session.session_id,
        started_at=session.started_at,
    )


@router.get(
    "/api/v1/sessions",
    response_model=SessionListResponse,
    tags=["Sessions"],
)
async def list_sessions(
    platform: str | None = Query(None),
    risk_level: str | None = Query(None),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    since: str | None = Query(default=None, description="ISO-8601 timestamp — return only sessions with activity after this time (used by dashboard Clear View)"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: User = Depends(require_api_key),
    db: AsyncSession = Depends(get_db),
):
    # Admins see all sessions; regular users see only their own
    filter_user_id = None if current_user.is_admin else current_user.user_id
    sessions, total = await crud.get_sessions(
        db,
        platform=platform,
        risk_level=risk_level,
        date_from=date_from,
        date_to=date_to,
        since=since,
        page=page,
        page_size=page_size,
        user_id=filter_user_id,
    )
    return SessionListResponse(
        sessions=sessions,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/api/v1/sessions/{session_id}",
    tags=["Sessions"],
)
async def get_session(
    session_id: str,
    current_user: User = Depends(require_api_key),
    db: AsyncSession = Depends(get_db),
):
    result = await crud.get_session_detail(db, session_id)
    if not result:
        raise HTTPException(status_code=404, detail="Session not found")
    return result


@router.get(
    "/api/v1/sessions/{session_id}/prompts/{prompt_id}",
    tags=["Sessions"],
)
async def get_prompt(
    session_id: str,
    prompt_id: str,
    current_user: User = Depends(require_api_key),
    db: AsyncSession = Depends(get_db),
):
    record = await crud.get_prompt_record(db, prompt_id)
    if not record or record.session_id != session_id:
        raise HTTPException(status_code=404, detail="Prompt not found")
    import json
    from database.crud import _utc_iso
    return {
        "prompt_id": record.prompt_id,
        "session_id": record.session_id,
        "timestamp": _utc_iso(record.timestamp),
        "masked_text": record.masked_text,
        "platform": record.platform,
        "risk_score": record.risk_score,
        "risk_level": record.risk_level,
        "action_taken": record.action_taken,
        "analysis": json.loads(record.analysis_result) if record.analysis_result else {},
        "in_browser_result": json.loads(record.in_browser_result) if record.in_browser_result else None,
    }
