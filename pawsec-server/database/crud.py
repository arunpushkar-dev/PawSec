"""CRUD operations for PawSec Server."""

import uuid
import json
import secrets
from datetime import datetime
from typing import Optional
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Session, PromptRecord, User


def _utc_iso(dt: datetime | None) -> str | None:
    """Return a UTC ISO-8601 string with 'Z' suffix so browsers parse correctly."""
    if dt is None:
        return None
    return dt.isoformat() + "Z"


# -- Users --------------------------------------------------------------------

async def get_user_by_api_key(db: AsyncSession, api_key: str) -> Optional[User]:
    result = await db.execute(select(User).where(User.api_key == api_key))
    return result.scalar_one_or_none()


async def get_first_admin(db: AsyncSession) -> Optional[User]:
    """Return the first active admin user — used for localhost trusted bypass."""
    result = await db.execute(
        select(User).where(User.is_admin == True, User.is_active == True).limit(1)
    )
    return result.scalar_one_or_none()


async def get_user_by_id(db: AsyncSession, user_id: str) -> Optional[User]:
    result = await db.execute(select(User).where(User.user_id == user_id))
    return result.scalar_one_or_none()


async def get_user_by_email(db: AsyncSession, email: str) -> Optional[User]:
    result = await db.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()


async def count_users(db: AsyncSession) -> int:
    return (await db.execute(select(func.count()).select_from(User))).scalar_one()


async def list_users(
    db: AsyncSession,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[User], int]:
    total = (await db.execute(select(func.count()).select_from(User))).scalar_one()
    offset = (page - 1) * page_size
    rows = (await db.execute(
        select(User).order_by(User.created_at.asc()).offset(offset).limit(page_size)
    )).scalars().all()
    return list(rows), total


async def _generate_unique_api_key(db: AsyncSession) -> str:
    """Generate a psk_ key guaranteed not to already exist in the users table."""
    for _ in range(10):
        candidate = "psk_" + secrets.token_urlsafe(24)  # 192-bit URL-safe base64
        existing = await db.execute(select(User).where(User.api_key == candidate))
        if existing.scalar_one_or_none() is None:
            return candidate
    raise RuntimeError("Failed to generate a unique API key after 10 attempts")


async def create_user(
    db: AsyncSession,
    name: str,
    email: str,
    company_id: str = None,
    notes: str = None,
    is_admin: bool = False,
    api_key: str = None,
) -> User:
    if api_key is None:
        api_key = await _generate_unique_api_key(db)
    user = User(
        user_id=str(uuid.uuid4()),
        name=name,
        email=email,
        company_id=company_id,
        notes=notes,
        is_admin=is_admin,
        is_active=True,
        api_key=api_key,
        created_at=datetime.utcnow(),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def update_user(
    db: AsyncSession,
    user_id: str,
    **kwargs,
) -> Optional[User]:
    user = await get_user_by_id(db, user_id)
    if not user:
        return None
    allowed = {"name", "company_id", "email", "is_active", "notes"}
    for k, v in kwargs.items():
        if k in allowed and v is not None:
            setattr(user, k, v)
    # Allow explicit False for is_active
    if "is_active" in kwargs and kwargs["is_active"] is not None:
        user.is_active = kwargs["is_active"]
    await db.commit()
    await db.refresh(user)
    return user


async def delete_user(db: AsyncSession, user_id: str) -> bool:
    user = await get_user_by_id(db, user_id)
    if not user:
        return False
    await db.delete(user)
    await db.commit()
    return True


async def delete_user_records(db: AsyncSession, user_id: str) -> int:
    """Delete all prompt records and sessions for a user.
    Returns the number of prompt records deleted."""
    from sqlalchemy import delete as sql_delete
    count_q = select(func.count()).select_from(PromptRecord).where(PromptRecord.user_id == user_id)
    deleted_count = (await db.execute(count_q)).scalar_one()
    await db.execute(sql_delete(PromptRecord).where(PromptRecord.user_id == user_id))
    await db.execute(sql_delete(Session).where(Session.user_id == user_id))
    await db.commit()
    return deleted_count


async def rotate_user_api_key(db: AsyncSession, user_id: str) -> Optional[User]:
    user = await get_user_by_id(db, user_id)
    if not user:
        return None
    user.api_key = await _generate_unique_api_key(db)
    await db.commit()
    await db.refresh(user)
    return user


async def touch_user_last_used(db: AsyncSession, user_id: str) -> None:
    user = await get_user_by_id(db, user_id)
    if user:
        user.last_used_at = datetime.utcnow()
        await db.commit()


# -- Sessions -----------------------------------------------------------------

async def create_session(
    db: AsyncSession,
    user_agent: str = None,
    extension_version: str = None,
    platform_hint: str = None,
    user_id: str = None,
) -> Session:
    session = Session(
        session_id=str(uuid.uuid4()),
        started_at=datetime.utcnow(),
        last_activity=datetime.utcnow(),
        user_agent=user_agent,
        extension_version=extension_version,
        platform_hint=platform_hint,
        user_id=user_id,
    )
    db.add(session)
    await db.commit()
    await db.refresh(session)
    return session


async def increment_session_allowed(db: AsyncSession, session_id: str) -> None:
    """Increment allowed_count and prompt_count on a session for ALLOWED actions
    (no PromptRecord is created for ALLOWED to preserve prompt privacy)."""
    session = await get_session_by_id(db, session_id)
    if session:
        session.prompt_count  = (session.prompt_count  or 0) + 1
        session.allowed_count = (session.allowed_count or 0) + 1
        session.last_activity = datetime.utcnow()
        await db.commit()


async def get_sessions(
    db: AsyncSession,
    page: int = 1,
    page_size: int = 20,
    platform: str = None,
    risk_level: str = None,
    date_from: str = None,
    date_to: str = None,
    user_id: str = None,
    since: str = None,
) -> tuple[list[dict], int]:
    query = select(Session).order_by(Session.last_activity.desc())
    count_query = select(func.count()).select_from(Session)

    if user_id is not None:
        # Include the user's own sessions AND unattributed sessions (created before
        # API keys were configured) so historical data is never hidden.
        from sqlalchemy import or_
        _uid_filter = or_(Session.user_id == user_id, Session.user_id == None)
        query       = query.where(_uid_filter)
        count_query = count_query.where(_uid_filter)

    if platform:
        query = query.where(Session.platform_hint == platform)
        count_query = count_query.where(Session.platform_hint == platform)

    if date_from:
        query = query.where(Session.started_at >= date_from)
        count_query = count_query.where(Session.started_at >= date_from)

    if date_to:
        query = query.where(Session.started_at <= date_to)
        count_query = count_query.where(Session.started_at <= date_to)

    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
            if since_dt.tzinfo is not None:
                since_dt = since_dt.replace(tzinfo=None)
            query = query.where(Session.last_activity >= since_dt)
            count_query = count_query.where(Session.last_activity >= since_dt)
        except (ValueError, TypeError):
            pass

    # risk_level filter joins to prompt records — skip if not provided
    if risk_level:
        from sqlalchemy import exists
        sub = select(PromptRecord.session_id).where(
            PromptRecord.risk_level == risk_level
        )
        query = query.where(Session.session_id.in_(sub))
        count_query = count_query.where(Session.session_id.in_(sub))

    total = (await db.execute(count_query)).scalar_one()
    offset = (page - 1) * page_size
    rows = (await db.execute(query.offset(offset).limit(page_size))).scalars().all()

    return [
        {
            "session_id":    s.session_id,
            "started_at":    _utc_iso(s.started_at),
            "last_activity": _utc_iso(s.last_activity),
            "prompt_count":  s.prompt_count or 0,
            "blocked_count": s.blocked_count or 0,
            "warned_count":  s.warned_count or 0,
            "allowed_count": s.allowed_count or 0,
            "platform":      s.platform_hint,
            "user_id":       s.user_id,
        }
        for s in rows
    ], total


async def get_session_by_id(db: AsyncSession, session_id: str) -> Optional[Session]:
    if not session_id:
        return None
    result = await db.execute(select(Session).where(Session.session_id == session_id))
    return result.scalar_one_or_none()


async def get_session_detail(db: AsyncSession, session_id: str) -> Optional[dict]:
    session = await get_session_by_id(db, session_id)
    if not session:
        return None
    prompts_orm = await get_prompts_for_session(db, session_id)
    prompts = []
    for p in prompts_orm:
        analysis = {}
        try:
            analysis = json.loads(p.analysis_result) if p.analysis_result else {}
        except Exception:
            pass
        in_browser = None
        try:
            in_browser = json.loads(p.in_browser_result) if p.in_browser_result else None
        except Exception:
            pass
        prompts.append({
            "prompt_id":         p.prompt_id,
            "session_id":        p.session_id,
            "timestamp":         _utc_iso(p.timestamp),
            "masked_text":       p.masked_text,
            "platform":          p.platform,
            "risk_score":        p.risk_score or 0,
            "risk_level":        p.risk_level or "SAFE",
            "action_taken":      p.action_taken or "ALLOWED",
            "pii_count":         p.pii_count or 0,
            "phi_count":         p.phi_count or 0,
            "code_threats":      p.code_threats or 0,
            "api_secrets_count": p.api_secrets_count or 0,
            "credentials_count": p.credentials_count or 0,
            "llm_intent":        p.llm_intent,
            "analysis":          analysis,
            "in_browser_result": in_browser,
        })
    return {
        "session_id":        session.session_id,
        "user_agent":        session.user_agent,
        "extension_version": session.extension_version,
        "platform_hint":     session.platform_hint,
        "started_at":        _utc_iso(session.started_at),
        "last_activity":     _utc_iso(session.last_activity),
        "prompt_count":      session.prompt_count or 0,
        "blocked_count":     session.blocked_count or 0,
        "warned_count":      session.warned_count or 0,
        "allowed_count":     session.allowed_count or 0,
        "prompts":           prompts,
    }


# -- Prompt Records -----------------------------------------------------------

async def create_prompt_record(
    db: AsyncSession,
    session_id: str,
    masked_text: str,
    platform: str,
    risk_score: int,
    risk_level: str,
    action_taken: str,
    analysis_result: dict,
    in_browser_result: dict = None,
    user_id: str = None,
    prompt_id: str = None,
) -> PromptRecord:
    analysis = analysis_result or {}
    pii     = analysis.get("pii") or {}
    phi     = analysis.get("phi") or {}
    code    = analysis.get("code_injection") or {}
    api_sec = analysis.get("api_secrets") or {}
    creds   = analysis.get("credentials") or {}
    llm     = analysis.get("llm_classification") or analysis.get("llm") or {}

    record = PromptRecord(
        prompt_id=prompt_id or str(uuid.uuid4()),
        session_id=session_id,
        user_id=user_id,
        timestamp=datetime.utcnow(),
        masked_text=masked_text,
        platform=platform,
        risk_score=risk_score,
        risk_level=risk_level,
        action_taken=action_taken,
        analysis_result=json.dumps(analysis_result) if isinstance(analysis_result, dict) else analysis_result,
        in_browser_result=json.dumps(in_browser_result) if isinstance(in_browser_result, dict) else in_browser_result,
        pii_count=pii.get("count", 0),
        phi_count=phi.get("count", 0),
        code_threats=code.get("count", code.get("threat_count", 0)),
        api_secrets_count=api_sec.get("count", 0),
        credentials_count=creds.get("count", 0),
        private_url_count=(analysis.get("private_url") or {}).get("count", 0),
        business_data_count=(analysis.get("business_data") or {}).get("count", 0),
        financial_data_count=(analysis.get("financial_data") or {}).get("count", 0),
        llm_intent=llm.get("Intent_Category") if llm.get("available") else None,
    )
    db.add(record)

    session = await get_session_by_id(db, session_id)
    if session:
        session.prompt_count  = (session.prompt_count  or 0) + 1
        session.last_activity = datetime.utcnow()
        if action_taken == "BLOCKED":
            session.blocked_count = (session.blocked_count or 0) + 1
        elif action_taken == "WARNED":
            session.warned_count  = (session.warned_count  or 0) + 1
        else:
            session.allowed_count = (session.allowed_count or 0) + 1

    await db.commit()
    await db.refresh(record)
    return record


async def get_prompt_record(
    db: AsyncSession, prompt_id: str, session_id: str = None
) -> Optional[PromptRecord]:
    stmt = select(PromptRecord).where(PromptRecord.prompt_id == prompt_id)
    if session_id:
        stmt = stmt.where(PromptRecord.session_id == session_id)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def get_prompts_for_session(
    db: AsyncSession, session_id: str
) -> list[PromptRecord]:
    result = await db.execute(
        select(PromptRecord)
        .where(PromptRecord.session_id == session_id)
        .order_by(PromptRecord.timestamp.desc())
    )
    return list(result.scalars().all())


# -- Statistics ---------------------------------------------------------------

async def get_stats(db: AsyncSession, user_id: str = None, since: str = None) -> dict:
    from datetime import datetime, timezone
    from sqlalchemy import or_

    # Parse optional `since` ISO timestamp (dashboard Clear View cutoff)
    since_dt = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
            if since_dt.tzinfo is not None:
                since_dt = since_dt.replace(tzinfo=None)  # DB stores naive UTC
        except (ValueError, TypeError):
            pass

    # --- Totals from Sessions (ALLOWED prompts are never stored as PromptRecords) ---
    sess_q = select(Session)
    if user_id is not None:
        # Include the user's own sessions AND unattributed ones (no API key set yet)
        _uid_filter = or_(Session.user_id == user_id, Session.user_id == None)
        sess_q = sess_q.where(_uid_filter)
    if since_dt is not None:
        sess_q = sess_q.where(Session.last_activity >= since_dt)

    sessions = (await db.execute(sess_q)).scalars().all()

    total_blocked = sum(s.blocked_count or 0 for s in sessions)
    total_warned  = sum(s.warned_count  or 0 for s in sessions)
    total_allowed = sum(s.allowed_count or 0 for s in sessions)
    total         = total_blocked + total_warned + total_allowed

    platform_breakdown: dict = {}
    for s in sessions:
        plat = s.platform_hint or "unknown"
        platform_breakdown[plat] = platform_breakdown.get(plat, 0) + (s.prompt_count or 0)

    # --- Risk distribution from PromptRecord (sessions don't carry risk_level) ---
    risk_q = select(PromptRecord.risk_level, func.count().label("cnt")).group_by(PromptRecord.risk_level)
    if user_id is not None:
        _uid_filter = or_(PromptRecord.user_id == user_id, PromptRecord.user_id == None)
        risk_q = risk_q.where(_uid_filter)
    if since_dt is not None:
        risk_q = risk_q.where(PromptRecord.timestamp >= since_dt)
    risk_rows = (await db.execute(risk_q)).all()

    return {
        "total_prompts":      total,
        "blocked":            total_blocked,
        "warned":             total_warned,
        "allowed":            total_allowed,
        "platform_breakdown": platform_breakdown,
        "risk_distribution":  {row.risk_level: row.cnt for row in risk_rows},
    }


async def get_admin_stats(db: AsyncSession) -> dict:
    """Per-user stats breakdown for admin overview.

    BLOCKED and WARNED counts come from PromptRecord (text is stored).
    ALLOWED counts come from Session.allowed_count (text is never stored for privacy).
    Total prompts = blocked + warned + allowed across all sessions.
    """
    users, _ = await list_users(db, page=1, page_size=1000)

    total_blocked_all = (await db.execute(
        select(func.count()).select_from(PromptRecord).where(PromptRecord.action_taken == "BLOCKED")
    )).scalar_one()
    total_warned_all = (await db.execute(
        select(func.count()).select_from(PromptRecord).where(PromptRecord.action_taken == "WARNED")
    )).scalar_one()
    total_allowed_all = (await db.execute(
        select(func.coalesce(func.sum(Session.allowed_count), 0)).select_from(Session)
        .where(Session.user_id.isnot(None))
    )).scalar_one()

    per_user = []
    for u in users:
        b = (await db.execute(
            select(func.count()).select_from(PromptRecord)
            .where(PromptRecord.user_id == u.user_id, PromptRecord.action_taken == "BLOCKED")
        )).scalar_one()
        w = (await db.execute(
            select(func.count()).select_from(PromptRecord)
            .where(PromptRecord.user_id == u.user_id, PromptRecord.action_taken == "WARNED")
        )).scalar_one()
        # ALLOWED prompts are never stored as PromptRecords — read from session counters
        al = (await db.execute(
            select(func.coalesce(func.sum(Session.allowed_count), 0)).select_from(Session)
            .where(Session.user_id == u.user_id)
        )).scalar_one()
        per_user.append({
            "user_id":     u.user_id,
            "name":        u.name,
            "company_id":  u.company_id,
            "email":       u.email,
            "blocked":     b,
            "warned":      w,
            "allowed":     al,
            "total":       b + w + al,
            "last_active": _utc_iso(u.last_used_at),
        })

    return {
        "total_users":   len(users),
        "total_prompts": total_blocked_all + total_warned_all + int(total_allowed_all),
        "blocked":       total_blocked_all,
        "warned":        total_warned_all,
        "allowed":       int(total_allowed_all),
        "per_user":      per_user,
    }


async def get_admin_sessions(
    db: AsyncSession,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[dict], int]:
    """All sessions with user info for admin view. Only sessions with a known user are returned."""
    query = select(Session).where(Session.user_id.isnot(None)).order_by(Session.last_activity.desc())
    count_query = select(func.count()).select_from(Session).where(Session.user_id.isnot(None))

    total = (await db.execute(count_query)).scalar_one()
    offset = (page - 1) * page_size
    rows = (await db.execute(query.offset(offset).limit(page_size))).scalars().all()

    result = []
    for s in rows:
        user_name = None
        user_email = None
        if s.user_id:
            user = await get_user_by_id(db, s.user_id)
            if user:
                user_name = user.name
                user_email = user.email
        result.append({
            "session_id":    s.session_id,
            "started_at":    _utc_iso(s.started_at),
            "last_activity": _utc_iso(s.last_activity),
            "prompt_count":  s.prompt_count or 0,
            "blocked_count": s.blocked_count or 0,
            "warned_count":  s.warned_count or 0,
            "allowed_count": s.allowed_count or 0,
            "platform":      s.platform_hint,
            "user_id":       s.user_id,
            "user_name":     user_name,
            "user_email":    user_email,
        })
    return result, total
