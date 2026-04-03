"""POST /api/v1/analyze - full 10-skill deep analysis pipeline."""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import require_api_key
from api.models import AnalyzeRequest, AnalyzeResponse
from api.websocket import manager
from database.db import get_db
from database import crud
from database.models import User
from analyzers.analyzer_runner import run_analysis

router = APIRouter(dependencies=[Depends(require_api_key)])


def _determine_action(_risk_level: str, risk_score: int) -> str:
    # Thresholds match the extension defaults (block_threshold=70, warn_threshold=30).
    # risk_level is NOT used here because HIGH maps to score 50-69 which should be
    # WARNED, not BLOCKED — using risk_level caused warned prompts to appear blocked.
    if risk_score >= 70:
        return "BLOCKED"
    if risk_score >= 30:
        return "WARNED"
    return "ALLOWED"


@router.post("/api/v1/analyze", response_model=AnalyzeResponse, tags=["Analysis"])
async def analyze_prompt(
    body: AnalyzeRequest,
    current_user: User = Depends(require_api_key),
    db: AsyncSession = Depends(get_db),
):
    prompt_id = f"prt_{uuid.uuid4().hex[:16]}"
    now = datetime.now(timezone.utc)

    analysis = await run_analysis(
        text=body.prompt_text,
        analyzers_requested=body.analyzers_requested,
    )

    risk = analysis.get("risk", {})
    risk_score: int = risk.get("effective_score", risk.get("total_score", 0))
    risk_level: str = risk.get("risk_level", "SAFE")

    # If the client (extension) detected a higher risk than the server's analysis
    # (e.g. because the prompt text was sent as '[REDACTED]' for privacy), trust
    # the client's in-browser assessment and use whichever score is higher.
    if body.in_browser_result:
        client_score = body.in_browser_result.risk_score or 0
        client_level = body.in_browser_result.risk_level or "SAFE"
        if client_score > risk_score:
            risk_score = client_score
            risk_level = client_level

    action = _determine_action(risk_level, risk_score)  # risk_level kept for call-site clarity

    # LLM pre-check calls send only ['llm','risk'] — they are fast-path lookups
    # used by the extension to get Ollama's semantic verdict before the user's
    # prompt is submitted.  The full PAWSEC_ANALYSIS submission (all analyzers)
    # follows immediately after and is the canonical record to persist.
    # Storing both would create a duplicate entry in the dashboard.
    _llm_precheck = set(body.analyzers_requested) <= {"llm", "risk"}

    # Always get or create the session so counters stay accurate for every action.
    session = await crud.get_session_by_id(db, body.session_id or "")
    if not session:
        session = await crud.create_session(
            db,
            user_agent=body.user_agent,
            extension_version=body.extension_version,
            platform_hint=body.platform,
            user_id=current_user.user_id,
        )

    if action in ("BLOCKED", "WARNED") and not _llm_precheck:
        # Only persist prompt text for risky prompts (privacy: ALLOWED text never stored).
        # Skip storage for LLM pre-check calls — the full analysis submission persists the record.
        pii_result = analysis.get("pii", {})
        masked = pii_result.get("masked_text") or body.prompt_text[:4000]

        await crud.create_prompt_record(
            db,
            session_id=session.session_id,
            masked_text=masked,
            platform=body.platform,
            risk_score=risk_score,
            risk_level=risk_level,
            action_taken=action,
            analysis_result=analysis,
            in_browser_result=body.in_browser_result.model_dump() if body.in_browser_result else None,
            user_id=current_user.user_id,
            prompt_id=prompt_id,
        )
    else:
        # ALLOWED (or LLM pre-check): update session counters without storing prompt text.
        await crud.increment_session_allowed(db, session.session_id)

    await manager.broadcast({
        "event": "new_prompt",
        "prompt_id": prompt_id,
        "session_id": session.session_id,
        "platform": body.platform,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "action_taken": action,
        "timestamp": now.isoformat(),
        "user_id": current_user.user_id,
        "user_name": current_user.name,
    })

    return AnalyzeResponse(
        prompt_id=prompt_id,
        session_id=body.session_id,
        timestamp=now,
        action_taken=action,
        risk_score=risk_score,
        risk_level=risk_level,
        analysis=analysis,
        recommendations=risk.get("recommendations", []),
    )
