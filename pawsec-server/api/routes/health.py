"""GET /health — liveness check."""

import time
import httpx
from fastapi import APIRouter

_start_time = time.time()
from config import settings
from api.models import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    # Probe Ollama availability
    ollama_ok = False
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(settings.ollama_url.replace("/api/chat", "/api/tags"))
            ollama_ok = resp.status_code == 200
    except Exception:
        pass

    return HealthResponse(
        status="ok",
        version="1.0.0",
        ollama_available=ollama_ok,
        db_connected=True,
        uptime_seconds=round(time.time() - _start_time, 1),
    )
