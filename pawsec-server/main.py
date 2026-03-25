"""PawSec Server — FastAPI application entry point."""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from config import settings
from database.db import init_db, AsyncSessionLocal, engine
from database import crud
from api.routes import analyze, sessions, stats, health
from api.routes.admin import router as admin_router
from api.websocket import router as ws_router

logger = logging.getLogger("pawsec")


async def _run_migrations():
    """Add new columns to existing tables if they don't exist yet (SQLite ALTER TABLE)."""
    from sqlalchemy import text
    async with engine.begin() as conn:
        # sessions.user_id
        try:
            await conn.execute(text(
                "ALTER TABLE sessions ADD COLUMN user_id VARCHAR(36) REFERENCES users(user_id)"
            ))
            logger.info("Migration: added sessions.user_id")
        except Exception:
            pass  # Column already exists

        # prompt_records.user_id
        try:
            await conn.execute(text(
                "ALTER TABLE prompt_records ADD COLUMN user_id VARCHAR(36) REFERENCES users(user_id)"
            ))
            logger.info("Migration: added prompt_records.user_id")
        except Exception:
            pass  # Column already exists


async def _bootstrap_admin():
    """On first run, create the admin user from config if no users exist."""
    async with AsyncSessionLocal() as db:
        count = await crud.count_users(db)
        if count == 0:
            admin = await crud.create_user(
                db,
                name="Administrator",
                email=settings.admin_email,
                company_id="ADMIN",
                is_admin=True,
                api_key=settings.pawsec_api_key,
            )
            print("=" * 60)
            print("PawSec Bootstrap: Admin user created.")
            print(f"  Email:   {admin.email}")
            print(f"  API Key: {admin.api_key}")
            print("  Store this key securely — it won't be shown again.")
            print("=" * 60)
        else:
            logger.info(f"Bootstrap skipped — {count} user(s) already exist.")


async def _check_ollama():
    """Verify Ollama is reachable at startup. Log a prominent warning if not."""
    import httpx
    # Derive base URL from the configured chat endpoint (strip path)
    raw = getattr(settings, 'ollama_url', 'http://localhost:11434')
    from urllib.parse import urlparse
    parsed = urlparse(raw)
    ollama_base = f"{parsed.scheme}://{parsed.netloc}"
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(f"{ollama_base}/api/tags")
            if r.status_code == 200:
                models = [m['name'] for m in r.json().get('models', [])]
                print(f"Ollama OK — models: {models}")
            else:
                logger.warning(f"Ollama returned HTTP {r.status_code}. LLM classification will be unavailable.")
    except Exception as e:
        print("=" * 60)
        print("WARNING: Ollama is NOT running or unreachable.")
        print(f"   URL tried: {ollama_base}")
        print(f"   Error:     {e}")
        print("   LLM-based threat classification will be DISABLED.")
        print("   Start Ollama with:  ollama serve")
        print("   Then restart this server.")
        print("=" * 60)


async def _purge_orphan_sessions():
    """Delete sessions and prompt records that have no user_id associated."""
    from sqlalchemy import delete as sql_delete, text
    async with AsyncSessionLocal() as db:
        # Count before purge for logging
        result = await db.execute(
            text("SELECT COUNT(*) FROM sessions WHERE user_id IS NULL")
        )
        orphan_count = result.scalar_one()
        if orphan_count > 0:
            # Delete prompt records belonging to orphan sessions first (FK constraint)
            await db.execute(text(
                "DELETE FROM prompt_records WHERE session_id IN "
                "(SELECT session_id FROM sessions WHERE user_id IS NULL)"
            ))
            await db.execute(text("DELETE FROM sessions WHERE user_id IS NULL"))
            await db.commit()
            logger.info(f"Purged {orphan_count} orphan session(s) with no user association.")
        else:
            logger.info("No orphan sessions found.")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await _run_migrations()
    await _bootstrap_admin()
    await _purge_orphan_sessions()
    await _check_ollama()
    yield


app = FastAPI(
    title="PawSec Server",
    description="Enterprise prompt security analysis pipeline",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS — allow the browser extension and dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API routes
app.include_router(health.router)
app.include_router(analyze.router)
app.include_router(sessions.router)
app.include_router(stats.router)
app.include_router(admin_router)
app.include_router(ws_router)

# Serve admin dashboard SPA at /dashboard/admin
_admin_dashboard_dir = Path(__file__).parent / "dashboard" / "admin"
if _admin_dashboard_dir.exists():
    app.mount("/dashboard/admin", StaticFiles(directory=str(_admin_dashboard_dir), html=True), name="admin-dashboard")

# Serve user dashboard SPA at /dashboard
_dashboard_dir = Path(__file__).parent / "dashboard"
if _dashboard_dir.exists():
    app.mount("/dashboard", StaticFiles(directory=str(_dashboard_dir), html=True), name="dashboard")


@app.get("/", include_in_schema=False)
async def root():
    return {
        "service": "PawSec Server",
        "version": "1.0.0",
        "dashboard": "/dashboard",
        "admin": "/dashboard/admin",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=False,
        log_level="info",
    )
