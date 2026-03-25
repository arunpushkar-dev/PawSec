"""WebSocket ConnectionManager + /ws/dashboard endpoint."""

import json
import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from database.db import AsyncSessionLocal
from database import crud

router = APIRouter()


class ConnectionManager:
    def __init__(self):
        self._connections: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        async with self._lock:
            self._connections.append(ws)

    async def disconnect(self, ws: WebSocket):
        async with self._lock:
            try:
                self._connections.remove(ws)
            except ValueError:
                pass

    async def broadcast(self, data: dict):
        """Send JSON to all connected dashboard clients. Dead connections are pruned."""
        message = json.dumps(data)
        dead: list[WebSocket] = []
        async with self._lock:
            targets = list(self._connections)
        for ws in targets:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    try:
                        self._connections.remove(ws)
                    except ValueError:
                        pass

    @property
    def active_count(self) -> int:
        return len(self._connections)


manager = ConnectionManager()


_LOCALHOST_IPS = frozenset({"127.0.0.1", "::1", "localhost"})


@router.websocket("/ws/dashboard")
async def ws_dashboard(websocket: WebSocket):
    # Validate API key via query param against users table
    token = websocket.query_params.get("token", "")
    client_ip = (websocket.client.host if websocket.client else "") or ""

    async with AsyncSessionLocal() as db:
        if token:
            user = await crud.get_user_by_api_key(db, token)
            if not user or not user.is_active:
                await websocket.close(code=4001)
                return
        elif client_ip in _LOCALHOST_IPS:
            # Localhost trusted bypass — no token required for admin dashboard
            user = await crud.get_first_admin(db)
            if not user:
                await websocket.close(code=4001)
                return
        else:
            await websocket.close(code=4001)
            return

    await manager.connect(websocket)
    try:
        # Send a ping every 30s to keep the connection alive
        while True:
            try:
                # Wait for client ping (or disconnect)
                await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
            except asyncio.TimeoutError:
                await websocket.send_text(json.dumps({"event": "ping"}))
    except WebSocketDisconnect:
        pass
    finally:
        await manager.disconnect(websocket)
