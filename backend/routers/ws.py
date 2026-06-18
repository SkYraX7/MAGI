"""WebSocket router — /ws/live-threats.

The token is validated on the handshake (query param), not per-message: an
unauthenticated socket is closed immediately (CLAUDE.md security checklist). On connect
the server replays the current graph so a reconnecting client rebuilds state without a
wipe. Thereafter the client only sends keepalive pings; all graph updates are pushed.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from backend.auth import verify_ws_token
from backend.graph.queries import get_full_graph
from backend.realtime import edge_add_msg, manager, node_add_msg

logger = logging.getLogger(__name__)

router = APIRouter()


@router.websocket("/ws/live-threats")
async def live_threats(websocket: WebSocket, token: str = Query(default="")) -> None:
    # Authenticate on handshake; close policy-violation (1008) if invalid.
    if verify_ws_token(token) is None:
        await websocket.close(code=1008)
        return

    session_id = await manager.connect(websocket)
    try:
        await _replay_current_graph(session_id)
        while True:
            message = await websocket.receive_json()
            if message.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        pass
    except Exception as exc:  # noqa: BLE001 - malformed client frame etc.
        logger.debug("WS session %s ended: %s", session_id, exc)
    finally:
        await manager.disconnect(session_id)


async def _replay_current_graph(session_id: str) -> None:
    """Send the current nodes/edges so a (re)connecting client rebuilds its graph."""
    graph = await get_full_graph()
    replay: list[dict] = [
        node_add_msg(n["id"], n["label"], n["properties"]) for n in graph["nodes"]
    ]
    replay += [edge_add_msg(e["source"], e["target"], e["rel"]) for e in graph["edges"]]
    await manager.send_messages(session_id, replay)
