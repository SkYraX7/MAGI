"""Real-time WebSocket fan-out.

A single in-process :class:`ConnectionManager` holds ``{session_id: WebSocket}`` and
broadcasts graph updates to every connected client. Session ids are also tracked in the
Redis ``ws:sessions`` set — unused by the single-process send path, but the seam that
makes horizontal scaling (Redis Pub/Sub) a drop-in later (CLAUDE.md Phase 4/5).

Message shapes match the WS contract: ``node_add`` / ``edge_add`` / ``threat_flag`` /
``prune``. :func:`event_to_messages` turns one ``UnifiedLogEvent`` into the node/edge
adds it implies, reusing the ingest key helpers so ids line up with replay-on-reconnect.
"""

from __future__ import annotations

import logging
from typing import Any, Optional
from uuid import uuid4

from fastapi import WebSocket

from backend.cache.redis import get_redis
from backend.graph.ingest import _parent_key, _process_key
from collectors.shared.schema import UnifiedLogEvent

logger = logging.getLogger(__name__)

WS_SESSIONS_KEY = "ws:sessions"


# --- message builders (the server -> client contract) ---
def node_add_msg(node_id: str, label: str, properties: dict[str, Any]) -> dict:
    return {"type": "node_add", "data": {"id": node_id, "label": label, "properties": properties}}


def edge_add_msg(source: str, target: str, rel: str) -> dict:
    return {"type": "edge_add", "data": {"source": source, "target": target, "rel": rel}}


def threat_flag_msg(node_id: str, campaign: str, confidence: float) -> dict:
    return {
        "type": "threat_flag",
        "data": {"node_id": node_id, "campaign": campaign, "confidence": confidence},
    }


def prune_msg(removed_edge_ids: list[str]) -> dict:
    return {"type": "prune", "data": {"removed_edge_ids": removed_edge_ids}}


def event_to_messages(event: UnifiedLogEvent) -> list[dict]:
    """Translate an ingested event into the node_add/edge_add messages it implies.

    Ids use the same keys ingest MERGEs on, so a node added live matches the same node
    replayed on reconnect; the frontend treats node_add as idempotent (keyed by id).
    """
    host = event.platform
    pkey = _process_key(event)
    msgs: list[dict] = [
        node_add_msg(host, "Host", {"name": host}),
        node_add_msg(pkey, "Process", {"name": event.source_process, "hash": pkey}),
        edge_add_msg(host, pkey, "RUNS"),
    ]
    if event.event_type == "network" and event.remote_ip:
        msgs.append(node_add_msg(event.remote_ip, "IP_Address", {"address": event.remote_ip}))
        msgs.append(edge_add_msg(pkey, event.remote_ip, "CONNECTED_TO"))
    elif event.event_type == "dns" and event.queried_domain:
        domain = event.queried_domain.strip().lower()
        msgs.append(node_add_msg(domain, "Domain", {"name": domain}))
        msgs.append(edge_add_msg(pkey, domain, "QUERIED"))
    elif event.event_type in ("process", "image_load") and (
        event.parent_process or event.parent_hash
    ):
        ppkey = _parent_key(event)
        msgs.append(
            node_add_msg(ppkey, "Process", {"name": event.parent_process or "unknown", "hash": ppkey})
        )
        msgs.append(edge_add_msg(host, ppkey, "RUNS"))
        msgs.append(edge_add_msg(ppkey, pkey, "SPAWNED"))
    return msgs


class ConnectionManager:
    """Tracks live WebSocket clients and fans messages out to all of them."""

    def __init__(self) -> None:
        self._connections: dict[str, WebSocket] = {}

    @property
    def count(self) -> int:
        return len(self._connections)

    async def connect(self, websocket: WebSocket) -> str:
        """Accept a socket, register it, and return its session id."""
        await websocket.accept()
        session_id = uuid4().hex
        self._connections[session_id] = websocket
        try:
            await get_redis().sadd(WS_SESSIONS_KEY, session_id)
        except Exception as exc:  # noqa: BLE001 - Redis is non-critical for the send path
            logger.debug("Could not record ws session in Redis: %s", exc)
        logger.info("WS client connected (%s); %d active", session_id, self.count)
        return session_id

    async def disconnect(self, session_id: str) -> None:
        self._connections.pop(session_id, None)
        try:
            await get_redis().srem(WS_SESSIONS_KEY, session_id)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Could not remove ws session from Redis: %s", exc)
        logger.info("WS client disconnected (%s); %d active", session_id, self.count)

    async def send_messages(self, session_id: str, messages: list[dict]) -> None:
        """Send a batch of messages to one client (used for replay-on-connect)."""
        ws = self._connections.get(session_id)
        if ws is None:
            return
        for message in messages:
            await ws.send_json(message)

    async def broadcast(self, message: dict) -> None:
        """Send one message to every connected client; drop any that error."""
        dead: list[str] = []
        for session_id, ws in list(self._connections.items()):
            try:
                await ws.send_json(message)
            except Exception:  # noqa: BLE001 - client vanished mid-send
                dead.append(session_id)
        for session_id in dead:
            await self.disconnect(session_id)

    async def broadcast_event(self, event: UnifiedLogEvent) -> None:
        """Broadcast the node/edge adds implied by a freshly ingested event."""
        for message in event_to_messages(event):
            await self.broadcast(message)

    async def drain(self) -> None:
        """Close all sockets on shutdown so clients reconnect cleanly."""
        for session_id, ws in list(self._connections.items()):
            try:
                await ws.close()
            except Exception:  # noqa: BLE001
                pass
            self._connections.pop(session_id, None)
        try:
            await get_redis().delete(WS_SESSIONS_KEY)
        except Exception:  # noqa: BLE001
            pass


# Process-wide singleton — imported by the pipeline (broadcast) and the WS router.
manager = ConnectionManager()


__all__ = [
    "ConnectionManager",
    "manager",
    "node_add_msg",
    "edge_add_msg",
    "threat_flag_msg",
    "prune_msg",
    "event_to_messages",
    "WS_SESSIONS_KEY",
]
