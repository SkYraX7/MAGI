"""API tests via FastAPI TestClient (no lifespan, Neo4j queries mocked).

TestClient is used WITHOUT the context-manager form so the lifespan (which needs a live
Neo4j/Redis) does not run; only the route logic is exercised.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from backend.auth import create_access_token
from backend.main import create_app

app = create_app()
client = TestClient(app)


def _auth(role: str = "admin") -> dict[str, str]:
    token = create_access_token(subject="admin", role=role)
    return {"Authorization": f"Bearer {token}"}


# --- auth ---
def test_login_bad_credentials_401():
    # Default settings have no admin hash -> authenticate fails.
    resp = client.post("/auth/token", json={"username": "admin", "password": "x"})
    assert resp.status_code == 401


def test_login_success_returns_token(monkeypatch):
    from backend.auth import User
    from backend.routers import auth as auth_router

    monkeypatch.setattr(
        auth_router, "authenticate", lambda u, p: User(username="admin", role="admin")
    )
    resp = client.post("/auth/token", json={"username": "admin", "password": "pw"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]


# --- auth guards ---
def test_graph_nodes_requires_auth():
    assert client.get("/graph/nodes").status_code == 401


def test_graph_nodes_with_token(monkeypatch):
    from backend.graph import queries

    monkeypatch.setattr(queries, "get_nodes", AsyncMock(return_value=[{"id": "h1", "label": "Host", "properties": {}}]))
    monkeypatch.setattr(queries, "count_nodes", AsyncMock(return_value=1))
    resp = client.get("/graph/nodes?type=Host&page=1&limit=10", headers=_auth())
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["nodes"][0]["id"] == "h1"


def test_graph_nodes_rejects_unknown_type(monkeypatch):
    resp = client.get("/graph/nodes?type=Bogus", headers=_auth())
    assert resp.status_code == 400


def test_graph_nodes_limit_cap_enforced():
    # limit > 500 fails query validation (422) before hitting the DB.
    resp = client.get("/graph/nodes?limit=999", headers=_auth())
    assert resp.status_code == 422


def test_campaigns_endpoint(monkeypatch):
    from backend.graph import queries

    monkeypatch.setattr(
        queries,
        "get_campaigns",
        AsyncMock(return_value=[{"name": "LockBit", "host_count": 2, "max_confidence": 0.9}]),
    )
    resp = client.get("/graph/campaigns", headers=_auth())
    assert resp.status_code == 200
    assert resp.json()["campaigns"][0]["name"] == "LockBit"


# --- RBAC on prune ---
def test_prune_requires_admin_role(monkeypatch):
    from backend.routers import graph as graph_router

    monkeypatch.setattr(graph_router, "run_prune_once", AsyncMock(return_value=[]))
    # viewer role -> 403
    assert client.delete("/graph/prune", headers=_auth(role="viewer")).status_code == 403


def test_prune_allows_admin(monkeypatch):
    from backend.routers import graph as graph_router

    monkeypatch.setattr(graph_router, "run_prune_once", AsyncMock(return_value=["e1"]))
    resp = client.delete("/graph/prune", headers=_auth(role="admin"))
    assert resp.status_code == 200
    assert resp.json()["removed_edge_ids"] == ["e1"]


# --- WebSocket handshake auth ---
def test_ws_rejects_without_token():
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/live-threats"):
            pass


def test_ws_rejects_bad_token():
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/live-threats?token=garbage"):
            pass
