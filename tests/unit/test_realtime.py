"""Unit tests for the realtime layer — message builders, event mapping, broadcast."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from backend import realtime
from backend.realtime import (
    ConnectionManager,
    edge_add_msg,
    event_to_messages,
    node_add_msg,
    prune_msg,
    threat_flag_msg,
)
from collectors.shared.schema import UnifiedLogEvent


@pytest.fixture(autouse=True)
def _fake_redis(monkeypatch):
    # ConnectionManager touches Redis for ws:sessions bookkeeping; stub it out.
    monkeypatch.setattr(realtime, "get_redis", lambda: AsyncMock())


def test_message_builders_shape():
    assert node_add_msg("h1", "Host", {"name": "h1"}) == {
        "type": "node_add",
        "data": {"id": "h1", "label": "Host", "properties": {"name": "h1"}},
    }
    assert edge_add_msg("a", "b", "RUNS")["type"] == "edge_add"
    assert threat_flag_msg("1.2.3.4", "LockBit", 0.9)["data"]["confidence"] == 0.9
    assert prune_msg(["x"]) == {"type": "prune", "data": {"removed_edge_ids": ["x"]}}


def test_event_to_messages_network():
    evt = UnifiedLogEvent(
        timestamp=datetime.now(timezone.utc),
        platform="h1",
        event_type="network",
        source_process="nginx",
        process_hash="",
        pid=1,
        direction="outbound",
        remote_ip="1.2.3.4",
        remote_port=443,
    )
    msgs = event_to_messages(evt)
    types = [(m["type"], m["data"].get("rel") or m["data"].get("label")) for m in msgs]
    assert ("node_add", "Host") in types
    assert ("node_add", "IP_Address") in types
    assert ("edge_add", "CONNECTED_TO") in types
    # Process id is the synthetic key (hashless), and the IP edge points to it.
    ip_edge = next(m for m in msgs if m["data"].get("rel") == "CONNECTED_TO")
    assert ip_edge["data"]["source"] == "synthetic:nginx@h1"
    assert ip_edge["data"]["target"] == "1.2.3.4"


def test_event_to_messages_dns():
    evt = UnifiedLogEvent(
        timestamp=datetime.now(timezone.utc),
        platform="h1",
        event_type="dns",
        source_process="chrome.exe",
        pid=1,
        queried_domain="Evil.COM",
    )
    msgs = event_to_messages(evt)
    domain_node = next(m for m in msgs if m["data"].get("label") == "Domain")
    assert domain_node["data"]["id"] == "evil.com"  # normalized lowercase
    assert any(m["data"].get("rel") == "QUERIED" for m in msgs)


def test_event_to_messages_process_spawn():
    evt = UnifiedLogEvent(
        timestamp=datetime.now(timezone.utc),
        platform="h1",
        event_type="process",
        source_process="powershell.exe",
        process_hash="dead",
        pid=1,
        parent_process="explorer.exe",
    )
    msgs = event_to_messages(evt)
    assert any(m["data"].get("rel") == "SPAWNED" for m in msgs)


async def test_broadcast_sends_to_all_and_drops_dead():
    cm = ConnectionManager()
    good = AsyncMock()
    dead = AsyncMock()
    dead.send_json.side_effect = RuntimeError("client gone")
    cm._connections = {"good": good, "dead": dead}

    await cm.broadcast({"type": "ping"})

    good.send_json.assert_awaited_once_with({"type": "ping"})
    # The failing socket is dropped from the registry.
    assert "dead" not in cm._connections
    assert "good" in cm._connections


async def test_broadcast_event_emits_node_and_edge_messages():
    cm = ConnectionManager()
    ws = AsyncMock()
    cm._connections = {"s": ws}
    evt = UnifiedLogEvent(
        timestamp=datetime.now(timezone.utc),
        platform="h1",
        event_type="network",
        source_process="svc",
        pid=1,
        direction="outbound",
        remote_ip="9.9.9.9",
        remote_port=53,
    )
    await cm.broadcast_event(evt)
    assert ws.send_json.await_count >= 4  # host, process, ip nodes + runs/connected edges
