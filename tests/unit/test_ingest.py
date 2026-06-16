"""Unit tests for ingest parameter construction (Cypher executed against a fake tx).

These assert the *parameters* and that Cypher is parameterized (MERGE present, no
f-string interpolation), without needing a live Neo4j. Real graph behavior — dedup,
1000-event correctness — is covered by tests/integration.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from backend.graph import ingest
from collectors.shared.schema import UnifiedLogEvent


class FakeTx:
    """Captures the last Cypher query + params passed to ``tx.run``."""

    def __init__(self) -> None:
        self.query: str | None = None
        self.params: dict = {}

    async def run(self, query, **params):
        self.query = query
        self.params = params


@pytest.fixture
def captured_tx(monkeypatch):
    """Patch run_write to execute the work against a FakeTx and expose it."""
    tx = FakeTx()

    async def fake_run_write(work, **_kw):
        return await work(tx)

    monkeypatch.setattr(ingest, "run_write", fake_run_write)
    return tx


def test_process_key_uses_real_hash():
    evt = UnifiedLogEvent(
        timestamp=datetime.now(timezone.utc),
        platform="h1",
        event_type="process",
        source_process="cmd.exe",
        process_hash="ABC",
        pid=1,
    )
    assert ingest._process_key(evt) == "abc"


def test_process_key_synthetic_when_no_hash():
    evt = UnifiedLogEvent(
        timestamp=datetime.now(timezone.utc),
        platform="h1",
        event_type="network",
        source_process="nginx",
        process_hash="",
        pid=1,
        direction="outbound",
        remote_ip="1.2.3.4",
    )
    assert ingest._process_key(evt) == "synthetic:nginx@h1"


async def test_log_network_event_params(captured_tx):
    evt = UnifiedLogEvent(
        timestamp=datetime(2026, 6, 16, tzinfo=timezone.utc),
        platform="h1",
        event_type="network",
        source_process="nginx",
        process_hash="",
        pid=1,
        direction="outbound",
        protocol="tcp",
        remote_ip="185.220.101.5",
        remote_port=443,
    )
    await ingest.log_network_event(evt)
    assert "MERGE" in captured_tx.query
    assert "CONNECTED_TO" in captured_tx.query
    assert captured_tx.params["remote_ip"] == "185.220.101.5"
    assert captured_tx.params["remote_port"] == 443
    assert captured_tx.params["process_key"] == "synthetic:nginx@h1"
    assert captured_tx.params["timestamp"] == evt.timestamp


async def test_log_network_event_coerces_null_port(captured_tx):
    evt = UnifiedLogEvent(
        timestamp=datetime.now(timezone.utc),
        platform="h1",
        event_type="network",
        source_process="svc",
        pid=1,
        direction="outbound",
        remote_ip="1.2.3.4",
        remote_port=None,
    )
    await ingest.log_network_event(evt)
    assert captured_tx.params["remote_port"] == 0  # null coerced to stable sentinel


async def test_log_process_event_with_parent_includes_spawn(captured_tx):
    evt = UnifiedLogEvent(
        timestamp=datetime.now(timezone.utc),
        platform="h1",
        event_type="process",
        source_process="powershell.exe",
        process_hash="DEAD",
        pid=10,
        parent_process="explorer.exe",
    )
    await ingest.log_process_event(evt)
    assert "SPAWNED" in captured_tx.query
    assert captured_tx.params["parent_process"] == "explorer.exe"
    assert captured_tx.params["parent_key"] == "synthetic:explorer.exe@h1"


async def test_log_process_event_without_parent_omits_spawn(captured_tx):
    evt = UnifiedLogEvent(
        timestamp=datetime.now(timezone.utc),
        platform="h1",
        event_type="process",
        source_process="init",
        process_hash="BEEF",
        pid=1,
    )
    await ingest.log_process_event(evt)
    assert "SPAWNED" not in captured_tx.query


async def test_log_dns_event_lowercases_domain(captured_tx):
    evt = UnifiedLogEvent(
        timestamp=datetime.now(timezone.utc),
        platform="h1",
        event_type="dns",
        source_process="chrome.exe",
        pid=5,
        queried_domain="Evil.Example.COM",
    )
    await ingest.log_dns_event(evt)
    assert "QUERIED" in captured_tx.query
    assert captured_tx.params["queried_domain"] == "evil.example.com"


async def test_log_event_dispatches_by_type(captured_tx):
    evt = UnifiedLogEvent(
        timestamp=datetime.now(timezone.utc),
        platform="h1",
        event_type="image_load",
        source_process="rundll32.exe",
        process_hash="CAFE",
        pid=7,
    )
    await ingest.log_event(evt)
    # image_load routes through the process writer (RUNS edge, no CONNECTED_TO).
    assert "RUNS" in captured_tx.query
    assert "CONNECTED_TO" not in captured_tx.query
