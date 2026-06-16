"""Integration tests — require a live Neo4j (docker-compose.test.yml).

Verifies the Phase 2 acceptance goal: re-ingesting identical events produces no
duplicate nodes, and feeding a batch yields the expected node/relationship counts.

Run with:  docker compose -f docker-compose.test.yml up -d  &&  pytest -m integration
Skipped automatically when Neo4j is not reachable so the unit suite stays green offline.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from backend.graph import schema
from backend.graph.driver import close_driver, run_read, run_write, verify_connectivity
from backend.graph.ingest import log_network_event, log_process_event
from collectors.shared.schema import UnifiedLogEvent

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
async def neo4j():
    try:
        await verify_connectivity(retries=1, base_delay=0.2)
    except Exception:  # noqa: BLE001
        pytest.skip("Neo4j not reachable; skipping integration tests")
    await schema.initialize_schema()
    yield
    await close_driver()


async def _wipe():
    async def _work(tx):
        await tx.run("MATCH (n) DETACH DELETE n")

    await run_write(_work)


async def _count_label(label: str) -> int:
    async def _work(tx):
        result = await tx.run(f"MATCH (n:{label}) RETURN count(n) AS c")
        record = await result.single()
        return record["c"]

    return await run_read(_work)


def _net_event(**overrides) -> UnifiedLogEvent:
    base = dict(
        timestamp=datetime(2026, 6, 16, 4, 45, tzinfo=timezone.utc),
        platform="host-int-01",
        event_type="network",
        source_process="nginx",
        process_hash="a" * 64,
        pid=100,
        direction="outbound",
        protocol="tcp",
        remote_ip="185.220.101.5",
        remote_port=443,
    )
    base.update(overrides)
    return UnifiedLogEvent(**base)


async def test_duplicate_network_event_creates_one_of_each(neo4j):
    await _wipe()
    evt = _net_event()
    await log_network_event(evt)
    await log_network_event(evt)  # identical — must not duplicate

    assert await _count_label("Host") == 1
    assert await _count_label("Process") == 1
    assert await _count_label("IP_Address") == 1


async def test_thousand_events_no_duplicate_nodes(neo4j):
    await _wipe()
    base = datetime(2026, 6, 16, tzinfo=timezone.utc)
    # 1000 connects from the same process to 5 distinct IPs.
    for i in range(1000):
        await log_network_event(
            _net_event(
                timestamp=base + timedelta(seconds=i),
                remote_ip=f"185.220.101.{i % 5}",
            )
        )

    assert await _count_label("Host") == 1
    assert await _count_label("Process") == 1
    assert await _count_label("IP_Address") == 5


async def test_spawn_chain_links_parent_and_child(neo4j):
    await _wipe()
    await log_process_event(
        UnifiedLogEvent(
            timestamp=datetime.now(timezone.utc),
            platform="host-int-01",
            event_type="process",
            source_process="powershell.exe",
            process_hash="b" * 64,
            pid=200,
            parent_process="explorer.exe",
            parent_hash="c" * 64,
        )
    )

    async def _work(tx):
        result = await tx.run(
            "MATCH (:Process)-[s:SPAWNED]->(:Process) RETURN count(s) AS c"
        )
        record = await result.single()
        return record["c"]

    assert await run_read(_work) == 1
