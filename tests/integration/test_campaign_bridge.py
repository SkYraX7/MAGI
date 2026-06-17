"""Integration test — Phase 3 goal: a flagged IP is bridged to a Threat_Campaign.

Requires a live Neo4j (docker-compose.test.yml); auto-skips when unreachable.
Verifies the campaign Cypher end to end: after ingesting a network event and bridging
the IP to a campaign, the Threat_Campaign node exists, PART_OF_CAMPAIGN links the IP,
and the campaign TARGETS the originating host.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from backend.graph import schema
from backend.graph.driver import close_driver, run_read, run_write, verify_connectivity
from backend.graph.ingest import bridge_campaign, log_network_event
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


async def test_feed_flagged_ip_bridges_campaign(neo4j):
    await _wipe()
    ts = datetime(2026, 6, 16, 4, 45, tzinfo=timezone.utc)
    ip = "185.220.101.5"

    # 1. A host's process connects to the IP (Phase 2 ingest).
    await log_network_event(
        UnifiedLogEvent(
            timestamp=ts,
            platform="victim-host",
            event_type="network",
            source_process="svchost.exe",
            process_hash="d" * 64,
            pid=1000,
            direction="outbound",
            remote_ip=ip,
            remote_port=443,
        )
    )

    # 2. Enrichment flags it (Phase 3 bridge).
    await bridge_campaign(
        ip,
        campaign="Feodo Tracker Botnet",
        confidence=0.4,
        source_feed="feodo",
        timestamp=ts,
    )

    # 3. Verify the campaign node, the PART_OF_CAMPAIGN edge, the malicious flag,
    #    and the TARGETS edge to the host.
    async def _check(tx):
        result = await tx.run(
            """
            MATCH (ip:IP_Address {address: $ip})-[pc:PART_OF_CAMPAIGN]->(c:Threat_Campaign)
            OPTIONAL MATCH (c)-[:TARGETS]->(h:Host)
            RETURN c.name AS campaign, ip.is_malicious AS malicious,
                   pc.confidence AS confidence, collect(h.name) AS hosts
            """,
            ip=ip,
        )
        return await result.single()

    record = await run_read(_check)
    assert record is not None
    assert record["campaign"] == "Feodo Tracker Botnet"
    assert record["malicious"] is True
    assert record["confidence"] == pytest.approx(0.4)
    assert "victim-host" in record["hosts"]
