"""DEMO_MODE telemetry seeder — dev only.

In the current single-host design the collectors and the backend are separate
processes with separate in-process queues, so a standalone collector does not feed the
running backend. For a self-contained end-to-end demo, this seeder runs *inside* the
backend process and injects synthetic telemetry onto the shared queue (so the real
ingest + broadcast path runs), plus a periodic simulated threat so an IP visibly turns
red and a Threat_Campaign lights up.

Enabled with ``DEMO_MODE=true``. Never enable in production.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import random
from datetime import datetime, timezone

from backend.graph.ingest import bridge_campaign, log_network_event, update_ip_enrichment
from backend.realtime import edge_add_msg, manager, node_add_msg, threat_flag_msg
from collectors.shared.queue import put_event
from collectors.shared.schema import UnifiedLogEvent

logger = logging.getLogger(__name__)

DEMO_HOSTS = ["web-prod-01", "db-prod-02", "workstation-07", "ci-runner-03"]
DEMO_PROCESSES = ["nginx", "python3", "chrome.exe", "svchost.exe", "sshd", "postgres"]
BENIGN_IPS = ["93.184.216.34", "140.82.121.4", "8.8.8.8", "151.101.1.69", "172.217.16.142"]
# Simulated-malicious IPs and the campaign each is attributed to.
THREAT_IPS = {
    "185.220.101.5": "LockBit",
    "45.137.21.9": "UNC2891",
    "193.106.191.21": "Feodo Tracker Botnet",
}


def _hash(name: str) -> str:
    return hashlib.sha256(name.encode()).hexdigest()


def _network_event(host: str, proc: str, ip: str, port: int) -> UnifiedLogEvent:
    return UnifiedLogEvent(
        timestamp=datetime.now(timezone.utc),
        platform=host,
        event_type="network",
        source_process=proc,
        process_hash=_hash(proc),
        pid=random.randint(100, 9999),
        direction="outbound",
        protocol="tcp",
        remote_ip=ip,
        remote_port=port,
    )


def benign_event(rng: random.Random) -> UnifiedLogEvent:
    """One synthetic benign connection (pure; unit-testable)."""
    return _network_event(
        host=rng.choice(DEMO_HOSTS),
        proc=rng.choice(DEMO_PROCESSES),
        ip=rng.choice(BENIGN_IPS),
        port=rng.choice([80, 443, 53, 5432, 22]),
    )


async def _emit_threat(rng: random.Random) -> None:
    """Ingest a connection to a 'bad' IP, then simulate the enrichment verdict + bridge."""
    host = rng.choice(DEMO_HOSTS)
    ip = rng.choice(list(THREAT_IPS))
    campaign = THREAT_IPS[ip]
    ts = datetime.now(timezone.utc)

    evt = _network_event(host, "svchost.exe", ip, 443)
    await log_network_event(evt)            # real graph write
    await manager.broadcast_event(evt)      # node_add/edge_add to the UI

    # Simulate the enrichment decision (no API keys / feed hit needed for the demo).
    await update_ip_enrichment(ip, enriched_at=ts, vt_score=9, country="RU", is_malicious=True)
    await bridge_campaign(ip, campaign=campaign, confidence=0.92, source_feed="demo", timestamp=ts)

    # Push the campaign node/edges + threat flag so the UI lights up live.
    await manager.broadcast(node_add_msg(ip, "IP_Address", {"address": ip, "is_malicious": True}))
    await manager.broadcast(node_add_msg(campaign, "Threat_Campaign", {"name": campaign}))
    await manager.broadcast(edge_add_msg(ip, campaign, "PART_OF_CAMPAIGN"))
    await manager.broadcast(edge_add_msg(campaign, host, "TARGETS"))
    await manager.broadcast(threat_flag_msg(ip, campaign, 0.92))
    logger.info("DEMO threat emitted: %s -> %s (%s)", host, ip, campaign)


async def run_demo_seeder(stop_event: asyncio.Event, interval: float = 2.0) -> None:
    """Inject benign telemetry every ``interval`` seconds; a threat every ~8th tick."""
    logger.warning("DEMO_MODE active — injecting synthetic telemetry (NOT for production)")
    rng = random.Random()
    tick = 0
    while not stop_event.is_set():
        try:
            await put_event(benign_event(rng))
            tick += 1
            if tick % 8 == 0:
                await _emit_threat(rng)
        except Exception:  # noqa: BLE001 - demo must never take the app down
            logger.exception("Demo seeder iteration failed")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass


__all__ = ["run_demo_seeder", "benign_event"]
