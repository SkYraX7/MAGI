"""Graph ingest — upsert :class:`UnifiedLogEvent`s into Neo4j.

Three public writers map onto the event types:

    log_network_event   network events   (Host)-[:RUNS]->(Process)-[:CONNECTED_TO]->(IP)
    log_process_event   process / image_load   parent -[:SPAWNED]-> child execution chains
    log_dns_event       dns events       (Process)-[:QUERIED]->(Domain)

:func:`log_event` dispatches by ``event_type``.

Invariants (CLAUDE.md Phase 2 critical rules):
  * ``MERGE`` everywhere — never bare ``CREATE`` — so re-ingesting identical events
    never duplicates nodes or relationships.
  * ``ON CREATE SET first_seen`` / ``ON MATCH SET last_seen`` on every node upsert.
  * Every value is passed as a query parameter; no f-string interpolation into Cypher.
  * Process hashes are lowercased (done in the schema model) before MERGE.

Processes without a binary hash (e.g. Sysmon ID 3 / syscall tracepoints carry none)
get a deterministic synthetic key ``synthetic:<name>@<host>`` so hashless processes on
a host collapse to one node instead of all merging on the empty string.
"""

from __future__ import annotations

import logging

from neo4j import AsyncManagedTransaction

from backend.graph.driver import run_write
from collectors.shared.schema import UnifiedLogEvent

logger = logging.getLogger(__name__)


def _process_key(event: UnifiedLogEvent) -> str:
    """Return the MERGE key for a Process node.

    Real SHA-256 when available; otherwise a deterministic synthetic key so hashless
    events for the same process name on the same host don't all collapse onto "".
    """
    if event.process_hash:
        return event.process_hash
    return f"synthetic:{event.source_process}@{event.platform}"


def _parent_key(event: UnifiedLogEvent) -> str:
    """MERGE key for the parent Process node (mirrors :func:`_process_key`)."""
    if event.parent_hash:
        return event.parent_hash
    return f"synthetic:{event.parent_process}@{event.platform}"


# --- Cypher (parameterized; relationship vars aliased so ON CREATE/MATCH can set props) ---

_NETWORK_CYPHER = """
MERGE (h:Host {name: $platform})
  ON CREATE SET h.first_seen = $timestamp
  ON MATCH  SET h.last_seen  = $timestamp

MERGE (p:Process {hash: $process_key})
  ON CREATE SET p.name = $source_process, p.first_seen = $timestamp, p.hashed = $has_hash,
                p.command_line = $command_line
  ON MATCH  SET p.last_seen = $timestamp,
                p.command_line = coalesce($command_line, p.command_line)

MERGE (ip:IP_Address {address: $remote_ip})
  ON CREATE SET ip.first_seen = $timestamp
  ON MATCH  SET ip.last_seen  = $timestamp

MERGE (h)-[runs:RUNS]->(p)
  ON CREATE SET runs.first_seen = $timestamp

MERGE (p)-[c:CONNECTED_TO {port: $remote_port, protocol: $protocol, direction: $direction}]->(ip)
  ON CREATE SET c.timestamp = $timestamp
  ON MATCH  SET c.timestamp = $timestamp
"""

_PROCESS_CYPHER = """
MERGE (h:Host {name: $platform})
  ON CREATE SET h.first_seen = $timestamp
  ON MATCH  SET h.last_seen  = $timestamp

MERGE (p:Process {hash: $process_key})
  ON CREATE SET p.name = $source_process, p.first_seen = $timestamp, p.hashed = $has_hash,
                p.command_line = $command_line
  ON MATCH  SET p.last_seen = $timestamp,
                p.command_line = coalesce($command_line, p.command_line)

MERGE (h)-[runs:RUNS]->(p)
  ON CREATE SET runs.first_seen = $timestamp
"""

# Appended to _PROCESS_CYPHER only when a parent is present.
_SPAWN_CYPHER = """
MERGE (parent:Process {hash: $parent_key})
  ON CREATE SET parent.name = $parent_process, parent.first_seen = $timestamp
  ON MATCH  SET parent.last_seen = $timestamp
MERGE (h)-[pruns:RUNS]->(parent)
  ON CREATE SET pruns.first_seen = $timestamp
MERGE (parent)-[sp:SPAWNED]->(p)
  ON CREATE SET sp.timestamp = $timestamp, sp.command_line = $command_line
  ON MATCH  SET sp.timestamp = $timestamp
"""

_DNS_CYPHER = """
MERGE (h:Host {name: $platform})
  ON CREATE SET h.first_seen = $timestamp
  ON MATCH  SET h.last_seen  = $timestamp

MERGE (p:Process {hash: $process_key})
  ON CREATE SET p.name = $source_process, p.first_seen = $timestamp, p.hashed = $has_hash,
                p.command_line = $command_line
  ON MATCH  SET p.last_seen = $timestamp,
                p.command_line = coalesce($command_line, p.command_line)

MERGE (h)-[runs:RUNS]->(p)
  ON CREATE SET runs.first_seen = $timestamp

MERGE (d:Domain {name: $queried_domain})
  ON CREATE SET d.first_seen = $timestamp
  ON MATCH  SET d.last_seen  = $timestamp

MERGE (p)-[q:QUERIED]->(d)
  ON CREATE SET q.timestamp = $timestamp
  ON MATCH  SET q.timestamp = $timestamp
"""


def _base_params(event: UnifiedLogEvent) -> dict:
    return {
        "platform": event.platform,
        "timestamp": event.timestamp,
        "source_process": event.source_process,
        "process_key": _process_key(event),
        "has_hash": bool(event.process_hash),
        "command_line": event.command_line,
    }


async def log_network_event(event: UnifiedLogEvent) -> None:
    """Upsert a network connection: Host runs Process, Process connected_to IP."""
    if not event.remote_ip:
        logger.warning("Skipping network event with no remote_ip from %s", event.platform)
        return
    params = _base_params(event)
    params.update(
        {
            "remote_ip": event.remote_ip,
            # MERGE keys can't be null; coerce a missing port to a stable sentinel.
            "remote_port": event.remote_port if event.remote_port is not None else 0,
            "protocol": event.protocol or "tcp",
            "direction": event.direction or "outbound",
        }
    )

    async def _work(tx: AsyncManagedTransaction) -> None:
        await tx.run(_NETWORK_CYPHER, **params)

    await run_write(_work)


async def log_process_event(event: UnifiedLogEvent) -> None:
    """Upsert a process execution (or image_load); link parent via SPAWNED when known."""
    params = _base_params(event)
    has_parent = bool(event.parent_process or event.parent_hash)
    cypher = _PROCESS_CYPHER + (_SPAWN_CYPHER if has_parent else "")
    if has_parent:
        params.update(
            {
                "parent_key": _parent_key(event),
                "parent_process": event.parent_process or "unknown",
            }
        )

    async def _work(tx: AsyncManagedTransaction) -> None:
        await tx.run(cypher, **params)

    await run_write(_work)


async def log_dns_event(event: UnifiedLogEvent) -> None:
    """Upsert a DNS query: Process queried Domain."""
    if not event.queried_domain:
        logger.warning("Skipping dns event with no queried_domain from %s", event.platform)
        return
    params = _base_params(event)
    # Domains are case-insensitive; normalize so MERGE doesn't make case-variant nodes.
    params["queried_domain"] = event.queried_domain.strip().lower()

    async def _work(tx: AsyncManagedTransaction) -> None:
        await tx.run(_DNS_CYPHER, **params)

    await run_write(_work)


# --------------------------------------------------------------------------- #
# Enrichment writers (Phase 3) — update IP nodes and bridge them to campaigns  #
# --------------------------------------------------------------------------- #

_IP_ENRICHMENT_CYPHER = """
MATCH (ip:IP_Address {address: $address})
SET ip.enriched_at = $enriched_at,
    ip.vt_score    = $vt_score,
    ip.censys_asn  = $censys_asn,
    ip.country     = $country,
    ip.is_malicious = $is_malicious
"""

# Bridge a malicious IP to its campaign, then connect the campaign to every host
# whose process has talked to that IP (PART_OF_CAMPAIGN + TARGETS in one tx).
_CAMPAIGN_BRIDGE_CYPHER = """
MERGE (c:Threat_Campaign {name: $campaign})
  ON CREATE SET c.first_seen = $timestamp, c.source_feed = $source_feed
  ON MATCH  SET c.source_feed = coalesce(c.source_feed, $source_feed)

WITH c
MATCH (ip:IP_Address {address: $address})
SET ip.is_malicious = true, ip.enriched_at = $timestamp

MERGE (ip)-[pc:PART_OF_CAMPAIGN]->(c)
  ON CREATE SET pc.confidence = $confidence, pc.source_feed = $source_feed
  ON MATCH  SET pc.confidence = $confidence

WITH c, ip
OPTIONAL MATCH (h:Host)-[:RUNS]->(:Process)-[:CONNECTED_TO]->(ip)
FOREACH (_ IN CASE WHEN h IS NULL THEN [] ELSE [1] END |
  MERGE (c)-[t:TARGETS]->(h)
    ON CREATE SET t.first_detected = $timestamp
)
"""


async def update_ip_enrichment(
    address: str,
    *,
    enriched_at,
    vt_score: int | None = None,
    censys_asn: int | None = None,
    country: str | None = None,
    is_malicious: bool = False,
) -> None:
    """Persist enrichment results onto an existing IP_Address node (best effort)."""
    params = {
        "address": address,
        "enriched_at": enriched_at,
        "vt_score": vt_score,
        "censys_asn": censys_asn,
        "country": country,
        "is_malicious": is_malicious,
    }

    async def _work(tx: AsyncManagedTransaction) -> None:
        await tx.run(_IP_ENRICHMENT_CYPHER, **params)

    await run_write(_work)


async def bridge_campaign(
    address: str,
    *,
    campaign: str,
    confidence: float,
    source_feed: str,
    timestamp,
) -> None:
    """Flag the IP malicious and bridge it to a Threat_Campaign + targeted Hosts.

    Satisfies the Phase 3 goal: a feed-flagged IP gets a Threat_Campaign node bridged
    to it (and to every host that has connected to it).
    """
    params = {
        "address": address,
        "campaign": campaign,
        "confidence": confidence,
        "source_feed": source_feed,
        "timestamp": timestamp,
    }

    async def _work(tx: AsyncManagedTransaction) -> None:
        await tx.run(_CAMPAIGN_BRIDGE_CYPHER, **params)

    await run_write(_work)


async def log_event(event: UnifiedLogEvent) -> None:
    """Dispatch an event to the appropriate writer by ``event_type``."""
    if event.event_type == "network":
        await log_network_event(event)
    elif event.event_type in ("process", "image_load"):
        # image_load has no dedicated relationship in the schema yet; record the
        # loading Process + Host RUNS edge so the node still appears in the graph.
        await log_process_event(event)
    elif event.event_type == "dns":
        await log_dns_event(event)
    else:  # pragma: no cover - Literal type makes this unreachable
        logger.warning("Unknown event_type %r; dropped", event.event_type)


__all__ = [
    "log_network_event",
    "log_process_event",
    "log_dns_event",
    "log_event",
    "update_ip_enrichment",
    "bridge_campaign",
]
