"""Graph pruning — age out stale benign edges so Neo4j memory stays bounded.

Runs on an interval (``PRUNE_INTERVAL_SECONDS``) via APScheduler. We use the
``AsyncIOScheduler`` (not the ``BlockingScheduler`` the spec sketches) because the
backend is fully async — the job shares the app's event loop and the async Neo4j
driver, rather than marshalling across a thread boundary.

Never pruned (CLAUDE.md): Threat_Campaign nodes, anything ``is_malicious = true``, and
anything with a path to a campaign. After a pass, removed edge ids are pushed to WS
clients so the frontend drops the stale links.
"""

from __future__ import annotations

import logging
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from backend.config import get_settings
from backend.graph.driver import run_write
from backend.realtime import manager, prune_msg

logger = logging.getLogger(__name__)

# Delete stale benign CONNECTED_TO edges. The edge id mirrors the frontend's link key
# (source|target|rel) so clients can remove exactly these links on the prune message.
_PRUNE_EDGES_CYPHER = """
MATCH (p:Process)-[r:CONNECTED_TO]->(ip:IP_Address)
WHERE r.timestamp < datetime() - duration({hours: $hours})
  AND NOT (ip)-[:PART_OF_CAMPAIGN]->()
  AND (ip.is_malicious IS NULL OR ip.is_malicious = false)
WITH r, p.hash + '|' + ip.address + '|CONNECTED_TO' AS rid
DELETE r
RETURN collect(rid) AS removed
"""

# Remove Process nodes left with no relationships after edge pruning.
_PRUNE_ORPHANS_CYPHER = """
MATCH (p:Process)
WHERE NOT (p)--()
DELETE p
"""

_scheduler: Optional[AsyncIOScheduler] = None


async def run_prune_once() -> list[str]:
    """Run a single pruning pass; returns the ids of removed edges (and broadcasts them)."""
    settings = get_settings()

    async def _prune_edges(tx) -> list[str]:
        result = await tx.run(_PRUNE_EDGES_CYPHER, hours=settings.prune_stale_after_hours)
        record = await result.single()
        return record["removed"] if record and record["removed"] else []

    removed = await run_write(_prune_edges)

    async def _prune_orphans(tx) -> None:
        await tx.run(_PRUNE_ORPHANS_CYPHER)

    await run_write(_prune_orphans)

    if removed:
        logger.info("Pruned %d stale benign edges", len(removed))
        await manager.broadcast(prune_msg(removed))
    return removed


def start_pruning() -> None:
    """Schedule the recurring prune job on the running event loop."""
    global _scheduler
    if _scheduler is not None:
        return
    settings = get_settings()
    _scheduler = AsyncIOScheduler()
    _scheduler.add_job(
        run_prune_once,
        "interval",
        seconds=settings.prune_interval_seconds,
        id="prune_stale_edges",
        max_instances=1,
        coalesce=True,
    )
    _scheduler.start()
    logger.info("Pruning scheduler started (every %ds)", settings.prune_interval_seconds)


def stop_pruning() -> None:
    """Stop the scheduler on shutdown."""
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        logger.info("Pruning scheduler stopped")


__all__ = ["run_prune_once", "start_pruning", "stop_pruning"]
