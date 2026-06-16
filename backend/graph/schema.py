"""Neo4j constraint + index setup — runs once at startup, idempotent.

Every statement uses ``IF NOT EXISTS`` so :func:`initialize_schema` is safe to call on
every boot. Uniqueness constraints are what make ``MERGE`` deduplicate nodes (and they
create a backing index for fast lookups); the extra indexes accelerate the enrichment
and pruning queries that filter on ``is_malicious`` / ``timestamp``.
"""

from __future__ import annotations

import logging

from neo4j import AsyncManagedTransaction

from backend.graph.driver import run_write

logger = logging.getLogger(__name__)

# Uniqueness constraints — one per node key. These guarantee MERGE upserts instead of
# duplicating, and back each key with an index automatically.
CONSTRAINTS: tuple[str, ...] = (
    "CREATE CONSTRAINT host_name IF NOT EXISTS "
    "FOR (h:Host) REQUIRE h.name IS UNIQUE",
    "CREATE CONSTRAINT process_hash IF NOT EXISTS "
    "FOR (p:Process) REQUIRE p.hash IS UNIQUE",
    "CREATE CONSTRAINT ip_address IF NOT EXISTS "
    "FOR (i:IP_Address) REQUIRE i.address IS UNIQUE",
    "CREATE CONSTRAINT domain_name IF NOT EXISTS "
    "FOR (d:Domain) REQUIRE d.name IS UNIQUE",
    "CREATE CONSTRAINT campaign_name IF NOT EXISTS "
    "FOR (c:Threat_Campaign) REQUIRE c.name IS UNIQUE",
)

# Secondary indexes for hot filter predicates in enrichment + pruning.
INDEXES: tuple[str, ...] = (
    "CREATE INDEX ip_is_malicious IF NOT EXISTS "
    "FOR (i:IP_Address) ON (i.is_malicious)",
    "CREATE INDEX domain_is_malicious IF NOT EXISTS "
    "FOR (d:Domain) ON (d.is_malicious)",
)


async def initialize_schema() -> None:
    """Create all constraints and indexes. Idempotent; call once on startup."""

    async def _apply(tx: AsyncManagedTransaction) -> None:
        for statement in (*CONSTRAINTS, *INDEXES):
            await tx.run(statement)

    await run_write(_apply)
    logger.info(
        "Neo4j schema initialized (%d constraints, %d indexes)",
        len(CONSTRAINTS),
        len(INDEXES),
    )


__all__ = ["initialize_schema", "CONSTRAINTS", "INDEXES"]
