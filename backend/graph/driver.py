"""Neo4j async driver singleton.

One :class:`AsyncDriver` per process, capped at ``NEO4J_MAX_CONNECTIONS`` pooled
connections. Connectivity is verified with bounded exponential-backoff retries so a
backend started slightly ahead of Neo4j (common under docker-compose) recovers
instead of crash-looping.

Writes go through :func:`run_write`, which uses Neo4j's *managed* transaction API
(``session.execute_write``) — that retries transient failures (``ServiceUnavailable``,
leader switches) automatically, satisfying the Phase 2 "retry logic" requirement.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable, Optional

from neo4j import AsyncDriver, AsyncGraphDatabase, AsyncManagedTransaction
from neo4j.exceptions import ServiceUnavailable

from backend.config import get_settings

logger = logging.getLogger(__name__)

_driver: Optional[AsyncDriver] = None


def get_driver() -> AsyncDriver:
    """Return the process-wide async driver, creating it lazily on first use."""
    global _driver
    if _driver is None:
        settings = get_settings()
        _driver = AsyncGraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
            max_connection_pool_size=settings.neo4j_max_connections,
            connection_acquisition_timeout=60.0,
        )
        logger.info(
            "Neo4j driver created (uri=%s, pool<=%d)",
            settings.neo4j_uri,
            settings.neo4j_max_connections,
        )
    return _driver


async def verify_connectivity(*, retries: int = 5, base_delay: float = 1.0) -> None:
    """Ping Neo4j, retrying with exponential backoff. Raises on final failure."""
    driver = get_driver()
    last_exc: Optional[Exception] = None
    for attempt in range(retries):
        try:
            await driver.verify_connectivity()
            logger.info("Neo4j connectivity verified")
            return
        except ServiceUnavailable as exc:
            last_exc = exc
            delay = min(base_delay * 2**attempt, 30.0)
            logger.warning(
                "Neo4j unavailable (attempt %d/%d); retrying in %.1fs",
                attempt + 1,
                retries,
                delay,
            )
            await asyncio.sleep(delay)
    assert last_exc is not None
    raise last_exc


async def run_write(
    work: Callable[[AsyncManagedTransaction], Awaitable[Any]],
    *,
    database: Optional[str] = None,
) -> Any:
    """Execute a write unit-of-work in a managed (auto-retrying) transaction.

    ``work`` is an async callable taking the transaction; all Cypher inside must use
    parameterized queries — never f-string interpolation (CLAUDE.md security rule).
    """
    driver = get_driver()
    async with driver.session(database=database) as session:
        return await session.execute_write(work)


async def run_read(
    work: Callable[[AsyncManagedTransaction], Awaitable[Any]],
    *,
    database: Optional[str] = None,
) -> Any:
    """Execute a read unit-of-work in a managed (auto-retrying) transaction."""
    driver = get_driver()
    async with driver.session(database=database) as session:
        return await session.execute_read(work)


async def close_driver() -> None:
    """Close the driver and drop the singleton (called from FastAPI lifespan shutdown)."""
    global _driver
    if _driver is not None:
        await _driver.close()
        _driver = None
        logger.info("Neo4j driver closed")


__all__ = ["get_driver", "verify_connectivity", "run_write", "run_read", "close_driver"]
