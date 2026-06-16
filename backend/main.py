"""FastAPI application factory + lifespan hooks.

Phase 2 scope: the lifespan initializes the Neo4j schema on startup and closes the
driver on shutdown, and runs a background consumer that drains the shared event queue
into the graph via :func:`backend.graph.ingest.log_event`. Routers, auth, CORS, and
metrics arrive in Phase 4/5; this file is intentionally minimal for now.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from backend.config import get_settings
from backend.graph.driver import close_driver, verify_connectivity
from backend.graph.ingest import log_event
from backend.graph.schema import initialize_schema
from collectors.shared.queue import get_event, task_done

logger = logging.getLogger(__name__)


async def _consume_queue(stop_event: asyncio.Event) -> None:
    """Drain the shared event queue into Neo4j until shutdown.

    Errors per event are caught and logged so one bad write never kills the consumer
    (mirrors the "one failing enricher does not crash the worker" rule).
    """
    while not stop_event.is_set():
        try:
            event = await asyncio.wait_for(get_event(), timeout=0.5)
        except asyncio.TimeoutError:
            continue
        try:
            await log_event(event)
        except Exception:  # noqa: BLE001 - keep the consumer alive on any write failure
            logger.exception("Failed to ingest %s event from %s", event.event_type, event.platform)
        finally:
            task_done()


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logger.info("MAGI backend starting up")

    # Startup: verify Neo4j is reachable, then create constraints/indexes (idempotent).
    await verify_connectivity()
    await initialize_schema()

    stop_event = asyncio.Event()
    consumer = asyncio.create_task(_consume_queue(stop_event))
    app.state.queue_consumer = consumer

    try:
        yield
    finally:
        # Shutdown: stop the consumer, then close the driver.
        logger.info("MAGI backend shutting down")
        stop_event.set()
        consumer.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await consumer
        await close_driver()
        logger.info("MAGI backend shutdown complete")


def create_app() -> FastAPI:
    """Application factory."""
    app = FastAPI(
        title="MAGI — Multi-source Adaptive Graph Intelligence",
        version="0.1.0",
        lifespan=lifespan,
    )

    @app.get("/healthz", tags=["health"])
    async def healthz() -> dict[str, str]:
        """Minimal liveness probe (full Neo4j+Redis readiness lands in Phase 5)."""
        return {"status": "ok"}

    return app


app = create_app()
