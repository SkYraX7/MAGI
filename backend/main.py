"""FastAPI application factory + lifespan hooks.

Startup: verify Neo4j, initialize the schema (idempotent), then start the enrichment
pipeline — a worker pool that drains the shared event queue, writes every event to the
graph (Phase 2 ingest), and enriches network events against OSINT sources (Phase 3).
Shutdown: stop the pipeline, then close the Neo4j and Redis clients.

Routers, auth, CORS, and metrics arrive in Phase 4/5; this file stays minimal for now.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from backend.cache.redis import close_redis
from backend.config import get_settings
from backend.enrichment.pipeline import EnrichmentPipeline
from backend.graph.driver import close_driver, verify_connectivity
from backend.graph.schema import initialize_schema

logger = logging.getLogger(__name__)


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

    pipeline = EnrichmentPipeline()
    await pipeline.start()
    app.state.pipeline = pipeline

    try:
        yield
    finally:
        # Shutdown: drain/stop the enrichment workers, then close clients.
        logger.info("MAGI backend shutting down")
        await pipeline.stop()
        await close_driver()
        await close_redis()
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
