"""FastAPI application factory + lifespan hooks.

Assembles the whole backend:
  * CORS restricted to ``ALLOWED_ORIGINS``
  * per-client rate limiting via slowapi
  * Prometheus metrics at ``/metrics``
  * routers: health, auth, graph (REST), ws (WebSocket)

Lifespan startup: verify Neo4j -> init schema -> start the enrichment pipeline (wired
to broadcast graph updates + threat flags to WS clients) -> start the prune scheduler.
Shutdown (CLAUDE.md order): flush/stop the enrichment queue -> drain WS sessions ->
close the Neo4j driver -> close Redis.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from backend.cache.redis import close_redis
from backend.config import get_settings
from backend.enrichment.notify import ThreatFlag, log_threat
from backend.enrichment.pipeline import EnrichmentPipeline
from backend.graph.driver import close_driver, verify_connectivity
from backend.graph.prune import start_pruning, stop_pruning
from backend.graph.schema import initialize_schema
from backend.realtime import manager, threat_flag_msg
from backend.routers import auth as auth_router
from backend.routers import graph as graph_router
from backend.routers import health as health_router
from backend.routers import ws as ws_router

logger = logging.getLogger(__name__)


async def _broadcast_threat(flag: ThreatFlag) -> None:
    """Pipeline threat sink: log it and push a threat_flag to every WS client."""
    await log_threat(flag)
    await manager.broadcast(threat_flag_msg(flag.node_id, flag.campaign, flag.confidence))


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logger.info("MAGI backend starting up")

    await verify_connectivity()
    await initialize_schema()

    pipeline = EnrichmentPipeline(
        on_threat=_broadcast_threat,
        on_event=manager.broadcast_event,
    )
    await pipeline.start()
    app.state.pipeline = pipeline
    start_pruning()

    try:
        yield
    finally:
        logger.info("MAGI backend shutting down")
        stop_pruning()
        await pipeline.stop()      # drain the enrichment queue/workers
        await manager.drain()      # close WS sessions so clients reconnect
        await close_driver()       # close Neo4j
        await close_redis()        # close Redis
        logger.info("MAGI backend shutdown complete")


def create_app() -> FastAPI:
    """Application factory."""
    settings = get_settings()

    app = FastAPI(
        title="MAGI — Multi-source Adaptive Graph Intelligence",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Rate limiting (per client IP).
    limiter = Limiter(key_func=get_remote_address, default_limits=[settings.api_rate_limit])
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)

    # CORS restricted to the configured frontend origins.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health_router.router)
    app.include_router(auth_router.router)
    app.include_router(graph_router.router)
    app.include_router(ws_router.router)

    # Prometheus /metrics.
    Instrumentator().instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)

    return app


app = create_app()
