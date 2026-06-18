"""Health endpoints — liveness and dependency readiness.

``/healthz`` is the readiness probe: it pings Neo4j and Redis and returns 200 with
``{"neo4j": "ok", "redis": "ok"}`` or 503 with per-dependency detail (CLAUDE.md Phase 5).
``/livez`` is a cheap liveness probe that never touches dependencies.
"""

from __future__ import annotations

from fastapi import APIRouter, Response, status

from backend.cache.redis import get_redis
from backend.graph.driver import get_driver

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def healthz(response: Response) -> dict[str, str]:
    """Readiness: ping Neo4j + Redis; 503 if either is unreachable."""
    health: dict[str, str] = {}
    healthy = True

    try:
        await get_driver().verify_connectivity()
        health["neo4j"] = "ok"
    except Exception as exc:  # noqa: BLE001
        health["neo4j"] = f"error: {exc}"
        healthy = False

    try:
        await get_redis().ping()
        health["redis"] = "ok"
    except Exception as exc:  # noqa: BLE001
        health["redis"] = f"error: {exc}"
        healthy = False

    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return health


@router.get("/livez")
async def livez() -> dict[str, str]:
    """Liveness: process is up (no dependency checks)."""
    return {"status": "ok"}
