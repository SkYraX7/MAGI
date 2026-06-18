"""Graph REST router — paginated nodes, campaigns, host subgraph, manual prune.

Every route requires a valid bearer token (router-level dependency); ``/graph/prune``
additionally requires ``role=admin``. Pagination caps ``limit`` at 500 per page.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.auth import User, get_current_user, require_admin
from backend.graph import queries
from backend.graph.prune import run_prune_once

router = APIRouter(
    prefix="/graph",
    tags=["graph"],
    dependencies=[Depends(get_current_user)],  # all graph routes require auth
)

MAX_LIMIT = 500


@router.get("/nodes")
async def list_nodes(
    type: Optional[str] = Query(None, description="Filter by node label"),
    page: int = Query(1, ge=1),
    limit: int = Query(100, ge=1, le=MAX_LIMIT),
) -> dict:
    """Paginated node list. Optional ``?type=IP_Address`` filter by label."""
    if type is not None and type not in queries.NODE_LABELS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unknown type {type!r}; allowed: {', '.join(queries.NODE_LABELS)}",
        )
    nodes = await queries.get_nodes(type, page, limit)
    total = await queries.count_nodes(type)
    return {"page": page, "limit": limit, "total": total, "nodes": nodes}


@router.get("/campaigns")
async def list_campaigns() -> dict:
    """Active threat campaigns with connected-host count and peak confidence."""
    return {"campaigns": await queries.get_campaigns()}


@router.get("/host/{name}")
async def host_subgraph(name: str) -> dict:
    """The 2-hop subgraph around a single host."""
    return await queries.get_host_subgraph(name)


@router.delete("/prune")
async def prune(_: User = Depends(require_admin)) -> dict:
    """Manually trigger a pruning pass (admin only)."""
    removed = await run_prune_once()
    return {"removed_edge_ids": removed, "count": len(removed)}
