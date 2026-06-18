"""Read queries backing the REST routers and the WebSocket replay-on-connect.

Node ids are computed *label-aware* (Process->hash, IP_Address->address, everything
else->name) so an id here matches the id the realtime layer and ingest use. Neo4j
temporal values are converted to ISO strings so FastAPI can serialize them.
"""

from __future__ import annotations

from typing import Any, Optional

from neo4j.time import Date, DateTime, Duration, Time

from backend.graph.driver import run_read

# Node-label allowlist for the ?type= filter on /graph/nodes.
NODE_LABELS = ("Host", "Process", "IP_Address", "Domain", "Threat_Campaign")


def _nid(var: str) -> str:
    """Cypher expression for a node's stable id (the property MERGE keys on).

    Only the Cypher variable name is interpolated (a fixed code token, never user
    input), so this introduces no injection surface.
    """
    return (
        f"CASE labels({var})[0] "
        f"WHEN 'Process' THEN {var}.hash "
        f"WHEN 'IP_Address' THEN {var}.address "
        f"ELSE {var}.name END"
    )


def _jsonable(value: Any) -> Any:
    """Recursively convert Neo4j temporal types to ISO strings for JSON serialization."""
    if isinstance(value, (DateTime, Date, Time, Duration)):
        return value.iso_format()
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    return value


async def get_nodes(node_type: Optional[str], page: int, limit: int) -> list[dict]:
    """Return one page of nodes as ``{id, label, properties}`` dicts (ordered by id)."""
    skip = (page - 1) * limit
    filt = "WHERE $type IN labels(n)" if node_type else ""
    cypher = f"""
    MATCH (n) {filt}
    WITH n ORDER BY {_nid('n')}
    SKIP $skip LIMIT $limit
    RETURN collect({{id: {_nid('n')}, label: labels(n)[0], properties: properties(n)}}) AS nodes
    """
    params: dict[str, Any] = {"skip": skip, "limit": limit}
    if node_type:
        params["type"] = node_type

    async def _work(tx):
        result = await tx.run(cypher, **params)
        record = await result.single()
        return record["nodes"] if record else []

    return _jsonable(await run_read(_work))


async def count_nodes(node_type: Optional[str]) -> int:
    """Total node count (optionally filtered by label) for pagination metadata."""
    filt = "WHERE $type IN labels(n)" if node_type else ""
    cypher = f"MATCH (n) {filt} RETURN count(n) AS c"
    params = {"type": node_type} if node_type else {}

    async def _work(tx):
        result = await tx.run(cypher, **params)
        record = await result.single()
        return record["c"] if record else 0

    return await run_read(_work)


_CAMPAIGNS_CYPHER = """
MATCH (c:Threat_Campaign)
OPTIONAL MATCH (ip:IP_Address)-[pc:PART_OF_CAMPAIGN]->(c)
WITH c, count(DISTINCT ip) AS ip_count, max(pc.confidence) AS max_confidence
OPTIONAL MATCH (c)-[:TARGETS]->(h:Host)
RETURN c.name AS name, c.source_feed AS source_feed, c.first_seen AS first_seen,
       ip_count, coalesce(max_confidence, 0.0) AS max_confidence,
       count(DISTINCT h) AS host_count
ORDER BY max_confidence DESC, name
"""


async def get_campaigns() -> list[dict]:
    """Active campaigns with connected-host count, IP count, and peak confidence."""

    async def _work(tx):
        result = await tx.run(_CAMPAIGNS_CYPHER)
        return [record.data() async for record in result]

    return _jsonable(await run_read(_work))


# Builds a {nodes, edges} subgraph from a non-empty node list, never UNWINDing an
# empty collection (which would collapse the result to zero rows).
_SUBGRAPH_TAIL = f"""
UNWIND allNodes AS a
OPTIONAL MATCH (a)-[r]->(b)
WHERE b IN allNodes
WITH allNodes, collect(DISTINCT r) AS rels
RETURN
  [n IN allNodes | {{id: {_nid('n')}, label: labels(n)[0], properties: properties(n)}}] AS nodes,
  [r IN rels WHERE r IS NOT NULL |
     {{source: {_nid('startNode(r)')}, target: {_nid('endNode(r)')}, rel: type(r)}}] AS edges
"""


async def get_host_subgraph(name: str) -> dict:
    """The 2-hop neighborhood around a single host as ``{nodes, edges}``."""
    cypher = f"""
    MATCH (h:Host {{name: $name}})
    OPTIONAL MATCH (h)-[*1..2]-(m)
    WITH h, collect(DISTINCT m) AS ms
    WITH [h] + [x IN ms WHERE x IS NOT NULL] AS allNodes
    {_SUBGRAPH_TAIL}
    """

    async def _work(tx):
        result = await tx.run(cypher, name=name)
        record = await result.single()
        if record is None:
            return {"nodes": [], "edges": []}
        return {"nodes": record["nodes"], "edges": record["edges"]}

    return _jsonable(await run_read(_work))


async def get_full_graph(limit: int = 1000) -> dict:
    """The whole graph (capped at ``limit`` nodes) for replay on a new WS connection."""
    cypher = f"""
    MATCH (n)
    WITH collect(n)[0..$limit] AS allNodes
    {_SUBGRAPH_TAIL}
    """

    async def _work(tx):
        result = await tx.run(cypher, limit=limit)
        record = await result.single()
        if record is None:
            return {"nodes": [], "edges": []}
        return {"nodes": record["nodes"], "edges": record["edges"]}

    return _jsonable(await run_read(_work))


__all__ = [
    "NODE_LABELS",
    "get_nodes",
    "count_nodes",
    "get_campaigns",
    "get_host_subgraph",
    "get_full_graph",
]
