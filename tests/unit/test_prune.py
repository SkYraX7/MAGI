"""Unit tests for the pruning job — correct Cypher params + broadcast on removal."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from backend.graph import prune


class FakeResult:
    def __init__(self, removed):
        self._removed = removed

    async def single(self):
        return {"removed": self._removed}


class FakeTx:
    def __init__(self, removed):
        self._removed = removed
        self.queries: list[str] = []

    async def run(self, query, **params):
        self.queries.append(query)
        self.last_params = params
        return FakeResult(self._removed)


@pytest.fixture
def patched(monkeypatch):
    """Patch run_write to run work against a FakeTx; capture broadcasts."""
    state = {"removed": ["p1|1.2.3.4|CONNECTED_TO"], "txs": []}

    async def fake_run_write(work, **_kw):
        tx = FakeTx(state["removed"])
        state["txs"].append(tx)
        return await work(tx)

    broadcasts = []
    monkeypatch.setattr(prune, "run_write", fake_run_write)
    monkeypatch.setattr(prune.manager, "broadcast", AsyncMock(side_effect=lambda m: broadcasts.append(m)))
    state["broadcasts"] = broadcasts
    return state


async def test_prune_passes_stale_hours_param(patched, monkeypatch):
    from backend.config import Settings

    settings = Settings(_env_file=None, prune_stale_after_hours=6)
    monkeypatch.setattr(prune, "get_settings", lambda: settings)

    removed = await prune.run_prune_once()

    assert removed == ["p1|1.2.3.4|CONNECTED_TO"]
    edges_tx = patched["txs"][0]
    assert edges_tx.last_params["hours"] == 6
    assert "CONNECTED_TO" in edges_tx.queries[0]
    assert "PART_OF_CAMPAIGN" in edges_tx.queries[0]  # never prune campaign-linked IPs


async def test_prune_broadcasts_removed_edges(patched):
    await prune.run_prune_once()
    assert patched["broadcasts"], "a prune message should be broadcast when edges are removed"
    assert patched["broadcasts"][0]["type"] == "prune"
    assert patched["broadcasts"][0]["data"]["removed_edge_ids"] == ["p1|1.2.3.4|CONNECTED_TO"]


async def test_prune_no_broadcast_when_nothing_removed(patched):
    patched["removed"] = []
    await prune.run_prune_once()
    assert patched["broadcasts"] == []
