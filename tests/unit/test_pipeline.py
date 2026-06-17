"""Unit tests for the enrichment pipeline orchestration (all I/O mocked)."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from backend.cache import redis as rds
from backend.enrichment import censys, virustotal
from backend.enrichment import pipeline as pl
from backend.enrichment.feeds import emerging, feodo
from backend.enrichment.models import EnrichmentResult
from backend.enrichment.pipeline import EnrichmentPipeline
from collectors.shared.schema import UnifiedLogEvent


def _net_event(**overrides) -> UnifiedLogEvent:
    base = dict(
        timestamp=datetime(2026, 6, 16, 4, 45, tzinfo=timezone.utc),
        platform="h1",
        event_type="network",
        source_process="svc",
        process_hash="abc",
        pid=1,
        direction="outbound",
        remote_ip="185.220.101.5",
        remote_port=443,
    )
    base.update(overrides)
    return UnifiedLogEvent(**base)


@pytest.fixture
def mocked_io(monkeypatch):
    """Patch Redis helpers and graph writers; capture the writer calls."""
    monkeypatch.setattr(rds, "already_seen", AsyncMock(return_value=False))
    monkeypatch.setattr(rds, "get_ip_cache", AsyncMock(return_value={}))
    monkeypatch.setattr(rds, "set_ip_cache", AsyncMock())

    captured: dict = {}

    async def fake_update(ip, **kw):
        captured["update"] = (ip, kw)

    async def fake_bridge(ip, **kw):
        captured["bridge"] = (ip, kw)

    monkeypatch.setattr(pl, "update_ip_enrichment", fake_update)
    monkeypatch.setattr(pl, "bridge_campaign", fake_bridge)
    return captured


def _patch_enrichers(monkeypatch, *, feodo_hit=False, vt_malicious=0):
    monkeypatch.setattr(
        virustotal, "enrich", AsyncMock(return_value=EnrichmentResult(vt_malicious=vt_malicious, vt_present=True))
    )
    monkeypatch.setattr(censys, "enrich", AsyncMock(return_value=EnrichmentResult()))
    feo = (
        EnrichmentResult(feodo_hit=True, campaign=feodo.CAMPAIGN, source_feed=feodo.FEED_NAME)
        if feodo_hit
        else EnrichmentResult()
    )
    monkeypatch.setattr(feodo, "enrich", AsyncMock(return_value=feo))
    monkeypatch.setattr(emerging, "enrich", AsyncMock(return_value=EnrichmentResult()))


async def test_feodo_hit_bridges_campaign(monkeypatch, mocked_io):
    # Feodo scores 0.40, which meets the lowered 0.40 threshold (and is authoritative).
    _patch_enrichers(monkeypatch, feodo_hit=True)
    flags = []

    async def on_threat(flag):
        flags.append(flag)

    p = EnrichmentPipeline(on_threat=on_threat)
    p._client = object()  # not used; enrichers are mocked
    await p._enrich_ip(_net_event())

    assert "bridge" in mocked_io, "campaign should be bridged on a feed hit"
    assert mocked_io["bridge"][0] == "185.220.101.5"
    assert mocked_io["bridge"][1]["campaign"] == feodo.CAMPAIGN
    assert mocked_io["update"][1]["is_malicious"] is True
    assert flags and flags[0].campaign == feodo.CAMPAIGN


async def test_emerging_only_bridges_via_attribution(monkeypatch, mocked_io):
    # Emerging scores 0.30, below the 0.40 threshold — it bridges only because a feed
    # hit is authoritative attribution. Guards that override after lowering the threshold.
    monkeypatch.setattr(virustotal, "enrich", AsyncMock(return_value=EnrichmentResult()))
    monkeypatch.setattr(censys, "enrich", AsyncMock(return_value=EnrichmentResult()))
    monkeypatch.setattr(feodo, "enrich", AsyncMock(return_value=EnrichmentResult()))
    monkeypatch.setattr(
        emerging,
        "enrich",
        AsyncMock(
            return_value=EnrichmentResult(
                emerging_hit=True, campaign=emerging.CAMPAIGN, source_feed=emerging.FEED_NAME
            )
        ),
    )

    p = EnrichmentPipeline()
    p._client = object()
    await p._enrich_ip(_net_event())

    assert mocked_io["bridge"][1]["campaign"] == emerging.CAMPAIGN
    assert mocked_io["bridge"][1]["confidence"] == pytest.approx(0.30)
    assert mocked_io["update"][1]["is_malicious"] is True


async def test_benign_ip_no_campaign(monkeypatch, mocked_io):
    _patch_enrichers(monkeypatch, feodo_hit=False, vt_malicious=0)
    p = EnrichmentPipeline()
    p._client = object()
    await p._enrich_ip(_net_event())

    assert "bridge" not in mocked_io
    assert mocked_io["update"][1]["is_malicious"] is False


async def test_high_vt_score_bridges_unattributed(monkeypatch, mocked_io):
    # VT >= 5 -> 0.50 >= threshold, but no feed attribution -> "Unattributed Threat".
    _patch_enrichers(monkeypatch, feodo_hit=False, vt_malicious=9)
    p = EnrichmentPipeline()
    p._client = object()
    await p._enrich_ip(_net_event())

    assert mocked_io["bridge"][1]["campaign"] == "Unattributed Threat"
    assert mocked_io["update"][1]["is_malicious"] is True


async def test_dedup_skips_enrichment(monkeypatch, mocked_io):
    monkeypatch.setattr(rds, "already_seen", AsyncMock(return_value=True))
    _patch_enrichers(monkeypatch, feodo_hit=True)
    p = EnrichmentPipeline()
    p._client = object()
    await p._enrich_ip(_net_event())

    # Seen within the dedup window -> no writes at all.
    assert "bridge" not in mocked_io
    assert "update" not in mocked_io


async def test_cache_hit_skips_fanout(monkeypatch, mocked_io):
    cached = EnrichmentResult(feodo_hit=True, campaign=feodo.CAMPAIGN, source_feed="feodo")
    monkeypatch.setattr(rds, "get_ip_cache", AsyncMock(return_value=cached.to_cache_mapping()))
    fan_out = AsyncMock()
    monkeypatch.setattr(EnrichmentPipeline, "_fan_out", fan_out)

    p = EnrichmentPipeline()
    p._client = object()
    await p._enrich_ip(_net_event())

    fan_out.assert_not_called()
    assert mocked_io["bridge"][1]["campaign"] == feodo.CAMPAIGN
