"""Unit tests for the enrichment event hash (dedup key derivation)."""

from __future__ import annotations

from datetime import datetime, timezone

from backend.enrichment.pipeline import compute_event_hash
from collectors.shared.schema import UnifiedLogEvent


def _event(ts: datetime, **overrides) -> UnifiedLogEvent:
    base = dict(
        timestamp=ts,
        platform="h1",
        event_type="network",
        source_process="nginx",
        process_hash="abc",
        pid=1,
        direction="outbound",
        remote_ip="1.2.3.4",
        remote_port=443,
    )
    base.update(overrides)
    return UnifiedLogEvent(**base)


def test_hash_is_deterministic():
    ts = datetime(2026, 6, 16, 4, 45, 0, tzinfo=timezone.utc)
    assert compute_event_hash(_event(ts)) == compute_event_hash(_event(ts))


def test_same_5s_window_collapses():
    a = _event(datetime(2026, 6, 16, 4, 45, 1, tzinfo=timezone.utc))
    b = _event(datetime(2026, 6, 16, 4, 45, 4, tzinfo=timezone.utc))
    assert compute_event_hash(a) == compute_event_hash(b)


def test_different_window_differs():
    a = _event(datetime(2026, 6, 16, 4, 45, 1, tzinfo=timezone.utc))
    b = _event(datetime(2026, 6, 16, 4, 45, 9, tzinfo=timezone.utc))
    assert compute_event_hash(a) != compute_event_hash(b)


def test_different_ip_differs():
    ts = datetime(2026, 6, 16, 4, 45, 0, tzinfo=timezone.utc)
    assert compute_event_hash(_event(ts)) != compute_event_hash(_event(ts, remote_ip="9.9.9.9"))


def test_hash_is_hex_sha256():
    h = compute_event_hash(_event(datetime.now(timezone.utc)))
    assert len(h) == 64
    int(h, 16)  # raises if not valid hex
