"""Unit tests for the UnifiedLogEvent schema — validation is the ingest gatekeeper."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from collectors.shared.schema import UnifiedLogEvent


def _network(**overrides):
    base = dict(
        timestamp=datetime(2026, 6, 16, 4, 45, tzinfo=timezone.utc),
        platform="host-01",
        event_type="network",
        source_process="nginx",
        process_hash="",
        pid=1234,
        direction="outbound",
        remote_ip="185.220.101.5",
        remote_port=443,
        protocol="tcp",
    )
    base.update(overrides)
    return base


def test_valid_network_event_parses():
    evt = UnifiedLogEvent(**_network())
    assert evt.event_type == "network"
    assert evt.remote_ip == "185.220.101.5"


def test_process_hash_is_lowercased():
    evt = UnifiedLogEvent(**_network(process_hash="ABC123DEF"))
    assert evt.process_hash == "abc123def"


def test_naive_timestamp_coerced_to_utc():
    evt = UnifiedLogEvent(**_network(timestamp=datetime(2026, 6, 16, 4, 45)))
    assert evt.timestamp.tzinfo is not None
    assert evt.timestamp.utcoffset().total_seconds() == 0


def test_missing_required_field_rejected():
    params = _network()
    del params["source_process"]
    with pytest.raises(ValidationError):
        UnifiedLogEvent(**params)


def test_wrong_type_rejected():
    with pytest.raises(ValidationError):
        UnifiedLogEvent(**_network(pid="not-an-int"))


def test_extra_field_forbidden():
    with pytest.raises(ValidationError):
        UnifiedLogEvent(**_network(bogus_field="x"))


def test_network_event_requires_remote_ip():
    params = _network()
    params["remote_ip"] = None
    with pytest.raises(ValidationError):
        UnifiedLogEvent(**params)


def test_network_event_requires_direction():
    params = _network(direction=None)
    with pytest.raises(ValidationError):
        UnifiedLogEvent(**params)


def test_dns_event_requires_domain():
    with pytest.raises(ValidationError):
        UnifiedLogEvent(
            timestamp=datetime.now(timezone.utc),
            platform="host-01",
            event_type="dns",
            source_process="chrome.exe",
            pid=10,
        )


def test_dns_event_valid():
    evt = UnifiedLogEvent(
        timestamp=datetime.now(timezone.utc),
        platform="host-01",
        event_type="dns",
        source_process="chrome.exe",
        pid=10,
        queried_domain="evil.example.com",
    )
    assert evt.queried_domain == "evil.example.com"


def test_invalid_direction_literal_rejected():
    with pytest.raises(ValidationError):
        UnifiedLogEvent(**_network(direction="sideways"))


def test_port_out_of_range_rejected():
    with pytest.raises(ValidationError):
        UnifiedLogEvent(**_network(remote_port=70000))


@pytest.mark.parametrize("event_type", ["process", "image_load"])
def test_process_and_image_load_minimal(event_type):
    evt = UnifiedLogEvent(
        timestamp=datetime.now(timezone.utc),
        platform="host-01",
        event_type=event_type,
        source_process="rundll32.exe",
        process_hash="DEADBEEF",
        pid=99,
    )
    assert evt.event_type == event_type
    assert evt.process_hash == "deadbeef"
