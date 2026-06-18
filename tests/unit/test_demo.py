"""Unit tests for the DEMO_MODE seeder's pure event generator."""

from __future__ import annotations

import random

from backend.demo import THREAT_IPS, benign_event


def test_benign_event_is_valid_network_event():
    evt = benign_event(random.Random(0))
    assert evt.event_type == "network"
    assert evt.remote_ip
    assert evt.direction == "outbound"
    assert len(evt.process_hash) == 64  # sha256 hex


def test_benign_event_varies_with_rng():
    a = benign_event(random.Random(1))
    b = benign_event(random.Random(2))
    # Different seeds should generally produce different (host, ip) pairs.
    assert (a.platform, a.remote_ip) != (b.platform, b.remote_ip) or a.pid != b.pid


def test_threat_ips_have_campaign_labels():
    assert all(isinstance(name, str) and name for name in THREAT_IPS.values())
