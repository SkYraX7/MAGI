"""Unit tests for Redis key builders and TTL constants (no server required)."""

from __future__ import annotations

from backend.cache import redis as r


def test_key_patterns():
    assert r.ip_key("1.2.3.4") == "ip:1.2.3.4"
    assert r.domain_key("Evil.COM") == "domain:evil.com"  # lowercased
    assert r.dedup_key("abc123") == "dedup:abc123"
    assert r.rate_key("virustotal") == "rate:osint:virustotal"
    assert r.feed_last_updated_key("feodo") == "feed:feodo:last_updated"


def test_ttl_constants_match_spec():
    assert r.IP_CACHE_TTL == 24 * 60 * 60
    assert r.DOMAIN_CACHE_TTL == 12 * 60 * 60
    assert r.DEDUP_TTL == 30
    assert r.RATE_LIMIT_TTL == 60
