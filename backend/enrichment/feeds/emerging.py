"""Emerging Threats Open enricher — compromised / known-hostile IP list."""

from __future__ import annotations

from typing import Optional

from backend.config import get_settings
from backend.enrichment.feeds.base import IpBlocklistFeed
from backend.enrichment.models import EnrichmentResult

FEED_NAME = "emerging"
CAMPAIGN = "Emerging Threats Compromised"

_feed: Optional[IpBlocklistFeed] = None


def get_feed() -> IpBlocklistFeed:
    """Return the Emerging Threats feed singleton."""
    global _feed
    if _feed is None:
        _feed = IpBlocklistFeed(FEED_NAME, get_settings().emerging_feed_url, CAMPAIGN)
    return _feed


async def enrich(ip: str) -> EnrichmentResult:
    """Membership check against the Emerging Threats list (local set lookup)."""
    if get_feed().contains(ip):
        return EnrichmentResult(emerging_hit=True, campaign=CAMPAIGN, source_feed=FEED_NAME)
    return EnrichmentResult()


__all__ = ["enrich", "get_feed", "FEED_NAME", "CAMPAIGN"]
