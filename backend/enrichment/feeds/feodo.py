"""Abuse.ch Feodo Tracker enricher — daily IP blocklist of botnet C2 servers."""

from __future__ import annotations

from typing import Optional

from backend.config import get_settings
from backend.enrichment.feeds.base import IpBlocklistFeed
from backend.enrichment.models import EnrichmentResult

FEED_NAME = "feodo"
CAMPAIGN = "Feodo Tracker Botnet"

_feed: Optional[IpBlocklistFeed] = None


def get_feed() -> IpBlocklistFeed:
    """Return the Feodo feed singleton."""
    global _feed
    if _feed is None:
        _feed = IpBlocklistFeed(FEED_NAME, get_settings().feodo_feed_url, CAMPAIGN)
    return _feed


async def enrich(ip: str) -> EnrichmentResult:
    """Membership check against the Feodo blocklist (local set lookup, no network)."""
    if get_feed().contains(ip):
        return EnrichmentResult(feodo_hit=True, campaign=CAMPAIGN, source_feed=FEED_NAME)
    return EnrichmentResult()


__all__ = ["enrich", "get_feed", "FEED_NAME", "CAMPAIGN"]
