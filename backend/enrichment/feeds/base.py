"""Shared machinery for IP-blocklist threat-intel feeds.

A feed is a daily-refreshed plain-text list of malicious IPs. Membership is an O(1)
set lookup, so per-event enrichment against a feed is free (no network call).

Resilience (CLAUDE.md "Feed download failure"):
  * Downloads are validated line-by-line before parsing — every non-comment line must
    be a valid IP, or it's skipped (and a feed that parses to zero IPs is rejected).
  * On download failure the last good copy on disk is served instead.
  * If the on-disk copy is older than ``FEED_STALE_ALERT_HOURS`` an alert is logged.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

from backend.cache.redis import set_feed_last_updated
from backend.config import get_settings

logger = logging.getLogger(__name__)


def parse_ip_blocklist(text: str) -> set[str]:
    """Parse blocklist text into a set of IPs, validating each line's format.

    Skips blank lines and ``#`` comments. Each remaining token must parse as an IP
    address; CIDR ranges and anything malformed are skipped with a debug log.
    """
    ips: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split()[0].split(",")[0].strip()  # tolerate "IP # comment" / CSV
        try:
            ipaddress.ip_address(token)
        except ValueError:
            logger.debug("Skipping non-IP blocklist line: %r", raw)
            continue
        ips.add(token)
    return ips


class IpBlocklistFeed:
    """A refreshable, disk-cached IP blocklist with O(1) membership lookup."""

    def __init__(self, name: str, url: str, campaign_name: str) -> None:
        self.name = name
        self.url = url
        self.campaign_name = campaign_name
        self._ips: set[str] = set()
        cache_dir = Path(get_settings().feeds_cache_dir)
        self._cache_file = cache_dir / f"{name}.txt"

    @property
    def size(self) -> int:
        return len(self._ips)

    def contains(self, ip: str) -> bool:
        return ip in self._ips

    def load_from_disk(self) -> bool:
        """Populate the in-memory set from the on-disk cache. Returns success."""
        if self._cache_file.exists():
            self._ips = parse_ip_blocklist(self._cache_file.read_text(encoding="utf-8"))
            logger.info("Feed %s loaded %d IPs from cache", self.name, len(self._ips))
            return True
        return False

    async def refresh(self, client: httpx.AsyncClient) -> bool:
        """Download and swap in a fresh blocklist; fall back to cache on failure."""
        try:
            resp = await client.get(self.url, timeout=30.0, follow_redirects=True)
            resp.raise_for_status()
            ips = parse_ip_blocklist(resp.text)
            if not ips:
                raise ValueError("feed parsed to zero valid IPs; rejecting as malformed")
            self._cache_file.parent.mkdir(parents=True, exist_ok=True)
            self._cache_file.write_text(resp.text, encoding="utf-8")
            self._ips = ips
            await set_feed_last_updated(self.name, datetime.now(timezone.utc).isoformat())
            logger.info("Feed %s refreshed: %d IPs", self.name, len(ips))
            return True
        except Exception as exc:  # noqa: BLE001 - any failure -> serve last good copy
            logger.warning("Feed %s download failed: %s; serving cached copy", self.name, exc)
            served = self.load_from_disk()
            self._alert_if_stale()
            return served

    def _alert_if_stale(self) -> None:
        if not self._cache_file.exists():
            logger.error("ALERT: feed %s has no cached copy and download failed", self.name)
            return
        age_hours = (time.time() - self._cache_file.stat().st_mtime) / 3600.0
        threshold = get_settings().feed_stale_alert_hours
        if age_hours > threshold:
            logger.error(
                "ALERT: feed %s cache is %.1fh old (> %dh threshold)",
                self.name,
                age_hours,
                threshold,
            )


__all__ = ["parse_ip_blocklist", "IpBlocklistFeed"]
