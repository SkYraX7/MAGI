"""Redis client singleton + key patterns, TTL constants, and dedup/rate-limit helpers.

Centralizes every Redis key the enrichment pipeline touches so the patterns in
CLAUDE.md ("Redis Key Patterns & TTLs") live in exactly one place. TTLs are named
module-level constants (seconds) — never magic numbers at call sites.
"""

from __future__ import annotations

import logging
from typing import Optional

from redis.asyncio import Redis, from_url

from backend.config import get_settings

logger = logging.getLogger(__name__)

# --- TTL constants (seconds) ---
IP_CACHE_TTL = 24 * 60 * 60      # ip:{address}        enrichment result cache — 24h
DOMAIN_CACHE_TTL = 12 * 60 * 60  # domain:{name}       DNS enrichment cache    — 12h
DEDUP_TTL = 30                   # dedup:{hash}        short-window de-dup     — 30s
RATE_LIMIT_TTL = 60              # rate:osint:{api}    per-minute rate window  — 60s

_redis: Optional[Redis] = None


# --- key builders ---
def ip_key(address: str) -> str:
    return f"ip:{address}"


def domain_key(name: str) -> str:
    return f"domain:{name.lower()}"


def dedup_key(event_hash: str) -> str:
    return f"dedup:{event_hash}"


def rate_key(api_name: str) -> str:
    return f"rate:osint:{api_name}"


def feed_last_updated_key(feed_name: str) -> str:
    return f"feed:{feed_name}:last_updated"


# --- client lifecycle ---
def get_redis() -> Redis:
    """Return the process-wide async Redis client, created lazily on first use."""
    global _redis
    if _redis is None:
        settings = get_settings()
        _redis = from_url(settings.redis_url, decode_responses=True)
        logger.info("Redis client created (url=%s)", settings.redis_url)
    return _redis


async def close_redis() -> None:
    """Close the client and drop the singleton (FastAPI lifespan shutdown)."""
    global _redis
    if _redis is not None:
        await _redis.aclose()
        _redis = None
        logger.info("Redis client closed")


# --- dedup / cache / rate-limit helpers ---
async def already_seen(event_hash: str) -> bool:
    """Return True if this event hash was seen within the dedup window.

    Atomic: ``SET key 1 NX EX 30`` sets only when absent, so a ``None`` reply means
    the key already existed (a duplicate) — no separate GET, no race.
    """
    was_set = await get_redis().set(dedup_key(event_hash), "1", nx=True, ex=DEDUP_TTL)
    return not was_set


async def get_ip_cache(address: str) -> dict[str, str]:
    """Return the cached enrichment hash for an IP (empty dict if absent/expired)."""
    return await get_redis().hgetall(ip_key(address))


async def set_ip_cache(address: str, mapping: dict[str, str]) -> None:
    """Cache an IP enrichment result hash with the 24h TTL."""
    if not mapping:
        return
    r = get_redis()
    key = ip_key(address)
    await r.hset(key, mapping=mapping)
    await r.expire(key, IP_CACHE_TTL)


async def within_rate_limit(api_name: str, max_per_minute: int) -> bool:
    """Token-per-minute limiter. Returns False once the per-minute quota is exceeded.

    Increments ``rate:osint:{api}`` and sets the 60s TTL on the first hit of a window.
    """
    r = get_redis()
    key = rate_key(api_name)
    count = await r.incr(key)
    if count == 1:
        await r.expire(key, RATE_LIMIT_TTL)
    return count <= max_per_minute


async def set_feed_last_updated(feed_name: str, iso_timestamp: str) -> None:
    await get_redis().set(feed_last_updated_key(feed_name), iso_timestamp)


async def get_feed_last_updated(feed_name: str) -> Optional[str]:
    return await get_redis().get(feed_last_updated_key(feed_name))


__all__ = [
    "IP_CACHE_TTL",
    "DOMAIN_CACHE_TTL",
    "DEDUP_TTL",
    "RATE_LIMIT_TTL",
    "ip_key",
    "domain_key",
    "dedup_key",
    "rate_key",
    "feed_last_updated_key",
    "get_redis",
    "close_redis",
    "already_seen",
    "get_ip_cache",
    "set_ip_cache",
    "within_rate_limit",
    "set_feed_last_updated",
    "get_feed_last_updated",
]
