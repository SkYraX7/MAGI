"""Censys host-tags enricher (Search API v2).

Pulls host labels/tags, ASN, and country for an IP. Skips when credentials are not
configured. Response validated with Pydantic; tags lowercased so scoring's
``scanner`` / ``tor-exit`` comparison is case-insensitive.
"""

from __future__ import annotations

import logging
from typing import Optional

import httpx
from pydantic import BaseModel, ConfigDict, Field

from backend.cache.redis import within_rate_limit
from backend.config import get_settings
from backend.enrichment.http import get_json_with_retry
from backend.enrichment.models import EnrichmentResult

logger = logging.getLogger(__name__)

API_NAME = "censys"
BASE_URL = "https://search.censys.io/api/v2/hosts"
# Censys paid tiers vary; default conservatively. Lives alongside VT's limiter.
RATE_PER_MINUTE = 4


class _AutonomousSystem(BaseModel):
    model_config = ConfigDict(extra="ignore")
    asn: Optional[int] = None


class _Location(BaseModel):
    model_config = ConfigDict(extra="ignore")
    country: Optional[str] = None


class _Result(BaseModel):
    model_config = ConfigDict(extra="ignore")
    autonomous_system: _AutonomousSystem = _AutonomousSystem()
    location: _Location = _Location()
    labels: list[str] = Field(default_factory=list)


class _Response(BaseModel):
    model_config = ConfigDict(extra="ignore")
    result: _Result = _Result()


def parse_response(payload: dict) -> EnrichmentResult:
    """Map a validated Censys response to an :class:`EnrichmentResult`."""
    parsed = _Response.model_validate(payload)
    result = parsed.result
    return EnrichmentResult(
        censys_tags=[t.lower() for t in result.labels],
        censys_asn=result.autonomous_system.asn,
        country=result.location.country,
    )


async def enrich(client: httpx.AsyncClient, ip: str) -> EnrichmentResult:
    """Query Censys for an IP; returns an empty result if skipped or failed."""
    settings = get_settings()
    if not (settings.censys_api_id and settings.censys_api_secret):
        return EnrichmentResult()  # no creds: skip (warning logged once at startup)

    if not await within_rate_limit(API_NAME, RATE_PER_MINUTE):
        logger.info("Censys per-minute rate limit reached; skipping %s", ip)
        return EnrichmentResult()

    payload = await get_json_with_retry(
        client,
        f"{BASE_URL}/{ip}",
        api_name=API_NAME,
        auth=(settings.censys_api_id, settings.censys_api_secret),
    )
    if payload is None:
        return EnrichmentResult()
    try:
        return parse_response(payload)
    except Exception as exc:  # noqa: BLE001 - malformed shape => skip, never crash worker
        logger.warning("Censys response parse failed for %s: %s", ip, exc)
        return EnrichmentResult()


__all__ = ["enrich", "parse_response", "API_NAME"]
