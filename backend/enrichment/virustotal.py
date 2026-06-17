"""VirusTotal IP-reputation enricher (API v3).

Skips cleanly when no API key is configured, and enforces the free-tier rate limit
via the shared Redis counter. The response is validated with Pydantic before use — we
never trust the external JSON shape (CLAUDE.md security checklist).
"""

from __future__ import annotations

import logging
from typing import Optional

import httpx
from pydantic import BaseModel, ConfigDict

from backend.cache.redis import within_rate_limit
from backend.config import get_settings
from backend.enrichment.http import get_json_with_retry
from backend.enrichment.models import EnrichmentResult

logger = logging.getLogger(__name__)

API_NAME = "virustotal"
BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses"


# --- response validation models (lenient: ignore unknown fields) ---
class _Stats(BaseModel):
    model_config = ConfigDict(extra="ignore")
    malicious: int = 0


class _Attributes(BaseModel):
    model_config = ConfigDict(extra="ignore")
    last_analysis_stats: _Stats = _Stats()
    country: Optional[str] = None


class _Data(BaseModel):
    model_config = ConfigDict(extra="ignore")
    attributes: _Attributes = _Attributes()


class _Response(BaseModel):
    model_config = ConfigDict(extra="ignore")
    data: _Data


def parse_response(payload: dict) -> EnrichmentResult:
    """Map a validated VirusTotal response to an :class:`EnrichmentResult`."""
    parsed = _Response.model_validate(payload)
    attrs = parsed.data.attributes
    return EnrichmentResult(
        vt_present=True,
        vt_malicious=attrs.last_analysis_stats.malicious,
        country=attrs.country,
    )


async def enrich(client: httpx.AsyncClient, ip: str) -> EnrichmentResult:
    """Query VirusTotal for an IP; returns an empty result if skipped or failed."""
    settings = get_settings()
    if not settings.virustotal_api_key:
        return EnrichmentResult()  # no key: skip (warning logged once at startup)

    if not await within_rate_limit(API_NAME, settings.virustotal_rate_per_minute):
        logger.info("VirusTotal per-minute rate limit reached; skipping %s", ip)
        return EnrichmentResult()

    payload = await get_json_with_retry(
        client,
        f"{BASE_URL}/{ip}",
        api_name=API_NAME,
        headers={"x-apikey": settings.virustotal_api_key},
    )
    if payload is None:
        return EnrichmentResult()
    try:
        return parse_response(payload)
    except Exception as exc:  # noqa: BLE001 - malformed shape => skip, never crash worker
        logger.warning("VirusTotal response parse failed for %s: %s", ip, exc)
        return EnrichmentResult()


__all__ = ["enrich", "parse_response", "API_NAME"]
