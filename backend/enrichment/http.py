"""Shared async HTTP helper for the OSINT enrichers.

Implements the CLAUDE.md "API failure handling" contract in one place:
  * HTTP 429 -> exponential backoff (1s -> 2s -> 4s), give up after 3 retries,
    log a warning, and return ``None`` so the caller skips that enricher.
  * Any other error returns ``None`` (never raises into the worker) so one failing
    API can't crash the enrichment worker.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
BASE_BACKOFF = 1.0


async def get_json_with_retry(
    client: httpx.AsyncClient,
    url: str,
    *,
    api_name: str,
    headers: Optional[dict[str, str]] = None,
    params: Optional[dict[str, Any]] = None,
    auth: Optional[tuple[str, str]] = None,
) -> Optional[dict]:
    """GET ``url`` and return parsed JSON, or ``None`` on rate-limit/error exhaustion."""
    delay = BASE_BACKOFF
    for attempt in range(MAX_RETRIES + 1):
        try:
            resp = await client.get(url, headers=headers, params=params, auth=auth)
        except httpx.HTTPError as exc:
            logger.warning("%s request error: %s", api_name, exc)
            return None

        if resp.status_code == 429:
            if attempt == MAX_RETRIES:
                logger.warning("%s rate-limited (429); gave up after %d retries", api_name, MAX_RETRIES)
                return None
            logger.info("%s 429; backing off %.1fs (attempt %d)", api_name, delay, attempt + 1)
            await asyncio.sleep(delay)
            delay *= 2
            continue

        if resp.status_code == 404:
            return None  # "no data for this indicator" is a normal, non-error answer

        if resp.status_code >= 400:
            logger.warning("%s returned HTTP %d", api_name, resp.status_code)
            return None

        try:
            return resp.json()
        except ValueError as exc:
            logger.warning("%s returned non-JSON body: %s", api_name, exc)
            return None

    return None


__all__ = ["get_json_with_retry", "MAX_RETRIES", "BASE_BACKOFF"]
