"""Enrichment pipeline — the async worker pool that turns telemetry into threats.

Workers drain the shared event queue. Every event is first written to the graph
(Phase 2 ingest); network events are then enriched against the OSINT sources. The
per-IP flow mirrors CLAUDE.md "Enrichment Pipeline":

    1. event hash (remote_ip + port + process_hash + timestamp rounded to 5s)
    2. dedup:  SET dedup:{hash} NX EX 30   -> skip if already seen
    3. cache:  HGETALL ip:{remote_ip}      -> reuse if present
    4. fan-out (asyncio.gather): VirusTotal, Censys, Feodo, Emerging Threats
    5. confidence score
    6. cache the result:  HSET ip:{remote_ip} ... EX 86400
    7. if score >= THREAT_CONFIDENCE_THRESHOLD  (or a feed directly attributed it):
         bridge a Threat_Campaign, mark the IP malicious, emit a threat_flag

Design decision: a feed hit is *authoritative attribution* — the feed names the threat
group — so a Feodo/Emerging match bridges a campaign even when the additive score alone
(Feodo +0.40 / Emerging +0.30) sits below the threshold. This is what makes the Phase 3
goal ("a Feodo-listed IP creates a Threat_Campaign within 30s") hold regardless of the
configured threshold.

Per-enricher errors are isolated (``return_exceptions=True`` + per-event try/except) so
one failing API never crashes a worker.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import Awaitable, Callable, Optional

import httpx

from backend.config import get_settings
from backend.enrichment import censys, virustotal
from backend.enrichment.feeds import emerging, feodo
from backend.enrichment.models import EnrichmentResult
from backend.enrichment.notify import ThreatFlag, ThreatNotifier, log_threat
from backend.enrichment.scoring import compute_confidence
from backend.graph.ingest import bridge_campaign, log_event, update_ip_enrichment
from collectors.shared.queue import get_event, task_done
from collectors.shared.schema import UnifiedLogEvent

logger = logging.getLogger(__name__)

DEDUP_WINDOW_SECONDS = 5  # timestamp rounding for the event hash


def compute_event_hash(event: UnifiedLogEvent) -> str:
    """SHA-256 over remote_ip + port + process_hash + 5s-rounded timestamp.

    Rounding to a 5s window collapses bursts of identical connections into one
    enrichment, which the 30s Redis dedup key then suppresses.
    """
    window = int(event.timestamp.timestamp()) // DEDUP_WINDOW_SECONDS * DEDUP_WINDOW_SECONDS
    raw = f"{event.remote_ip}|{event.remote_port}|{event.process_hash}|{window}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class EnrichmentPipeline:
    """Owns the worker pool, the shared HTTP client, and feed refresh."""

    def __init__(
        self,
        on_threat: Optional[ThreatNotifier] = None,
        on_event: Optional[Callable[[UnifiedLogEvent], Awaitable[None]]] = None,
    ) -> None:
        self._settings = get_settings()
        self._on_threat: ThreatNotifier = on_threat or log_threat
        # Called after each successful graph write (wired to the WS broadcaster in main).
        self._on_event = on_event
        self._client: Optional[httpx.AsyncClient] = None
        self._workers: list[asyncio.Task] = []
        self._feed_task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()

    # --- lifecycle ---
    async def start(self) -> None:
        self._warn_missing_keys()
        self._client = httpx.AsyncClient()
        await self._refresh_feeds()  # initial blocking load so first events can match
        self._feed_task = asyncio.create_task(self._feed_refresh_loop())
        self._workers = [
            asyncio.create_task(self._worker(i))
            for i in range(self._settings.enrichment_worker_count)
        ]
        logger.info("Enrichment pipeline started with %d workers", len(self._workers))

    async def stop(self) -> None:
        self._stop.set()
        for task in (*self._workers, self._feed_task):
            if task is not None:
                task.cancel()
        await asyncio.gather(
            *(t for t in (*self._workers, self._feed_task) if t is not None),
            return_exceptions=True,
        )
        if self._client is not None:
            await self._client.aclose()
        logger.info("Enrichment pipeline stopped")

    def _warn_missing_keys(self) -> None:
        if not self._settings.virustotal_api_key:
            logger.warning("VIRUSTOTAL_API_KEY not set — VirusTotal enricher disabled")
        if not (self._settings.censys_api_id and self._settings.censys_api_secret):
            logger.warning("Censys credentials not set — Censys enricher disabled")

    # --- feeds ---
    async def _refresh_feeds(self) -> None:
        assert self._client is not None
        await asyncio.gather(
            feodo.get_feed().refresh(self._client),
            emerging.get_feed().refresh(self._client),
            return_exceptions=True,
        )

    async def _feed_refresh_loop(self) -> None:
        interval = self._settings.feed_refresh_seconds
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval)
            except asyncio.TimeoutError:
                await self._refresh_feeds()

    # --- workers ---
    async def _worker(self, index: int) -> None:
        while not self._stop.is_set():
            try:
                event = await asyncio.wait_for(get_event(), timeout=0.5)
            except asyncio.TimeoutError:
                continue
            try:
                await log_event(event)  # Phase 2 graph ingest for every event
                if self._on_event is not None:
                    await self._on_event(event)  # broadcast node/edge adds to WS clients
                if event.event_type == "network" and event.remote_ip:
                    await self._enrich_ip(event)
            except Exception:  # noqa: BLE001 - keep worker alive on any failure
                logger.exception("Worker %d failed on %s event", index, event.event_type)
            finally:
                task_done()

    # --- per-IP enrichment ---
    async def _enrich_ip(self, event: UnifiedLogEvent) -> None:
        # Imported here so unit tests can patch redis helpers without a live server.
        from backend.cache.redis import already_seen, get_ip_cache, set_ip_cache

        ip = event.remote_ip
        assert ip is not None

        if await already_seen(compute_event_hash(event)):
            return  # identical event within the 30s window — already handled

        cached = await get_ip_cache(ip)
        if cached:
            result = EnrichmentResult.from_cache_mapping(cached)
        else:
            result = await self._fan_out(ip)
            await set_ip_cache(ip, result.to_cache_mapping())

        score = compute_confidence(result)
        # A feed hit is definitive attribution even when the additive score is < threshold.
        is_threat = score >= self._settings.threat_confidence_threshold or result.campaign is not None

        await update_ip_enrichment(
            ip,
            enriched_at=event.timestamp,
            vt_score=result.vt_malicious or None,
            censys_asn=result.censys_asn,
            country=result.country,
            is_malicious=is_threat,
        )

        if is_threat:
            campaign = result.campaign or "Unattributed Threat"
            source_feed = result.source_feed or "composite"
            await bridge_campaign(
                ip,
                campaign=campaign,
                confidence=score,
                source_feed=source_feed,
                timestamp=event.timestamp,
            )
            await self._notify_threat(ip, campaign, score)

    async def _fan_out(self, ip: str) -> EnrichmentResult:
        assert self._client is not None
        results = await asyncio.gather(
            virustotal.enrich(self._client, ip),
            censys.enrich(self._client, ip),
            feodo.enrich(ip),
            emerging.enrich(ip),
            return_exceptions=True,
        )
        clean: list[EnrichmentResult] = []
        for r in results:
            if isinstance(r, EnrichmentResult):
                clean.append(r)
            else:
                logger.warning("Enricher raised during fan-out for %s: %s", ip, r)
        return EnrichmentResult.combine(clean)

    async def _notify_threat(self, ip: str, campaign: str, confidence: float) -> None:
        try:
            await self._on_threat(ThreatFlag(node_id=ip, campaign=campaign, confidence=confidence))
        except Exception:  # noqa: BLE001 - notification must never break enrichment
            logger.exception("Threat notifier failed for %s", ip)


__all__ = ["EnrichmentPipeline", "compute_event_hash", "DEDUP_WINDOW_SECONDS"]
