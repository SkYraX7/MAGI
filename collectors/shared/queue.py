"""In-process event bus shared between collectors and the enrichment pipeline.

A single :class:`asyncio.Queue` singleton decouples ingestion from enrichment: the
collector daemons drop validated events and return instantly to listening, while
separate worker pools drain the queue (CLAUDE.md "API Asynchronous Bottleneck").

Always import the helpers from this module — do **not** instantiate an ``asyncio.Queue``
inline elsewhere, or producers and consumers will end up on different queues.

For multi-host deployments this is the seam to swap for Redis Streams; the helper
signatures are intentionally transport-agnostic.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from collectors.shared.schema import UnifiedLogEvent

logger = logging.getLogger(__name__)

# Bound the queue so a stalled enrichment pool applies backpressure instead of
# exhausting memory during a traffic spike.
DEFAULT_MAXSIZE = 10_000

_queue: Optional["asyncio.Queue[UnifiedLogEvent]"] = None


def get_queue() -> "asyncio.Queue[UnifiedLogEvent]":
    """Return the process-wide event queue, creating it lazily on first use.

    Created lazily (not at import time) so it binds to the running event loop of
    whichever process imports it, rather than a loop that may not exist yet.
    """
    global _queue
    if _queue is None:
        _queue = asyncio.Queue(maxsize=DEFAULT_MAXSIZE)
        logger.debug("Initialized shared event queue (maxsize=%d)", DEFAULT_MAXSIZE)
    return _queue


async def put_event(event: UnifiedLogEvent) -> None:
    """Enqueue an event, blocking if the queue is full (applies backpressure)."""
    await get_queue().put(event)


def put_event_nowait(event: UnifiedLogEvent) -> bool:
    """Enqueue without blocking. Returns ``False`` and logs if the queue is full.

    Collectors prefer this in tight syscall/event callbacks so a slow consumer can
    never block telemetry capture — a dropped event is logged, never silent.
    """
    try:
        get_queue().put_nowait(event)
        return True
    except asyncio.QueueFull:
        logger.warning(
            "Event queue full (maxsize=%d); dropping %s event from %s",
            DEFAULT_MAXSIZE,
            event.event_type,
            event.platform,
        )
        return False


async def get_event() -> UnifiedLogEvent:
    """Dequeue the next event, awaiting until one is available."""
    return await get_queue().get()


def task_done() -> None:
    """Mark a dequeued event as processed (mirrors :meth:`asyncio.Queue.task_done`)."""
    get_queue().task_done()


def qsize() -> int:
    """Current number of queued events (approximate; useful for metrics/health)."""
    return get_queue().qsize() if _queue is not None else 0


def _reset_for_tests() -> None:
    """Drop the singleton so each test starts with a fresh queue. Test-only."""
    global _queue
    _queue = None


__all__ = [
    "get_queue",
    "put_event",
    "put_event_nowait",
    "get_event",
    "task_done",
    "qsize",
    "DEFAULT_MAXSIZE",
]
