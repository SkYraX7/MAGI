"""Shared daemon runtime helpers: signal handling and a stdout event drainer.

Both collectors must catch SIGTERM/SIGINT, flush buffered events to the queue, then
exit cleanly (CLAUDE.md Phase 1 "Graceful shutdown"). They also share the Phase 1
acceptance behavior: emit validated ``UnifiedLogEvent`` JSON to stdout. This module
provides both so the Windows and Linux daemons stay in lockstep.
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
from typing import Iterable

from collectors.shared.queue import get_event, task_done
from collectors.shared.schema import UnifiedLogEvent

logger = logging.getLogger(__name__)


def install_shutdown_handler(stop_event: asyncio.Event) -> None:
    """Wire SIGINT/SIGTERM to set ``stop_event`` for a cooperative shutdown.

    Uses ``loop.add_signal_handler`` where supported (POSIX) and falls back to
    ``signal.signal`` on platforms that lack it (Windows ProactorEventLoop).
    """
    loop = asyncio.get_running_loop()
    signals: Iterable[signal.Signals] = (signal.SIGINT, signal.SIGTERM)

    def _request_stop(signame: str) -> None:
        if not stop_event.is_set():
            logger.info("Received %s — initiating graceful shutdown", signame)
            stop_event.set()

    for sig in signals:
        try:
            loop.add_signal_handler(sig, _request_stop, sig.name)
        except (NotImplementedError, RuntimeError):
            # Windows: add_signal_handler is unsupported for SIGTERM. Fall back.
            try:
                signal.signal(sig, lambda *_s, _n=sig.name: _request_stop(_n))
            except (ValueError, OSError):
                logger.debug("Could not install handler for %s on this platform", sig.name)


async def drain_to_stdout(stop_event: asyncio.Event) -> None:
    """Consume events off the shared queue and print each as one JSON line.

    This is the Phase 1 standalone demonstration consumer (newline-delimited JSON,
    one event per line). Real deployments run the enrichment pipeline here instead.
    """
    while not stop_event.is_set():
        try:
            event: UnifiedLogEvent = await asyncio.wait_for(get_event(), timeout=0.5)
        except asyncio.TimeoutError:
            continue
        try:
            sys.stdout.write(event.model_dump_json() + "\n")
            sys.stdout.flush()
        finally:
            task_done()


__all__ = ["install_shutdown_handler", "drain_to_stdout"]
