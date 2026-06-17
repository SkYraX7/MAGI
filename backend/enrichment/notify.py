"""Threat-flag notification seam.

The pipeline emits a :class:`ThreatFlag` whenever an IP is confirmed malicious. In
Phase 3 the default sink just logs; Phase 4 replaces it with the WebSocket broadcast
(``{"type": "threat_flag", "data": {...}}``) without touching the pipeline.
"""

from __future__ import annotations

import logging
from typing import Awaitable, Callable

from pydantic import BaseModel

logger = logging.getLogger(__name__)


class ThreatFlag(BaseModel):
    """Payload mirroring the WS ``threat_flag`` message's ``data`` field."""

    node_id: str
    campaign: str
    confidence: float


# An async sink for threat flags. Swap for the WS broadcaster in Phase 4.
ThreatNotifier = Callable[[ThreatFlag], Awaitable[None]]


async def log_threat(flag: ThreatFlag) -> None:
    """Default notifier: log the flag at WARNING."""
    logger.warning(
        "THREAT FLAGGED: %s -> %s (confidence %.2f)",
        flag.node_id,
        flag.campaign,
        flag.confidence,
    )


__all__ = ["ThreatFlag", "ThreatNotifier", "log_threat"]
