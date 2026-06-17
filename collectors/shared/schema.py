"""Unified telemetry schema shared by every MAGI collector.

Both the Windows (Sysmon/EVTX) and Linux (eBPF/auditd) daemons normalize their
platform-specific events into :class:`UnifiedLogEvent` before enqueuing. Malformed
events are rejected by Pydantic validation and dropped by the collector — never
silently swallowed.

Design notes
------------
* ``process_hash`` is normalized to lowercase here so case-variant hashes do not
  create duplicate :Process nodes downstream (see CLAUDE.md security checklist).
* The four ``event_type`` values map directly onto the graph ingest functions:
  ``process`` / ``network`` / ``image_load`` -> log_*_event, ``dns`` -> log_dns_event.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

EventType = Literal["process", "network", "image_load", "dns"]
Direction = Literal["inbound", "outbound"]
Protocol = Literal["tcp", "udp"]


class UnifiedLogEvent(BaseModel):
    """Platform-agnostic endpoint telemetry event.

    A single model carries all four event types. Fields outside the relevant
    block are ``None`` for a given event (e.g. a ``dns`` event leaves the network
    fields unset). The :meth:`_check_required_per_type` validator enforces that the
    minimum fields for each event type are present.
    """

    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    platform: str = Field(min_length=1)  # hostname or cloud instance ID
    event_type: EventType
    source_process: str = Field(min_length=1)
    process_hash: str = ""  # SHA-256; empty string if unavailable
    pid: int = Field(ge=0)
    parent_process: Optional[str] = None
    parent_hash: Optional[str] = None

    # --- process event fields ---
    command_line: Optional[str] = None      # full command line, when the source provides it

    # --- network event fields ---
    direction: Optional[Direction] = None
    local_ip: Optional[str] = None
    local_port: Optional[int] = Field(default=None, ge=0, le=65535)
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = Field(default=None, ge=0, le=65535)
    protocol: Optional[Protocol] = None

    # --- dns event fields ---
    queried_domain: Optional[str] = None

    @field_validator("process_hash", "parent_hash")
    @classmethod
    def _normalize_hash(cls, v: Optional[str]) -> Optional[str]:
        """Lowercase + trim hashes so MERGE never creates case-variant duplicates."""
        if v is None:
            return None
        return v.strip().lower()

    @field_validator("timestamp")
    @classmethod
    def _ensure_tz_aware(cls, v: datetime) -> datetime:
        """Coerce naive timestamps to UTC; eBPF/auditd often emit naive times."""
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v

    @model_validator(mode="after")
    def _check_required_per_type(self) -> "UnifiedLogEvent":
        """Enforce the minimum fields each event type needs to be useful downstream."""
        if self.event_type == "network":
            if not self.remote_ip:
                raise ValueError("network event requires remote_ip")
            if self.direction is None:
                raise ValueError("network event requires direction")
        elif self.event_type == "dns":
            if not self.queried_domain:
                raise ValueError("dns event requires queried_domain")
        # process / image_load only need the common fields (source_process, pid).
        return self


__all__ = ["UnifiedLogEvent", "EventType", "Direction", "Protocol"]
