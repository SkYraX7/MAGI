"""Windows telemetry collector — tails the Sysmon/Operational event channel.

Subscribes to ``Microsoft-Windows-Sysmon/Operational`` and normalizes the four
Sysmon event IDs MAGI cares about into :class:`UnifiedLogEvent`:

    ID 1  Process Create   -> event_type "process"
    ID 3  Network Connect  -> event_type "network"
    ID 7  Image Loaded     -> event_type "image_load"   (DLL side-loading / LOLBins)
    ID 22 DNS Query        -> event_type "dns"

The XML→event mapping (:func:`parse_sysmon_xml`) is a pure function with no Windows
dependency so it can be unit-tested with captured event XML. The live subscription
(:class:`SysmonCollector`) requires ``pywin32`` and ``SeSecurityPrivilege`` (run as
Administrator). Malformed events are logged and dropped, never silently swallowed.

Run standalone (Phase 1 acceptance — emits validated JSON to stdout):

    python -m collectors.windows.sysmon_collector
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from datetime import datetime, timezone
from typing import Optional
from xml.etree import ElementTree as ET

from collectors.shared.queue import put_event_nowait
from collectors.shared.runtime import drain_to_stdout, install_shutdown_handler
from collectors.shared.schema import UnifiedLogEvent

logger = logging.getLogger(__name__)

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
# Only the four event IDs we map; the query filters server-side so we never render
# events we would just discard.
SYSMON_QUERY = "*[System[(EventID=1 or EventID=3 or EventID=7 or EventID=22)]]"

# Windows event log XML namespace.
_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


# --------------------------------------------------------------------------- #
# Pure parsing helpers (no pywin32 dependency — unit-testable)                 #
# --------------------------------------------------------------------------- #
def _basename(path: Optional[str]) -> Optional[str]:
    """Return the executable name from a Windows image path (``C:\\...\\x.exe`` -> ``x.exe``)."""
    if not path:
        return None
    return path.replace("/", "\\").rsplit("\\", 1)[-1] or path


def _extract_sha256(hashes: Optional[str]) -> str:
    """Pull the SHA256 out of a Sysmon ``Hashes`` field.

    Sysmon emits e.g. ``SHA256=ABC...,MD5=...,IMPHASH=...``. Returns lowercase hash,
    or empty string when absent (schema normalizes case again downstream).
    """
    if not hashes:
        return ""
    for part in hashes.split(","):
        key, _, value = part.partition("=")
        if key.strip().upper() == "SHA256":
            return value.strip().lower()
    return ""


def _parse_utc_time(raw: Optional[str], fallback: Optional[str]) -> datetime:
    """Parse Sysmon ``UtcTime`` (``YYYY-MM-DD HH:MM:SS.fff``); fall back to System time."""
    if raw:
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    if fallback:
        # System/TimeCreated SystemTime is ISO-8601, often with nanosecond precision
        # (9 fractional digits) which fromisoformat rejects — trim to microseconds.
        iso = re.sub(r"(\.\d{6})\d+", r"\1", fallback).replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(iso)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _event_data(root: ET.Element) -> dict[str, str]:
    """Flatten ``<EventData><Data Name='X'>v</Data></EventData>`` into a dict."""
    data: dict[str, str] = {}
    for node in root.findall("./e:EventData/e:Data", _NS):
        name = node.get("Name")
        if name is not None:
            data[name] = node.text or ""
    return data


def parse_sysmon_xml(xml: str) -> Optional[UnifiedLogEvent]:
    """Map one rendered Sysmon event XML string to a :class:`UnifiedLogEvent`.

    Returns ``None`` for event IDs we do not handle or events that fail validation.
    """
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        logger.warning("Dropping unparseable Sysmon XML: %s", exc)
        return None

    system = root.find("./e:System", _NS)
    if system is None:
        return None

    eid_node = system.find("./e:EventID", _NS)
    if eid_node is None or not eid_node.text:
        return None
    event_id = int(eid_node.text)

    computer = system.findtext("./e:Computer", default="unknown", namespaces=_NS)
    time_created = system.find("./e:TimeCreated", _NS)
    system_time = time_created.get("SystemTime") if time_created is not None else None

    data = _event_data(root)
    timestamp = _parse_utc_time(data.get("UtcTime"), system_time)
    pid = int(data.get("ProcessId") or 0)
    image = _basename(data.get("Image"))

    try:
        if event_id == 1:  # Process Create
            return UnifiedLogEvent(
                timestamp=timestamp,
                platform=computer,
                event_type="process",
                source_process=image or "unknown",
                process_hash=_extract_sha256(data.get("Hashes")),
                pid=pid,
                parent_process=_basename(data.get("ParentImage")),
                command_line=data.get("CommandLine"),
            )
        if event_id == 3:  # Network Connect
            return UnifiedLogEvent(
                timestamp=timestamp,
                platform=computer,
                event_type="network",
                source_process=image or "unknown",
                process_hash="",  # Sysmon ID3 carries no hash
                pid=pid,
                direction="outbound" if data.get("Initiated") == "true" else "inbound",
                protocol=(data.get("Protocol") or "tcp").lower(),
                local_ip=data.get("SourceIp"),
                local_port=int(data["SourcePort"]) if data.get("SourcePort") else None,
                remote_ip=data.get("DestinationIp"),
                remote_port=int(data["DestinationPort"]) if data.get("DestinationPort") else None,
            )
        if event_id == 7:  # Image Loaded — hash is of the loaded module (sideload signal)
            return UnifiedLogEvent(
                timestamp=timestamp,
                platform=computer,
                event_type="image_load",
                source_process=image or "unknown",
                process_hash=_extract_sha256(data.get("Hashes")),
                pid=pid,
            )
        if event_id == 22:  # DNS Query
            return UnifiedLogEvent(
                timestamp=timestamp,
                platform=computer,
                event_type="dns",
                source_process=image or "unknown",
                pid=pid,
                queried_domain=data.get("QueryName"),
            )
    except ValueError as exc:
        logger.warning("Dropping invalid Sysmon event ID %d: %s", event_id, exc)
        return None

    return None  # event ID not handled


# --------------------------------------------------------------------------- #
# Live subscription (requires pywin32 + Administrator)                         #
# --------------------------------------------------------------------------- #
class SysmonCollector:
    """Subscribes to the Sysmon channel and pushes mapped events onto the shared queue."""

    def __init__(self, *, start_at_oldest: bool = False) -> None:
        self._start_at_oldest = start_at_oldest

    def _poll_loop(self, loop: asyncio.AbstractEventLoop, stop_event: asyncio.Event) -> None:
        """Blocking subscription loop, run in an executor thread.

        pywin32 is synchronous, so events are handed back to the asyncio loop with
        ``call_soon_threadsafe`` to keep the queue single-threaded.
        """
        try:
            import win32event
            import win32evtlog
        except ImportError as exc:  # pragma: no cover - platform guard
            raise RuntimeError(
                "Windows collector requires pywin32: pip install 'magi[windows]'"
            ) from exc

        flags = (
            win32evtlog.EvtSubscribeStartAtOldestRecord
            if self._start_at_oldest
            else win32evtlog.EvtSubscribeToFutureEvents
        )
        signal_event = win32event.CreateEvent(None, 0, 0, None)
        try:
            subscription = win32evtlog.EvtSubscribe(
                SYSMON_CHANNEL,
                flags,
                SignalEvent=signal_event,
                Query=SYSMON_QUERY,
            )
        except Exception as exc:  # pragma: no cover - environment dependent
            raise RuntimeError(
                f"Failed to subscribe to {SYSMON_CHANNEL}. Is Sysmon installed and "
                f"is this process elevated (SeSecurityPrivilege)? Original: {exc}"
            ) from exc

        logger.info("Subscribed to %s (query=%s)", SYSMON_CHANNEL, SYSMON_QUERY)
        while not stop_event.is_set():
            # Wake at least every 500ms so shutdown is responsive even with no events.
            win32event.WaitForSingleObject(signal_event, 500)
            self._drain_subscription(win32evtlog, subscription, loop)

    def _drain_subscription(self, win32evtlog, subscription, loop) -> None:
        """Render and enqueue every pending event in the subscription result set."""
        while True:
            try:
                handles = win32evtlog.EvtNext(subscription, 32)
            except Exception:  # ERROR_NO_MORE_ITEMS (259) once the batch is exhausted
                return
            if not handles:
                return
            for handle in handles:
                try:
                    xml = win32evtlog.EvtRender(handle, win32evtlog.EvtRenderEventXml)
                except Exception as exc:  # pragma: no cover
                    logger.warning("Failed to render Sysmon event: %s", exc)
                    continue
                event = parse_sysmon_xml(xml)
                if event is not None:
                    loop.call_soon_threadsafe(put_event_nowait, event)

    async def run(self, stop_event: asyncio.Event) -> None:
        """Run the blocking poll loop in the default thread pool until ``stop_event``."""
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._poll_loop, loop, stop_event)


async def main() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    stop_event = asyncio.Event()
    install_shutdown_handler(stop_event)

    collector = SysmonCollector()
    printer = asyncio.create_task(drain_to_stdout(stop_event))
    try:
        await collector.run(stop_event)
    finally:
        stop_event.set()
        await printer
    logger.info("Sysmon collector stopped cleanly")


if __name__ == "__main__":
    asyncio.run(main())
