"""Linux telemetry collector — eBPF via bcc, with a graceful auditd fallback.

Primary path: load :mod:`ebpf_probes.c` with bcc, attach to the ``sys_enter_connect``
and ``sys_enter_execve`` tracepoints, and stream events off perf ring buffers. This
requires kernel >= 5.8 and ``CAP_BPF``/``CAP_PERFMON`` (run as root, or grant via
``setcap 'cap_bpf,cap_perfmon+ep' $(which python3)``).

Fallback path: when eBPF is unavailable (missing bcc, insufficient privilege, older
kernel) the collector tails ``/var/log/audit/audit.log`` and parses ``EXECVE`` and
``SOCKADDR`` records instead — lower fidelity, but keeps telemetry flowing.

Both paths normalize to :class:`UnifiedLogEvent`. The sockaddr-hex decoder used by the
auditd path is a pure function (:func:`parse_sockaddr_hex`) so it can be unit-tested.

Run standalone (Phase 1 acceptance — emits validated JSON to stdout):

    sudo python -m collectors.linux.ebpf_collector
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import struct
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from collectors.shared.queue import put_event_nowait
from collectors.shared.runtime import drain_to_stdout, install_shutdown_handler
from collectors.shared.schema import UnifiedLogEvent

logger = logging.getLogger(__name__)

PROBES_PATH = Path(__file__).with_name("ebpf_probes.c")
AUDIT_LOG_PATH = Path(os.getenv("AUDITD_LOG_PATH", "/var/log/audit/audit.log"))

AF_INET = socket.AF_INET
AF_INET6 = socket.AF_INET6


# --------------------------------------------------------------------------- #
# Pure parsing helpers (no bcc / kernel dependency — unit-testable)            #
# --------------------------------------------------------------------------- #
def parse_sockaddr_hex(saddr: str) -> Optional[tuple[str, int]]:
    """Decode an auditd ``SOCKADDR saddr=`` hex blob into ``(ip, port)``.

    The blob is the raw ``struct sockaddr``: family is little-endian, port is
    big-endian. Returns ``None`` for non-IP families (AF_UNIX, AF_NETLINK, …) or
    malformed input.
    """
    try:
        raw = bytes.fromhex(saddr.strip())
    except ValueError:
        return None
    if len(raw) < 4:
        return None

    family = struct.unpack_from("<H", raw, 0)[0]
    if family == AF_INET:
        if len(raw) < 8:
            return None
        port = struct.unpack_from("!H", raw, 2)[0]
        ip = socket.inet_ntop(AF_INET, raw[4:8])
        return ip, port
    if family == AF_INET6:
        if len(raw) < 28:
            return None
        port = struct.unpack_from("!H", raw, 2)[0]
        ip = socket.inet_ntop(AF_INET6, raw[8:24])
        return ip, port
    return None


def _decode_comm(raw: bytes) -> str:
    """Decode a fixed-width kernel ``comm`` field, stripping the NUL padding."""
    return raw.split(b"\x00", 1)[0].decode("utf-8", "replace") or "unknown"


# --------------------------------------------------------------------------- #
# eBPF (bcc) path                                                             #
# --------------------------------------------------------------------------- #
class EbpfCollector:
    """Loads the eBPF probes and streams connect/execve events onto the shared queue."""

    @staticmethod
    def available() -> bool:
        """True if bcc is importable (does not prove sufficient privilege)."""
        try:
            import bcc  # noqa: F401
        except ImportError:
            return False
        return True

    def _connect_handler(self, bpf, loop: asyncio.AbstractEventLoop):
        def handle(cpu, data, size):
            evt = bpf["connect_events"].event(data)
            family = AF_INET if evt.family == AF_INET else AF_INET6
            if family == AF_INET:
                ip = socket.inet_ntop(AF_INET, struct.pack("I", evt.daddr_v4))
            else:
                ip = socket.inet_ntop(AF_INET6, bytes(evt.daddr_v6))
            port = socket.ntohs(evt.dport)
            try:
                event = UnifiedLogEvent(
                    timestamp=datetime.now(timezone.utc),
                    platform=socket.gethostname(),
                    event_type="network",
                    source_process=_decode_comm(bytes(evt.comm)),
                    process_hash="",  # syscall tracepoints carry no binary hash
                    pid=evt.pid,
                    direction="outbound",  # connect() is always outbound-initiated
                    protocol="tcp",
                    remote_ip=ip,
                    remote_port=port,
                )
            except ValueError as exc:
                logger.warning("Dropping invalid connect event: %s", exc)
                return
            loop.call_soon_threadsafe(put_event_nowait, event)

        return handle

    def _exec_handler(self, bpf, loop: asyncio.AbstractEventLoop):
        def handle(cpu, data, size):
            evt = bpf["exec_events"].event(data)
            filename = bytes(evt.filename).split(b"\x00", 1)[0].decode("utf-8", "replace")
            comm = _decode_comm(bytes(evt.comm))
            try:
                event = UnifiedLogEvent(
                    timestamp=datetime.now(timezone.utc),
                    platform=socket.gethostname(),
                    event_type="process",
                    source_process=filename or comm,
                    process_hash="",
                    pid=evt.pid,
                    parent_process=None,  # ppid known (evt.ppid); name resolved downstream
                )
            except ValueError as exc:
                logger.warning("Dropping invalid execve event: %s", exc)
                return
            loop.call_soon_threadsafe(put_event_nowait, event)

        return handle

    def _poll_loop(self, loop: asyncio.AbstractEventLoop, stop_event: asyncio.Event) -> None:
        from bcc import BPF  # imported here so module import works off-Linux

        logger.info("Compiling and loading eBPF probes from %s", PROBES_PATH)
        bpf = BPF(src_file=str(PROBES_PATH))
        bpf["connect_events"].open_perf_buffer(self._connect_handler(bpf, loop))
        bpf["exec_events"].open_perf_buffer(self._exec_handler(bpf, loop))
        logger.info("eBPF probes attached; streaming connect + execve events")

        while not stop_event.is_set():
            # 500ms poll keeps shutdown responsive between event bursts.
            bpf.perf_buffer_poll(timeout=500)

    async def run(self, stop_event: asyncio.Event) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._poll_loop, loop, stop_event)


# --------------------------------------------------------------------------- #
# auditd fallback path                                                         #
# --------------------------------------------------------------------------- #
class AuditdCollector:
    """Tails the audit log and emits process/network events when eBPF is unavailable."""

    def __init__(self, log_path: Path = AUDIT_LOG_PATH) -> None:
        self._log_path = log_path
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    @staticmethod
    def available(log_path: Path = AUDIT_LOG_PATH) -> bool:
        return log_path.exists() and os.access(log_path, os.R_OK)

    def _enqueue(self, event: UnifiedLogEvent) -> None:
        """Hand an event to the asyncio loop's queue from the tail thread, safely."""
        if self._loop is not None:
            self._loop.call_soon_threadsafe(put_event_nowait, event)
        else:  # no loop bound (e.g. direct unit-test call) — enqueue inline
            put_event_nowait(event)

    def _emit_execve(self, comm: str, exe: str, pid: int) -> None:
        try:
            event = UnifiedLogEvent(
                timestamp=datetime.now(timezone.utc),
                platform=socket.gethostname(),
                event_type="process",
                source_process=exe or comm or "unknown",
                process_hash="",
                pid=pid,
            )
        except ValueError as exc:
            logger.warning("Dropping invalid auditd execve: %s", exc)
            return
        self._enqueue(event)

    def _emit_connect(self, comm: str, pid: int, ip: str, port: int) -> None:
        try:
            event = UnifiedLogEvent(
                timestamp=datetime.now(timezone.utc),
                platform=socket.gethostname(),
                event_type="network",
                source_process=comm or "unknown",
                process_hash="",
                pid=pid,
                direction="outbound",
                protocol="tcp",
                remote_ip=ip,
                remote_port=port,
            )
        except ValueError as exc:
            logger.warning("Dropping invalid auditd connect: %s", exc)
            return
        self._enqueue(event)

    def _process_record(self, line: str) -> None:
        """Parse one audit record line and emit an event if it is exec/connect.

        auditd splits an event across several ``type=`` records; we treat SYSCALL
        (comm/exe/pid) and SOCKADDR records independently here for simplicity — good
        enough for the fallback. Fields look like ``key=value`` space-separated.
        """
        fields = dict(
            tok.split("=", 1) for tok in line.split() if "=" in tok and not tok.startswith("msg=")
        )
        rtype = None
        if line.startswith("type="):
            rtype = line[5:].split(None, 1)[0]

        comm = fields.get("comm", "").strip('"')
        exe = fields.get("exe", "").strip('"')
        pid = int(fields["pid"]) if fields.get("pid", "").isdigit() else 0

        if rtype == "SOCKADDR" and "saddr" in fields:
            parsed = parse_sockaddr_hex(fields["saddr"])
            if parsed:
                self._emit_connect(comm, pid, parsed[0], parsed[1])
        elif rtype == "SYSCALL" and fields.get("syscall") in {"59", "221"}:  # execve/execveat
            self._emit_execve(comm, exe, pid)

    def _tail_loop(self, stop_event: asyncio.Event) -> None:
        logger.info("Falling back to auditd; tailing %s", self._log_path)
        with self._log_path.open("r", errors="replace") as fh:
            fh.seek(0, os.SEEK_END)  # start at the tail; only new events
            while not stop_event.is_set():
                line = fh.readline()
                if not line:
                    # At EOF; brief sleep before re-checking for appended lines.
                    time.sleep(0.25)
                    continue
                try:
                    self._process_record(line.strip())
                except Exception as exc:  # never let one bad line kill the tail
                    logger.debug("Skipping unparseable audit line: %s", exc)

    async def run(self, stop_event: asyncio.Event) -> None:
        self._loop = asyncio.get_running_loop()
        await self._loop.run_in_executor(None, self._tail_loop, stop_event)


# --------------------------------------------------------------------------- #
# Selection + entrypoint                                                       #
# --------------------------------------------------------------------------- #
def select_collector() -> "EbpfCollector | AuditdCollector":
    """Pick eBPF if bcc is importable, otherwise the auditd fallback."""
    if EbpfCollector.available():
        return EbpfCollector()
    logger.warning("bcc not available; using auditd fallback collector")
    return AuditdCollector()


async def main() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    stop_event = asyncio.Event()
    install_shutdown_handler(stop_event)

    collector = select_collector()
    printer = asyncio.create_task(drain_to_stdout(stop_event))
    try:
        await collector.run(stop_event)
    finally:
        stop_event.set()
        await printer
    logger.info("Linux collector stopped cleanly")


if __name__ == "__main__":
    asyncio.run(main())
