"""Unit tests for the Linux collector's pure helpers (sockaddr-hex decode + selection)."""

from __future__ import annotations

import socket
import struct

from collectors.linux.ebpf_collector import (
    AuditdCollector,
    EbpfCollector,
    parse_sockaddr_hex,
    select_collector,
)


def _make_v4_saddr(ip: str, port: int) -> str:
    family = struct.pack("<H", socket.AF_INET)
    port_b = struct.pack("!H", port)
    addr = socket.inet_aton(ip)
    return (family + port_b + addr + b"\x00" * 8).hex()


def _make_v6_saddr(ip: str, port: int) -> str:
    family = struct.pack("<H", socket.AF_INET6)
    port_b = struct.pack("!H", port)
    flowinfo = b"\x00" * 4
    addr = socket.inet_pton(socket.AF_INET6, ip)
    scope = b"\x00" * 4
    return (family + port_b + flowinfo + addr + scope).hex()


def test_parse_ipv4_sockaddr():
    parsed = parse_sockaddr_hex(_make_v4_saddr("185.220.101.5", 443))
    assert parsed == ("185.220.101.5", 443)


def test_parse_ipv6_sockaddr():
    parsed = parse_sockaddr_hex(_make_v6_saddr("2606:4700:4700::1111", 853))
    assert parsed is not None
    ip, port = parsed
    assert port == 853
    assert socket.inet_pton(socket.AF_INET6, ip) == socket.inet_pton(
        socket.AF_INET6, "2606:4700:4700::1111"
    )


def test_parse_non_ip_family_returns_none():
    # AF_UNIX (family value 1) sockaddr — not an IP endpoint. Packed literally so the
    # test runs on Windows too, where socket.AF_UNIX may be absent.
    unix = struct.pack("<H", 1).hex() + "2f746d702f73"
    assert parse_sockaddr_hex(unix) is None


def test_parse_malformed_hex_returns_none():
    assert parse_sockaddr_hex("nothex!!") is None
    assert parse_sockaddr_hex("0200") is None  # too short for AF_INET


def test_select_collector_falls_back_to_auditd_without_bcc(monkeypatch):
    monkeypatch.setattr(EbpfCollector, "available", staticmethod(lambda: False))
    assert isinstance(select_collector(), AuditdCollector)


def test_select_collector_prefers_ebpf_when_available(monkeypatch):
    monkeypatch.setattr(EbpfCollector, "available", staticmethod(lambda: True))
    assert isinstance(select_collector(), EbpfCollector)


def test_auditd_process_record_emits_connect(monkeypatch):
    collector = AuditdCollector()
    captured = []
    monkeypatch.setattr(collector, "_emit_connect", lambda *a: captured.append(a))
    saddr = _make_v4_saddr("8.8.8.8", 53)
    line = f'type=SOCKADDR msg=audit(1.0:9): saddr={saddr.upper()}'
    collector._process_record(line)
    assert captured and captured[0][2:] == ("8.8.8.8", 53)


def test_auditd_process_record_emits_execve(monkeypatch):
    collector = AuditdCollector()
    captured = []
    monkeypatch.setattr(collector, "_emit_execve", lambda *a: captured.append(a))
    line = 'type=SYSCALL msg=audit(1.0:9): syscall=59 comm="bash" exe="/usr/bin/bash" pid=42'
    collector._process_record(line)
    assert captured
