"""Unit tests for the pure Sysmon XML -> UnifiedLogEvent mapping (no pywin32 needed)."""

from __future__ import annotations

from collectors.windows.sysmon_collector import (
    _basename,
    _extract_sha256,
    parse_sysmon_xml,
)

NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _wrap(event_id: int, data_rows: dict[str, str]) -> str:
    rows = "".join(f"<Data Name='{k}'>{v}</Data>" for k, v in data_rows.items())
    return f"""<Event xmlns='{NS}'>
      <System>
        <EventID>{event_id}</EventID>
        <TimeCreated SystemTime='2026-06-16T04:45:00.123456789Z'/>
        <Computer>WIN-HOST-01</Computer>
      </System>
      <EventData>{rows}</EventData>
    </Event>"""


def test_basename_handles_windows_paths():
    assert _basename(r"C:\Windows\System32\cmd.exe") == "cmd.exe"
    assert _basename(None) is None


def test_extract_sha256_from_hashes_field():
    hashes = "SHA256=ABC123,MD5=999,IMPHASH=777"
    assert _extract_sha256(hashes) == "abc123"
    assert _extract_sha256("MD5=999") == ""
    assert _extract_sha256(None) == ""


def test_parse_process_create_event_id_1():
    xml = _wrap(
        1,
        {
            "UtcTime": "2026-06-16 04:45:00.123",
            "ProcessId": "4321",
            "Image": r"C:\Windows\System32\powershell.exe",
            "Hashes": "SHA256=AABBCC",
            "ParentImage": r"C:\Windows\explorer.exe",
            "CommandLine": "powershell.exe -enc ZQBjAGgAbwA=",
        },
    )
    evt = parse_sysmon_xml(xml)
    assert evt is not None
    assert evt.event_type == "process"
    assert evt.source_process == "powershell.exe"
    assert evt.process_hash == "aabbcc"
    assert evt.parent_process == "explorer.exe"
    assert evt.command_line == "powershell.exe -enc ZQBjAGgAbwA="
    assert evt.pid == 4321
    assert evt.platform == "WIN-HOST-01"


def test_parse_network_connect_event_id_3():
    xml = _wrap(
        3,
        {
            "UtcTime": "2026-06-16 04:45:01.000",
            "ProcessId": "4321",
            "Image": r"C:\Program Files\app\svc.exe",
            "Protocol": "tcp",
            "Initiated": "true",
            "SourceIp": "10.0.0.5",
            "SourcePort": "44132",
            "DestinationIp": "185.220.101.5",
            "DestinationPort": "443",
        },
    )
    evt = parse_sysmon_xml(xml)
    assert evt is not None
    assert evt.event_type == "network"
    assert evt.direction == "outbound"
    assert evt.remote_ip == "185.220.101.5"
    assert evt.remote_port == 443
    assert evt.local_ip == "10.0.0.5"
    assert evt.protocol == "tcp"


def test_parse_network_inbound_when_not_initiated():
    xml = _wrap(
        3,
        {
            "ProcessId": "1",
            "Image": r"C:\svc.exe",
            "Initiated": "false",
            "DestinationIp": "10.0.0.9",
            "DestinationPort": "80",
        },
    )
    evt = parse_sysmon_xml(xml)
    assert evt is not None
    assert evt.direction == "inbound"


def test_parse_image_load_event_id_7():
    xml = _wrap(
        7,
        {
            "ProcessId": "555",
            "Image": r"C:\Windows\System32\rundll32.exe",
            "Hashes": "SHA256=FEEDFACE",
        },
    )
    evt = parse_sysmon_xml(xml)
    assert evt is not None
    assert evt.event_type == "image_load"
    assert evt.process_hash == "feedface"


def test_parse_dns_query_event_id_22():
    xml = _wrap(
        22,
        {
            "ProcessId": "777",
            "Image": r"C:\Program Files\Google\Chrome\chrome.exe",
            "QueryName": "evil.example.com",
        },
    )
    evt = parse_sysmon_xml(xml)
    assert evt is not None
    assert evt.event_type == "dns"
    assert evt.queried_domain == "evil.example.com"
    assert evt.source_process == "chrome.exe"


def test_unhandled_event_id_returns_none():
    assert parse_sysmon_xml(_wrap(11, {"ProcessId": "1", "Image": "x"})) is None


def test_garbage_xml_returns_none():
    assert parse_sysmon_xml("<not-valid") is None


def test_nanosecond_system_time_is_parsed():
    # Event ID 3 with no UtcTime forces the System/TimeCreated fallback path.
    xml = _wrap(
        3,
        {
            "ProcessId": "1",
            "Image": r"C:\svc.exe",
            "Initiated": "true",
            "DestinationIp": "1.2.3.4",
            "DestinationPort": "53",
        },
    )
    # Remove UtcTime row to trigger fallback.
    xml = xml.replace("<Data Name='UtcTime'>", "<Data Name='_skip'>")
    evt = parse_sysmon_xml(xml)
    assert evt is not None
    assert evt.timestamp.year == 2026
    assert evt.timestamp.tzinfo is not None
