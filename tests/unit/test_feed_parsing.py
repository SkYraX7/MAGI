"""Unit tests for blocklist parsing — validates format before trusting feed content."""

from __future__ import annotations

from backend.enrichment.feeds.base import parse_ip_blocklist


def test_parses_plain_ip_list():
    text = "1.2.3.4\n5.6.7.8\n9.10.11.12\n"
    assert parse_ip_blocklist(text) == {"1.2.3.4", "5.6.7.8", "9.10.11.12"}


def test_skips_comments_and_blank_lines():
    text = "# Feodo Tracker blocklist\n\n1.2.3.4\n# another comment\n5.6.7.8\n"
    assert parse_ip_blocklist(text) == {"1.2.3.4", "5.6.7.8"}


def test_skips_malformed_lines():
    text = "1.2.3.4\nnot-an-ip\n999.999.999.999\n5.6.7.8\n"
    assert parse_ip_blocklist(text) == {"1.2.3.4", "5.6.7.8"}


def test_tolerates_trailing_comment_and_csv():
    text = "1.2.3.4 # botnet C2\n5.6.7.8,Dridex,online\n"
    assert parse_ip_blocklist(text) == {"1.2.3.4", "5.6.7.8"}


def test_handles_ipv6():
    text = "2606:4700:4700::1111\n1.2.3.4\n"
    assert parse_ip_blocklist(text) == {"2606:4700:4700::1111", "1.2.3.4"}


def test_empty_input_yields_empty_set():
    assert parse_ip_blocklist("") == set()
    assert parse_ip_blocklist("# only comments\n\n") == set()
