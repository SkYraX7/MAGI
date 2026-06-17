"""Unit tests for OSINT response parsing + EnrichmentResult combine/cache roundtrip."""

from __future__ import annotations

from backend.enrichment import censys, virustotal
from backend.enrichment.models import EnrichmentResult


def test_virustotal_parse():
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 7, "harmless": 60},
                "country": "RU",
                "asn": 12345,
            }
        }
    }
    result = virustotal.parse_response(payload)
    assert result.vt_present is True
    assert result.vt_malicious == 7
    assert result.country == "RU"


def test_virustotal_parse_tolerates_missing_fields():
    result = virustotal.parse_response({"data": {"attributes": {}}})
    assert result.vt_present is True
    assert result.vt_malicious == 0


def test_censys_parse():
    payload = {
        "result": {
            "autonomous_system": {"asn": 6789},
            "location": {"country": "United States"},
            "labels": ["SCANNER", "remote-access"],
        }
    }
    result = censys.parse_response(payload)
    assert result.censys_asn == 6789
    assert result.country == "United States"
    assert "scanner" in result.censys_tags  # lowercased


def test_censys_parse_empty_result():
    result = censys.parse_response({"result": {}})
    assert result.censys_asn is None
    assert result.censys_tags == []


def test_combine_merges_signals():
    vt = EnrichmentResult(vt_present=True, vt_malicious=8, country="RU")
    cen = EnrichmentResult(censys_tags=["scanner"], censys_asn=42)
    feo = EnrichmentResult(feodo_hit=True, campaign="Feodo Tracker Botnet", source_feed="feodo")
    merged = EnrichmentResult.combine([vt, cen, feo])
    assert merged.vt_malicious == 8
    assert merged.censys_asn == 42
    assert merged.feodo_hit is True
    assert merged.campaign == "Feodo Tracker Botnet"


def test_combine_first_feed_wins_campaign():
    feo = EnrichmentResult(feodo_hit=True, campaign="Feodo Tracker Botnet", source_feed="feodo")
    emg = EnrichmentResult(emerging_hit=True, campaign="Emerging Threats Compromised", source_feed="emerging")
    merged = EnrichmentResult.combine([feo, emg])
    assert merged.campaign == "Feodo Tracker Botnet"
    assert merged.feodo_hit and merged.emerging_hit


def test_cache_mapping_roundtrip():
    original = EnrichmentResult(
        vt_present=True,
        vt_malicious=3,
        censys_tags=["scanner", "tor-exit"],
        censys_asn=100,
        country="DE",
        feodo_hit=True,
        campaign="Feodo Tracker Botnet",
        source_feed="feodo",
    )
    restored = EnrichmentResult.from_cache_mapping(original.to_cache_mapping())
    assert restored.vt_malicious == 3
    assert set(restored.censys_tags) == {"scanner", "tor-exit"}
    assert restored.censys_asn == 100
    assert restored.country == "DE"
    assert restored.feodo_hit is True
    assert restored.campaign == "Feodo Tracker Botnet"
