"""Unit tests for confidence scoring — known signal combos -> expected weighted sums."""

from __future__ import annotations

import pytest

from backend.enrichment.models import EnrichmentResult
from backend.enrichment.scoring import compute_confidence


def test_empty_result_scores_zero():
    assert compute_confidence(EnrichmentResult()) == 0.0


def test_vt_high_detections():
    assert compute_confidence(EnrichmentResult(vt_malicious=5)) == 0.50
    assert compute_confidence(EnrichmentResult(vt_malicious=20)) == 0.50


def test_vt_low_detections():
    assert compute_confidence(EnrichmentResult(vt_malicious=1)) == 0.20
    assert compute_confidence(EnrichmentResult(vt_malicious=4)) == 0.20


def test_censys_suspicious_tag():
    assert compute_confidence(EnrichmentResult(censys_tags=["scanner"])) == 0.20
    assert compute_confidence(EnrichmentResult(censys_tags=["tor-exit"])) == 0.20
    assert compute_confidence(EnrichmentResult(censys_tags=["benign-tag"])) == 0.0


def test_feed_hits():
    assert compute_confidence(EnrichmentResult(feodo_hit=True)) == 0.40
    assert compute_confidence(EnrichmentResult(emerging_hit=True)) == 0.30


def test_additive_combination():
    # VT high (0.5) + censys (0.2) + emerging (0.3) = 1.0
    result = EnrichmentResult(vt_malicious=10, censys_tags=["scanner"], emerging_hit=True)
    assert compute_confidence(result) == pytest.approx(1.0)


def test_score_capped_at_one():
    # 0.5 + 0.2 + 0.4 + 0.3 = 1.4 -> capped to 1.0
    result = EnrichmentResult(
        vt_malicious=10, censys_tags=["tor-exit"], feodo_hit=True, emerging_hit=True
    )
    assert compute_confidence(result) == 1.0


def test_feodo_alone_meets_default_threshold():
    # The default threshold is lowered to the Feodo weight (0.40) so a single Feodo hit
    # qualifies on score alone — tie it to the actual config default to avoid drift.
    from backend.config import Settings

    threshold = Settings(_env_file=None).threat_confidence_threshold
    assert compute_confidence(EnrichmentResult(feodo_hit=True)) >= threshold
