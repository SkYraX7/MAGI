"""Confidence scoring — pure function over an :class:`EnrichmentResult`.

Additive weights, capped at 1.0, exactly per CLAUDE.md "Confidence scoring":

    VirusTotal detections >= 5 engines  +0.50
    VirusTotal detections 1-4 engines   +0.20
    Censys tag scanner / tor-exit       +0.20
    Feodo Tracker hit                   +0.40
    Emerging Threats hit                +0.30
"""

from __future__ import annotations

from backend.enrichment.models import EnrichmentResult

# Censys tags that contribute to the score.
SUSPICIOUS_CENSYS_TAGS = frozenset({"scanner", "tor-exit"})


def compute_confidence(result: EnrichmentResult) -> float:
    """Return an additive confidence score in [0.0, 1.0]."""
    score = 0.0

    if result.vt_malicious >= 5:
        score += 0.50
    elif result.vt_malicious >= 1:
        score += 0.20

    if any(tag in SUSPICIOUS_CENSYS_TAGS for tag in result.censys_tags):
        score += 0.20

    if result.feodo_hit:
        score += 0.40

    if result.emerging_hit:
        score += 0.30

    return min(score, 1.0)


__all__ = ["compute_confidence", "SUSPICIOUS_CENSYS_TAGS"]
