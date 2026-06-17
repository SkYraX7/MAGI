"""Typed enrichment results.

Each enricher returns a partial :class:`EnrichmentResult` carrying only the signals it
produced; the pipeline combines them with :meth:`EnrichmentResult.combine` before
scoring. Keeping everything in one validated model means the scorer and the graph
writer never have to guess at external JSON shapes.
"""

from __future__ import annotations

from typing import Iterable, Optional

from pydantic import BaseModel, Field


class EnrichmentResult(BaseModel):
    """Aggregated OSINT signals for a single IP address."""

    # --- VirusTotal ---
    vt_malicious: int = 0           # number of engines flagging malicious
    vt_present: bool = False        # VT actually returned a result

    # --- Censys ---
    censys_tags: list[str] = Field(default_factory=list)
    censys_asn: Optional[int] = None
    country: Optional[str] = None

    # --- Threat-intel feeds ---
    feodo_hit: bool = False
    emerging_hit: bool = False

    # --- derived campaign attribution (set by feeds) ---
    campaign: Optional[str] = None
    source_feed: Optional[str] = None

    @classmethod
    def combine(cls, results: Iterable["EnrichmentResult"]) -> "EnrichmentResult":
        """Merge partial results from the parallel enricher fan-out into one."""
        merged = cls()
        for r in results:
            merged.vt_malicious = max(merged.vt_malicious, r.vt_malicious)
            merged.vt_present = merged.vt_present or r.vt_present
            merged.censys_tags = list({*merged.censys_tags, *r.censys_tags})
            merged.censys_asn = merged.censys_asn or r.censys_asn
            merged.country = merged.country or r.country
            merged.feodo_hit = merged.feodo_hit or r.feodo_hit
            merged.emerging_hit = merged.emerging_hit or r.emerging_hit
            # First feed to claim the IP wins the campaign label (Feodo runs first).
            if r.campaign and not merged.campaign:
                merged.campaign = r.campaign
                merged.source_feed = r.source_feed
        return merged

    def to_cache_mapping(self) -> dict[str, str]:
        """Flatten to a Redis-hash-friendly ``str -> str`` mapping."""
        return {
            "vt_malicious": str(self.vt_malicious),
            "vt_present": "1" if self.vt_present else "0",
            "censys_tags": ",".join(self.censys_tags),
            "censys_asn": str(self.censys_asn) if self.censys_asn is not None else "",
            "country": self.country or "",
            "feodo_hit": "1" if self.feodo_hit else "0",
            "emerging_hit": "1" if self.emerging_hit else "0",
            "campaign": self.campaign or "",
            "source_feed": self.source_feed or "",
        }

    @classmethod
    def from_cache_mapping(cls, mapping: dict[str, str]) -> "EnrichmentResult":
        """Rebuild a result from a cached Redis hash."""
        tags = mapping.get("censys_tags", "")
        asn = mapping.get("censys_asn", "")
        return cls(
            vt_malicious=int(mapping.get("vt_malicious", 0) or 0),
            vt_present=mapping.get("vt_present") == "1",
            censys_tags=[t for t in tags.split(",") if t],
            censys_asn=int(asn) if asn else None,
            country=mapping.get("country") or None,
            feodo_hit=mapping.get("feodo_hit") == "1",
            emerging_hit=mapping.get("emerging_hit") == "1",
            campaign=mapping.get("campaign") or None,
            source_feed=mapping.get("source_feed") or None,
        )


__all__ = ["EnrichmentResult"]
