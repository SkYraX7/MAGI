"""Application configuration via pydantic-settings (singleton).

All secrets and tunables are loaded from environment variables / ``.env`` — nothing
is hardcoded (CLAUDE.md security checklist). Import the singleton through
:func:`get_settings` rather than instantiating :class:`Settings` directly so the
``.env`` file is read once and reused.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Strongly-typed view over the environment. See ``.env.example`` for all keys."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",  # tolerate unrelated env vars (frontend, CI, etc.)
        case_sensitive=False,
    )

    # --- Neo4j ---
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "changeme"
    neo4j_max_connections: int = Field(default=50, ge=1, le=500)

    # --- Redis ---
    redis_url: str = "redis://localhost:6379/0"

    # --- JWT (consumed in Phase 4; defined here so config stays one source of truth) ---
    jwt_private_key_path: str = "./keys/private.pem"
    jwt_public_key_path: str = "./keys/public.pem"
    jwt_algorithm: str = "RS256"
    jwt_expire_minutes: int = 480

    # --- OSINT API keys (blank => enricher skipped, warning logged) ---
    virustotal_api_key: str = ""
    censys_api_id: str = ""
    censys_api_secret: str = ""

    # --- Enrichment ---
    enrichment_worker_count: int = Field(default=4, ge=1)
    # Set to the Feodo weight (0.40) so a single Feodo-tracker hit clears the bar on
    # score alone; also lets two low-confidence signals (e.g. VT 1-4 + Censys) qualify.
    threat_confidence_threshold: float = Field(default=0.4, ge=0.0, le=1.0)
    # VirusTotal free tier is 4 req/min; raise for paid tiers (Redis counter enforces it).
    virustotal_rate_per_minute: int = Field(default=4, ge=1)

    # --- Threat-intel feeds ---
    feodo_feed_url: str = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    emerging_feed_url: str = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    feeds_cache_dir: str = "./feeds_cache"
    feed_refresh_seconds: int = Field(default=86400, ge=60)  # daily
    feed_stale_alert_hours: int = Field(default=48, ge=1)

    # --- Pruning daemon ---
    prune_interval_seconds: int = Field(default=3600, ge=1)
    prune_stale_after_hours: int = Field(default=6, ge=1)

    # --- CORS ---
    allowed_origins: str = "http://localhost:3000"

    # --- Admin (MVP single-user store) ---
    admin_username: str = "admin"
    admin_password_hash: str = ""

    # --- Logging ---
    log_level: str = "INFO"

    @property
    def cors_origins(self) -> list[str]:
        """Parse the comma-separated ``ALLOWED_ORIGINS`` into a list."""
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings singleton (cached after first read)."""
    return Settings()


__all__ = ["Settings", "get_settings"]
