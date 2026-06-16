"""Unit tests for the pydantic-settings configuration singleton."""

from __future__ import annotations

from backend.config import Settings, get_settings


def test_defaults_load_without_env(monkeypatch):
    # Construct directly with no .env influence by clearing relevant env vars.
    for key in ("NEO4J_URI", "ALLOWED_ORIGINS", "THREAT_CONFIDENCE_THRESHOLD"):
        monkeypatch.delenv(key, raising=False)
    settings = Settings(_env_file=None)
    assert settings.neo4j_uri.startswith("bolt://")
    assert settings.neo4j_max_connections == 50
    assert 0.0 <= settings.threat_confidence_threshold <= 1.0


def test_cors_origins_parsed_from_csv():
    settings = Settings(_env_file=None, allowed_origins="http://a.com, http://b.com ,")
    assert settings.cors_origins == ["http://a.com", "http://b.com"]


def test_env_override(monkeypatch):
    monkeypatch.setenv("NEO4J_USER", "custom_user")
    settings = Settings(_env_file=None)
    assert settings.neo4j_user == "custom_user"


def test_get_settings_is_cached():
    get_settings.cache_clear()
    assert get_settings() is get_settings()
