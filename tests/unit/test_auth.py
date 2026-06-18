"""Unit tests for auth — password hashing, JWT issue/verify, and credential checks."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from backend.auth import (
    authenticate,
    create_access_token,
    decode_token,
    hash_password,
    verify_password,
)
from backend.config import Settings


def test_password_hash_roundtrip():
    h = hash_password("s3cret-pw")
    assert h != "s3cret-pw"
    assert verify_password("s3cret-pw", h) is True
    assert verify_password("wrong", h) is False


def test_verify_password_empty_hash_is_false():
    assert verify_password("anything", "") is False


def test_token_roundtrip_carries_role():
    token = create_access_token(subject="admin", role="admin")
    data = decode_token(token)
    assert data.username == "admin"
    assert data.role == "admin"


def test_expired_token_raises():
    token = create_access_token(subject="admin", role="admin", expires_minutes=-1)
    with pytest.raises(HTTPException) as exc:
        decode_token(token)
    assert exc.value.status_code == 401


def test_tampered_token_raises():
    token = create_access_token(subject="admin", role="admin")
    tampered = token[:-3] + ("aaa" if not token.endswith("aaa") else "bbb")
    with pytest.raises(HTTPException):
        decode_token(tampered)


def test_authenticate_success(monkeypatch):
    h = hash_password("hunter2")
    settings = Settings(
        _env_file=None, admin_username="admin", admin_password_hash=h, admin_role="admin"
    )
    monkeypatch.setattr("backend.auth.get_settings", lambda: settings)
    user = authenticate("admin", "hunter2")
    assert user is not None
    assert user.username == "admin"
    assert user.role == "admin"


def test_authenticate_wrong_password(monkeypatch):
    h = hash_password("hunter2")
    settings = Settings(_env_file=None, admin_username="admin", admin_password_hash=h)
    monkeypatch.setattr("backend.auth.get_settings", lambda: settings)
    assert authenticate("admin", "nope") is None


def test_authenticate_unknown_user(monkeypatch):
    h = hash_password("hunter2")
    settings = Settings(_env_file=None, admin_username="admin", admin_password_hash=h)
    monkeypatch.setattr("backend.auth.get_settings", lambda: settings)
    assert authenticate("intruder", "hunter2") is None


def test_authenticate_no_hash_configured(monkeypatch):
    settings = Settings(_env_file=None, admin_username="admin", admin_password_hash="")
    monkeypatch.setattr("backend.auth.get_settings", lambda: settings)
    assert authenticate("admin", "anything") is None
