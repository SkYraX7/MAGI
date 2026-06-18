"""Authentication — RS256 JWT issue/verify, password hashing, and FastAPI guards.

MVP auth model (CLAUDE.md): a single admin user sourced from env. Tokens are signed
with an RS256 private key that never leaves the backend; verification uses the public
key. The ``role`` claim drives RBAC at the API layer (Neo4j Community has none).

Password hashing uses ``bcrypt`` directly — passlib 1.7 is incompatible with bcrypt
4.x/5.x, and the direct API is simpler and well supported.

CLI helper (referenced from .env.example):

    python -m backend.auth hash <password>     # prints a bcrypt hash for ADMIN_PASSWORD_HASH
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Optional

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel

from backend.config import get_settings


class User(BaseModel):
    username: str
    role: str


class TokenData(BaseModel):
    username: str
    role: str


# --- key loading (cached; keys are small and immutable for the process lifetime) ---
@lru_cache
def _private_key() -> str:
    return Path(get_settings().jwt_private_key_path).read_text(encoding="utf-8")


@lru_cache
def _public_key() -> str:
    return Path(get_settings().jwt_public_key_path).read_text(encoding="utf-8")


# --- passwords ---
def hash_password(plain: str) -> str:
    """Return a bcrypt hash for a plaintext password."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Constant-time bcrypt verification; False (not an exception) on any mismatch."""
    if not hashed:
        return False
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# --- tokens ---
def create_access_token(*, subject: str, role: str, expires_minutes: Optional[int] = None) -> str:
    """Issue a signed RS256 JWT carrying the subject + role claim."""
    settings = get_settings()
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=expires_minutes or settings.jwt_expire_minutes)
    claims = {"sub": subject, "role": role, "iat": now, "exp": expire}
    return jwt.encode(claims, _private_key(), algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> TokenData:
    """Verify a JWT and return its claims. Raises 401 on expired/tampered/invalid tokens."""
    settings = get_settings()
    try:
        payload = jwt.decode(token, _public_key(), algorithms=[settings.jwt_algorithm])
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    subject = payload.get("sub")
    if not subject:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token missing subject")
    return TokenData(username=subject, role=payload.get("role", "viewer"))


def authenticate(username: str, password: str) -> Optional[User]:
    """Validate credentials against the MVP single admin user from env."""
    settings = get_settings()
    if username != settings.admin_username:
        return None
    if not verify_password(password, settings.admin_password_hash):
        return None
    return User(username=username, role=settings.admin_role)


# --- FastAPI dependencies ---
_bearer = HTTPBearer(auto_error=False)


async def get_current_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> User:
    """Resolve the bearer token into a User, or raise 401."""
    if creds is None or not creds.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    data = decode_token(creds.credentials)
    return User(username=data.username, role=data.role)


async def require_admin(user: User = Depends(get_current_user)) -> User:
    """Guard that allows only ``role=admin`` tokens through (RBAC at the API layer)."""
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return user


def verify_ws_token(token: Optional[str]) -> Optional[User]:
    """Validate a WebSocket handshake token. Returns None on failure (caller closes)."""
    if not token:
        return None
    try:
        data = decode_token(token)
    except HTTPException:
        return None
    return User(username=data.username, role=data.role)


def _cli() -> None:
    if len(sys.argv) == 3 and sys.argv[1] == "hash":
        print(hash_password(sys.argv[2]))
    else:
        print("usage: python -m backend.auth hash <password>", file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    _cli()


__all__ = [
    "User",
    "TokenData",
    "hash_password",
    "verify_password",
    "create_access_token",
    "decode_token",
    "authenticate",
    "get_current_user",
    "require_admin",
    "verify_ws_token",
]
