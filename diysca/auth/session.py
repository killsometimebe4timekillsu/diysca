"""Signed cookies for logged-in users (no server-side session store, survives restarts)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

from diysca.core.config import settings

COOKIE = "diysca_session"
FLOW_COOKIE = "diysca_oidc"
_secret_cache: bytes | None = None


def secret() -> bytes:
    """settings.session_secret, else a random key kept in <data_dir>/session.key (created on first use)."""
    global _secret_cache
    if settings.session_secret:
        return settings.session_secret.encode()
    if _secret_cache:
        return _secret_cache
    path = Path(settings.data_dir) / "session.key"
    try:
        _secret_cache = path.read_bytes().strip()
    except FileNotFoundError:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        key = secrets.token_hex(32).encode()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
        _secret_cache = key
    return _secret_cache


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign(data: dict, max_age: float) -> str:
    body = _b64(json.dumps({**data, "exp": int(time.time() + max_age)}, separators=(",", ":")).encode())
    mac = _b64(hmac.new(secret(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{mac}"


def verify(value: str | None) -> dict | None:
    if not value or "." not in value:
        return None
    body, mac = value.rsplit(".", 1)
    good = _b64(hmac.new(secret(), body.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(mac.encode("utf-8", "replace"), good.encode()):  # str compare raises on non-ASCII
        return None
    try:
        data = json.loads(_unb64(body))
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    if data.get("exp", 0) < time.time():
        return None
    return data


def cookie_kwargs(max_age: float) -> dict:
    return {"max_age": int(max_age), "httponly": True, "samesite": "lax",
            "secure": settings.base_url.startswith("https://"), "path": "/"}
