"""Authentication that is always on: HTTP basic auth for people, bearer tokens for agents.

Without the auth module everybody who gets in is an admin. The auth module (diysca/auth) adds OIDC
login, roles and host scopes on top of this.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from diysca.core.config import settings

_basic = HTTPBasic(auto_error=False)
ROLES = ("viewer", "operator", "approver", "admin")


@dataclass
class User:
    name: str                      # shown in logs: alice, token:ci, web
    role: str = "admin"
    kind: str = "anonymous"        # anonymous | basic | token | oidc
    hosts: list[str] = field(default_factory=list)  # scope patterns; empty = all systems
    email: str = ""
    groups: list[str] = field(default_factory=list)

    @property
    def is_agent(self) -> bool:
        return self.kind == "token"

    def can(self, role: str) -> bool:
        return ROLES.index(self.role) >= ROLES.index(role)


def token_entry(token: str) -> tuple[str, dict] | None:
    """api_tokens: {name: "secret"} or {name: {token: "secret", role: operator, hosts: "group:dmz"}}."""
    for name, t in (settings.api_tokens or {}).items():
        conf = t if isinstance(t, dict) else {"token": t}
        if conf.get("token") and _same(conf["token"], token):
            return name, conf
    return None


def machine_path(path: str) -> bool:
    return path.startswith("/api/") or path == "/mcp"


def token_user(name: str, conf: dict) -> User:
    default = "approver" if settings.agents_can_approve else "operator"
    role = str(conf.get("role") or default)
    if role not in ROLES:
        role = "viewer"
    hosts = conf.get("hosts") or []
    hosts = [h.strip() for h in hosts.split(",")] if isinstance(hosts, str) else list(hosts)
    return User(name=f"token:{name}", role=role, kind="token", hosts=hosts)


def ui_open() -> bool:
    """True when no login is configured for the web UI: anyone who reaches the port acts as admin."""
    from diysca.auth import oidc
    return not (settings.web_user and settings.web_password) and not oidc.configured()


def _same(a: str, b: str) -> bool:
    """Constant-time comparison that also takes non-ASCII input (compare_digest on str raises for it)."""
    return secrets.compare_digest(str(a).encode(), str(b).encode())


def basic_ok(creds: HTTPBasicCredentials | None) -> bool:
    return bool(settings.web_user and settings.web_password and creds
                and _same(creds.username, settings.web_user) and _same(creds.password, settings.web_password))


def safe_next(url: str | None, default: str = "/") -> str:
    """A path on this site to redirect to, or `default`. Refuses other sites ("//evil.example", "https://...",
    "/\\evil") and script URLs, so login and "back" links can't send people elsewhere."""
    url = str(url or "")
    if not url.startswith("/") or url.startswith("//") or "\\" in url or any(ord(c) < 0x20 for c in url):
        return default
    return url


def same_origin(request: Request) -> bool:
    """False when a browser sends this request from another site (CSRF). Browsers attach the basic-auth
    login and the session cookie to such requests on their own, so every change made with them is checked.
    Clients that send neither Origin nor Referer (curl, scripts) are not browsers and pass."""
    from urllib.parse import urlsplit
    h = request.headers
    if h.get("sec-fetch-site", "").lower() == "cross-site":
        return False
    src = h.get("origin") or h.get("referer")
    if not src:
        return True
    host = urlsplit(src).netloc.lower()
    ours = {h.get("host", "").lower(), urlsplit(settings.base_url).netloc.lower()}
    ours |= {x.strip().lower() for x in h.get("x-forwarded-host", "").split(",")}
    return bool(host) and host in ours - {""}


def set_user(request: Request, user: User):
    request.state.user = user
    request.state.actor = user.name
    request.state.is_token = user.kind == "token"


async def authenticate(request: Request, creds: HTTPBasicCredentials | None = Depends(_basic)):
    """Core rules: tokens open /api/* and /mcp; basic auth opens everything; nothing configured = open."""
    path = request.url.path
    set_user(request, User(name="web"))
    if path == "/healthz":
        return
    authz = request.headers.get("authorization", "")
    if authz.lower().startswith("bearer "):
        hit = token_entry(authz[7:].strip())
        if hit and machine_path(path):
            set_user(request, token_user(*hit))
            return
        raise HTTPException(401, "invalid API token" if not hit else "API tokens only work on /api/* and /mcp",
                            headers={"WWW-Authenticate": "Bearer"})
    basic_on = bool(settings.web_user and settings.web_password)
    if basic_on or (settings.api_tokens and machine_path(path)):
        if basic_ok(creds):
            set_user(request, User(name=creds.username, kind="basic"))
            return
        raise HTTPException(401, headers={"WWW-Authenticate": "Basic" if basic_on else "Bearer"})
