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


def web_login_configured() -> bool:
    """A login for people: basic auth, or OIDC with the auth module on."""
    if settings.web_user and settings.web_password:
        return True
    from diysca.auth import oidc
    from diysca.core import modules
    return modules.enabled("auth") and oidc.configured()


def ui_open() -> bool:
    """True when no login is configured for the web UI: anyone who reaches the port acts as admin."""
    return not web_login_configured()


LOOPBACK = ("127.0.0.1", "::1", "localhost")


def open_listen_error(host: str) -> str | None:
    """Why `diysca serve --host <host>` must not start, or None."""
    if ui_open() and host not in LOOPBACK and not settings.allow_no_login:
        return (f"No login is configured, so everyone who can reach {host} would be an admin. Set web_user and "
                "web_password (or OIDC, see docs/auth.md), or listen on 127.0.0.1. For a lab without a login, set "
                "allow_no_login: true (env DIYSCA_ALLOW_NO_LOGIN=true).")
    return None


def tokens_need_web_login(path: str) -> bool:
    """API tokens are set but people have no login: the web pages would bypass every token role and scope."""
    return bool(settings.api_tokens) and not machine_path(path) and ui_open() and not settings.allow_no_login


TOKENS_WITHOUT_LOGIN = ("API tokens are configured, but there is no login for the web UI, so the UI would bypass "
                        "the tokens' roles. Set web_user and web_password (or OIDC, see docs/auth.md), or "
                        "allow_no_login: true for a lab.")


# ------------------------------------------------------------------ failed logins
class LoginLimiter:
    """Counts failed logins per client address. After `login_max_failures` the address waits
    `login_lockout_seconds`, doubling with every further failure (at most 1 h). A success clears it."""

    def __init__(self):
        self._fails: dict[str, list] = {}  # ip -> [count, blocked_until, last_failure]

    def retry_after(self, ip: str) -> int:
        import time
        e = self._fails.get(ip)
        if not e:
            return 0
        left = e[1] - time.time()
        return int(left) + 1 if left > 0 else 0

    def failed(self, ip: str):
        import time
        now = time.time()
        if len(self._fails) > 10000:  # forget the oldest, never grow without bound
            for k in sorted(self._fails, key=lambda k: self._fails[k][2])[:5000]:
                del self._fails[k]
        e = self._fails.setdefault(ip, [0, 0.0, now])
        if now - e[2] > 24 * 3600:
            e[0] = 0
        e[0] += 1
        e[2] = now
        over = e[0] - settings.login_max_failures
        if settings.login_max_failures > 0 and over >= 0:
            e[1] = now + min(settings.login_lockout_seconds * (2 ** min(over, 20)), 3600)

    def ok(self, ip: str):
        self._fails.pop(ip, None)

    def reset(self):
        self._fails.clear()


limiter = LoginLimiter()


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "?"


def check_not_locked(request: Request):
    wait = limiter.retry_after(client_ip(request))
    if wait:
        raise HTTPException(429, f"too many failed logins from this address; try again in {wait} s",
                            headers={"Retry-After": str(wait)})


def login_failed(request: Request, detail: str, headers: dict) -> HTTPException:
    """Count the failure and return the 401 to raise."""
    limiter.failed(client_ip(request))
    return HTTPException(401, detail, headers=headers)


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
    """Core rules: tokens open /api/* and /mcp; basic auth opens everything; nothing configured = open
    (on 127.0.0.1 only, see open_listen_error), except web pages while API tokens are set."""
    path = request.url.path
    set_user(request, User(name="web"))
    if path == "/healthz":
        return
    authz = request.headers.get("authorization", "")
    if authz.lower().startswith("bearer ") or creds is not None:
        check_not_locked(request)
    if authz.lower().startswith("bearer "):
        hit = token_entry(authz[7:].strip())
        if hit and machine_path(path):
            limiter.ok(client_ip(request))
            set_user(request, token_user(*hit))
            return
        if not hit:
            raise login_failed(request, "invalid API token", {"WWW-Authenticate": "Bearer"})
        raise HTTPException(401, "API tokens only work on /api/* and /mcp", headers={"WWW-Authenticate": "Bearer"})
    basic_on = bool(settings.web_user and settings.web_password)
    if basic_on or (settings.api_tokens and machine_path(path)):
        if basic_ok(creds):
            limiter.ok(client_ip(request))
            set_user(request, User(name=creds.username, kind="basic"))
            return
        hdr = {"WWW-Authenticate": "Basic" if basic_on else "Bearer"}
        if creds is not None:
            raise login_failed(request, "wrong user name or password", hdr)
        raise HTTPException(401, headers=hdr)
    if tokens_need_web_login(path):
        raise HTTPException(403, TOKENS_WITHOUT_LOGIN)
