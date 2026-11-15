"""Roles, scopes, login enforcement and the audit log (auth module).

Roles, each including the ones before it:

    viewer     sees systems, findings, mitigations, patch log (within its scope)
    operator   + scans, ignores findings, generates playbooks, claims / reports mitigations, saved filters
    approver   + approves and cancels mitigations
    admin      + settings: CVE sources, channels, subscriptions, hand-off, repo manager runs, systems, import

    rbac:
      default_role: ""            # role for OIDC users no binding matches; "" = no access
      bindings:
        - {group: secops, role: admin}
        - {group: dba, role: approver, hosts: "group:db"}     # only systems in the db group
        - {user: alice, role: approver}
        - {email: "*@ops.example.org", role: operator}

The basic-auth login (web_user / web_password) is always admin: keep it as a break-glass account.
API tokens: role and hosts per token (api_tokens: {ci: {token: ..., role: operator, hosts: "group:dmz"}}).
"""
from __future__ import annotations

import re
from fnmatch import fnmatch
from urllib.parse import urlencode

from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBasicCredentials

from diysca.auth import oidc, session
from diysca.core import db, events, scope
from diysca.core.config import settings
from diysca.core.security import ROLES, User, _basic, basic_ok, machine_path, set_user, token_entry, token_user

OPEN_PATHS = ("/healthz", "/login", "/auth/callback", "/logout")

# (method, path regex, role). First match wins. GETs not listed need "viewer".
POLICY: list[tuple[str, str, str]] = [
    ("GET", r"^/settings/export\.yml$", "admin"),
    ("GET", r"^/settings(/.*)?$", "admin"),
    ("POST", r"^/mitigations$", "approver"),
    ("POST", r"^/mitigations/\d+/cancel$", "approver"),
    ("POST", r"^/api/mitigations$", "approver"),
    ("POST", r"^/api/mitigations/\d+/cancel$", "approver"),
    ("POST", r"^/mitigations/\d+/(report|handoff)$", "operator"),
    ("POST", r"^/api/mitigations/\d+/(claim|report)$", "operator"),
    ("POST", r"^/(api/)?scan$", "operator"),
    ("POST", r"^/systems/\d+/scan$", "operator"),
    ("POST", r"^/findings/\d+/status$", "operator"),
    ("POST", r"^/patch/playbook$", "operator"),
    ("POST", r"^/reprovision$", "operator"),
    ("POST", r"^/filters(/\d+/delete)?$", "operator"),
    ("POST", r"^/mcp$", "viewer"),  # each MCP tool checks its own role
    ("POST", r".*", "admin"),
]


def required_role(method: str, path: str) -> str:
    for m, rx, role in POLICY:
        if m == method and re.match(rx, path):
            return role
    return "viewer"


def role_for(name: str, email: str, groups: list[str]) -> tuple[str | None, list[str]]:
    """Highest role of the matching bindings, and the host patterns it is limited to ([] = all systems)."""
    best, hosts, unscoped = None, [], False
    for b in (settings.rbac or {}).get("bindings") or []:
        hit = (("group" in b and any(fnmatch(g, str(b["group"])) for g in groups))
               or ("user" in b and fnmatch(name, str(b["user"])))
               or ("email" in b and email and fnmatch(email.lower(), str(b["email"]).lower())))
        role = str(b.get("role") or "viewer")
        if not hit or role not in ROLES:
            continue
        if best is None or ROLES.index(role) > ROLES.index(best):
            best, hosts, unscoped = role, [], False
        if role == best:
            if b.get("hosts"):
                hosts += [h.strip() for h in str(b["hosts"]).split(",") if h.strip()]
            else:
                unscoped = True
    if best is None:
        default = (settings.rbac or {}).get("default_role") or ""
        return (default if default in ROLES else None), []
    return best, ([] if unscoped else hosts)


def login_user(info: dict) -> User | None:
    role, hosts = role_for(info["name"], info.get("email", ""), info.get("groups", []))
    if not role:
        return None
    return User(name=info["name"], role=role, kind="oidc", hosts=hosts, email=info.get("email", ""),
                groups=info.get("groups", []))


def user_from_cookie(request: Request) -> User | None:
    d = session.verify(request.cookies.get(session.COOKIE))
    if not d or d.get("t") != "login" or not d.get("u") or d.get("r") not in ROLES:
        return None
    return User(name=d["u"], role=d["r"], kind="oidc", hosts=d.get("h") or [], email=d.get("e", ""),
                groups=d.get("g") or [])


def _wants_html(request: Request) -> bool:
    return request.method == "GET" and not machine_path(request.url.path) and \
        "text/html" in request.headers.get("accept", "text/html")


class LoginRedirect(Exception):
    def __init__(self, url: str):
        self.url = url


async def authenticate(request: Request, creds: HTTPBasicCredentials | None = Depends(_basic)):
    path = request.url.path
    set_user(request, User(name="web"))
    if path in OPEN_PATHS:
        return
    user: User | None = None
    authz = request.headers.get("authorization", "")
    if authz.lower().startswith("bearer "):
        hit = token_entry(authz[7:].strip())
        if not hit or not machine_path(path):
            raise HTTPException(401, "invalid API token" if not hit else "API tokens only work on /api/* and /mcp",
                                headers={"WWW-Authenticate": "Bearer"})
        user = token_user(*hit)
    elif basic_ok(creds):
        user = User(name=creds.username, kind="basic")
    else:
        user = user_from_cookie(request)
    if user is None:
        login_needed = oidc.configured() or (settings.web_user and settings.web_password) or \
            (settings.api_tokens and machine_path(path))
        if not login_needed:
            user = User(name="web")  # nothing configured: open, like without the auth module
        elif oidc.configured() and _wants_html(request):
            nxt = request.url.path + ("?" + request.url.query if request.url.query else "")
            raise LoginRedirect("/login?" + urlencode({"next": nxt}))
        else:
            raise HTTPException(401, headers={"WWW-Authenticate": "Basic" if settings.web_user else "Bearer"})
    set_user(request, user)
    need = required_role(request.method, path)
    if not user.can(need):
        raise HTTPException(403, f"this needs the {need} role; you are {user.role}")
    scope.set_ids(scope.hosts_for(user.hosts))


# ------------------------------------------------------------------ audit log
def record(actor: str, action: str, target: str = "", detail: str = "", role: str = "", status: int | None = None,
           ip: str = ""):
    db.x("INSERT INTO audit_log(at, actor, role, action, target, detail, status, ip) VALUES (?,?,?,?,?,?,?,?)",
         (db.now(), actor, role, action, target[:500], detail[:2000], status, ip))


def _on_audit(actor: str, action: str, target: str = "", detail: str = "", **_):
    record(actor, action, target, detail)


def prune():
    import datetime
    cutoff = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=settings.audit_days)).isoformat()
    db.x("DELETE FROM audit_log WHERE at < ?", (cutoff,))


def install(app):
    """Middleware: login redirects, and every change (non-GET request) goes to the audit log."""
    from starlette.middleware.base import BaseHTTPMiddleware

    @app.exception_handler(LoginRedirect)
    async def _login_redirect(request, exc: LoginRedirect):
        return RedirectResponse(exc.url, 303)

    class Audit(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            response = await call_next(request)
            if request.method not in ("GET", "HEAD", "OPTIONS") and request.url.path not in ("/mcp",):
                u = getattr(request.state, "user", None)
                try:
                    record(u.name if u else "?", f"{request.method} {request.url.path}",
                           detail=request.url.query, role=u.role if u else "", status=response.status_code,
                           ip=request.client.host if request.client else "")
                except Exception:  # noqa: BLE001 - never fail a request because of the log
                    pass
            return response

    app.add_middleware(Audit)


def setup():
    events.on("audit", _on_audit)
