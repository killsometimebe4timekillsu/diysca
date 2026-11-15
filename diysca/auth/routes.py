"""Auth module pages: login / logout, Settings > Access (who has which role, audit log)."""
from __future__ import annotations

import csv
import io
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, Response

from diysca.auth import oidc, rbac, session
from diysca.core import db
from diysca.core.config import settings
from diysca.core.security import safe_next
from diysca.ui import csv_cell, render, templates

router = APIRouter()


@router.get("/login", include_in_schema=False)
def login(request: Request, next: str = "/", error: str = ""):
    next = safe_next(next)  # shown as a link and used after login: only paths on this site
    if not oidc.configured() or error:
        return templates.TemplateResponse(request, "login.html", {"error": error, "oidc": oidc.configured(),
                                                                  "basic": bool(settings.web_user), "next": next},
                                          status_code=400 if error else 200)
    try:
        url, flow = oidc.start(next)
    except (oidc.OIDCError, httpx.HTTPError) as e:
        return RedirectResponse("/login?" + urlencode({"error": f"Login provider not reachable: {e}"}), 303)
    r = RedirectResponse(url, 303)
    r.set_cookie(session.FLOW_COOKIE, session.sign({**flow, "t": "flow"}, 600), **session.cookie_kwargs(600))
    return r


@router.get("/auth/callback", include_in_schema=False)
def callback(request: Request, code: str = "", state: str = "", error: str = "", error_description: str = ""):
    if error:
        return RedirectResponse("/login?" + urlencode({"error": f"{error}: {error_description}"}), 303)
    flow = session.verify(request.cookies.get(session.FLOW_COOKIE))
    if flow and flow.get("t") != "flow":  # a login cookie is not a flow cookie, and the other way round
        flow = None
    try:
        info = oidc.finish(code, state, flow or {})
    except (oidc.OIDCError, httpx.HTTPError) as e:
        rbac.record("?", "login failed", detail=str(e), ip=request.client.host if request.client else "")
        return RedirectResponse("/login?" + urlencode({"error": str(e)}), 303)
    user = rbac.login_user(info)
    ip = request.client.host if request.client else ""
    if not user:
        rbac.record(info["name"], "login denied", detail=f"no role for groups {', '.join(info['groups'])}", ip=ip)
        return RedirectResponse("/login?" + urlencode({"error": f"{info['name']} has no access to diysca. "
                                                                "Ask an admin to add a role binding for you or one of "
                                                                "your groups."}), 303)
    rbac.record(user.name, "login", detail=f"role {user.role}" + (f", systems {','.join(user.hosts)}" if user.hosts else ""),
                role=user.role, ip=ip)
    max_age = settings.session_hours * 3600
    r = RedirectResponse(safe_next((flow or {}).get("next")), 303)
    r.set_cookie(session.COOKIE, session.sign({"t": "login", "u": user.name, "r": user.role, "h": user.hosts, "e": user.email,
                                               "g": user.groups[:50]}, max_age), **session.cookie_kwargs(max_age))
    r.delete_cookie(session.FLOW_COOKIE, path="/")
    return r


@router.get("/logout", include_in_schema=False)
def logout(request: Request):
    u = rbac.user_from_cookie(request)
    if u:
        rbac.record(u.name, "logout", role=u.role)
    r = RedirectResponse((oidc.logout_url() if oidc.configured() else None) or "/login", 303)
    r.delete_cookie(session.COOKIE, path="/")
    return r


def _audit_rows(args: dict, limit: int = 500):
    where, p = ["1=1"], []
    for col in ("actor", "action"):
        if args.get(col):
            where.append(f"{col} LIKE ?")
            p.append(f"%{args[col]}%")
    if args.get("from"):
        where.append("at >= ?")
        p.append(args["from"])
    if args.get("to"):
        where.append("at <= ?")
        p.append(args["to"] + "T23:59:59")
    return db.q(f"SELECT * FROM audit_log WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT {int(limit)}", p)


@router.get("/settings/access", include_in_schema=False)
def access(request: Request):
    args = {k: v for k, v in request.query_params.items() if v}
    return render(request, "settings_access.html", tab="access", oidc_on=oidc.configured(),
                  issuer=(settings.oidc or {}).get("issuer", ""), redirect_uri=oidc.redirect_uri(),
                  bindings=(settings.rbac or {}).get("bindings") or [],
                  default_role=(settings.rbac or {}).get("default_role") or "", policy=rbac.POLICY,
                  tokens=[(n, (t.get("role") if isinstance(t, dict) else None) or
                           ("approver" if settings.agents_can_approve else "operator"),
                           (t.get("hosts") if isinstance(t, dict) else "") or "all")
                          for n, t in (settings.api_tokens or {}).items()],
                  log=_audit_rows(args, 300), args=args, basic=bool(settings.web_user))


@router.get("/settings/access/audit.csv", include_in_schema=False)
def audit_csv(request: Request):
    rows = _audit_rows({k: v for k, v in request.query_params.items() if v}, 100000)
    buf = io.StringIO()
    w = csv.writer(buf)
    cols = ("at", "actor", "role", "action", "target", "detail", "status", "ip")
    w.writerow(cols)
    for r in rows:
        w.writerow([csv_cell(r[c]) for c in cols])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="diysca-audit.csv"'})


@router.get("/api/me", tags=["auth"], summary="Who am I")
def me(request: Request):
    """The caller's name, role and the systems their role is limited to (empty = all)."""
    u = request.state.user
    return {"name": u.name, "role": u.role, "kind": u.kind, "hosts": u.hosts, "groups": u.groups}


