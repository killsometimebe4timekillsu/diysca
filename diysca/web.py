"""The web app: assembled from the enabled modules (see diysca/core/modules.py).

Core pages live here (dashboard, general settings, import / export, saved filters, MCP, health); each module
adds its own pages and API routes through its router.
"""
from __future__ import annotations

import asyncio
import datetime
import importlib
import logging
import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.exception_handlers import http_exception_handler, request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from diysca import __version__, mcp
from diysca.core import db, modules, security, settings_io
from diysca.core.config import settings
from diysca.scanning import scanner
from diysca.ui import _SECRET_KEYS, _masked, actor, hosts_query, render, scope_clause


@asynccontextmanager
async def lifespan(app):
    db.connect()
    if settings.inventories or settings.inventory_providers:
        await asyncio.to_thread(scanner.import_inventories)
    task = asyncio.create_task(scanner.scheduler()) if settings.run_scheduler else None
    yield
    if task:
        task.cancel()


API_DESCRIPTION = """
JSON API of diysca, the self-hosted CVE scanner and patcher. The full guide with examples is in
[docs/api.md](https://github.com/killsometimebe4timekillsu/diysca/blob/main/docs/api.md).

**Authentication.** People log in with OIDC (auth module) or HTTP basic auth (`web_user` / `web_password`).
Agents, CI/CD jobs and MCP clients send `Authorization: Bearer <token>` with a token from `api_tokens`. Tokens
only open `/api/*` and `/mcp`. Without any login configured, everything is open, and diysca only listens on 127.0.0.1.

**Roles.** With the auth module: `viewer` reads, `operator` scans and runs mitigations, `approver` approves,
`admin` changes settings. Roles can be limited to some systems; lists and counts then only show those.

**Filters.** List endpoints take the same query parameters as the filters in the web UI.

**Modules.** Endpoints of modules that are switched off (`modules:` in config.yml) are not there.
"""

modules.load()
_auth_dep = security.authenticate
if modules.enabled("auth"):
    from diysca.auth import rbac
    _auth_dep = rbac.authenticate

app = FastAPI(title="diysca", version=__version__, description=API_DESCRIPTION,
              openapi_tags=[t for m in modules.all_loaded() for t in m.openapi_tags],
              lifespan=lifespan, dependencies=[Depends(_auth_dep)])
def _api_only_in_schema(routes):
    """The OpenAPI document covers the machine API, not the HTML pages."""
    for r in routes:
        if hasattr(r, "include_in_schema") and not getattr(r, "path", "").startswith(("/api/", "/mcp", "/healthz")):
            r.include_in_schema = False


for _m in modules.all_loaded():
    if _m.routes:
        _router = importlib.import_module(_m.routes).router
        _api_only_in_schema(_router.routes)
        app.include_router(_router)
if modules.enabled("auth"):
    from diysca.auth import rbac as _rbac
    _rbac.install(app)


_ERROR_TITLES = {400: "That request can't be used", 403: "Not allowed", 404: "Not found", 405: "Not possible here",
                 409: "Not possible right now", 422: "Something in the form is not valid", 500: "Something went wrong"}


def _browser_page(request: Request) -> bool:
    """A person in a browser (not the API, MCP or a script): they get a page, not a line of JSON."""
    return not security.machine_path(request.url.path) and "text/html" in request.headers.get("accept", "")


def _error_page(request: Request, status: int, message: str, hint: str = ""):
    try:
        resp = render(request, "error.html", title=_ERROR_TITLES.get(status, f"Error {status}"), message=message, hint=hint)
        resp.status_code = status
        return resp
    except Exception:  # noqa: BLE001 - e.g. the database is down: the error page must not need it
        return Response(f"diysca: {message}", status_code=status, media_type="text/plain")


@app.exception_handler(StarletteHTTPException)
async def _http_error(request: Request, exc: StarletteHTTPException):
    if exc.status_code in _ERROR_TITLES and _browser_page(request):
        default = {404: "This page or item does not exist, or you may not see it.",
                   405: "This address does not accept this kind of request."}
        return _error_page(request, exc.status_code, str(exc.detail) if exc.detail and exc.detail != "Not Found"
                           else default.get(exc.status_code, "The request was refused."))
    return await http_exception_handler(request, exc)


@app.exception_handler(RequestValidationError)
async def _form_error(request: Request, exc: RequestValidationError):
    if _browser_page(request):
        what = "; ".join(f"{'.'.join(str(x) for x in e.get('loc', [])[1:]) or 'input'}: {e.get('msg', 'not valid')}"
                         for e in exc.errors()[:8])
        return _error_page(request, 422, what, "Go back, correct the value and send the form again.")
    return await request_validation_exception_handler(request, exc)


@app.exception_handler(Exception)
async def _crash(request: Request, exc: Exception):
    logging.getLogger("diysca").exception("unhandled error on %s %s", request.method, request.url.path)
    if _browser_page(request):
        return _error_page(request, 500, f"{type(exc).__name__} while handling this page.",
                           "The details are in the diysca log. If it keeps happening, please report it.")
    return JSONResponse({"detail": "internal error"}, 500)


@app.middleware("http")
async def _block_cross_site_changes(request: Request, call_next):
    """CSRF: a change (anything but GET/HEAD/OPTIONS) that a browser sends from another site is refused.
    Bearer tokens are exempt, because a browser never adds those by itself."""
    if request.method not in ("GET", "HEAD", "OPTIONS") and \
            not request.headers.get("authorization", "").lower().startswith("bearer ") and \
            not security.same_origin(request):
        msg = "cross-site request blocked: open diysca directly and try again"
        if _browser_page(request):
            return _error_page(request, 403, "This change was sent from another site, so diysca refused it.",
                               "Open diysca directly and try again. Behind a reverse proxy, make sure it passes "
                               "the Host header on.")
        return JSONResponse({"detail": msg}, 403)
    response = await call_next(request)
    # no framing by other sites (clickjacking), no MIME sniffing, no URLs with filters leaking to other sites
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Content-Security-Policy", "frame-ancestors 'none'")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    return response


# --------------------------------------------------------------- pages
@app.get("/")
def dashboard(request: Request):
    sc = scope_clause("host_id")
    sev = {r["severity"]: r["n"] for r in db.q(
        f"SELECT severity, COUNT(*) n FROM findings WHERE status='open'{sc} GROUP BY severity")}
    week = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=7)).replace(microsecond=0).isoformat()
    stats = db.q1(f"""SELECT (SELECT COUNT(*) FROM hosts WHERE 1=1{scope_clause("id")}) hosts,
                           (SELECT COUNT(*) FROM packages WHERE 1=1{sc}) packages,
                           (SELECT COUNT(*) FROM findings WHERE status='open'{sc}) open,
                           (SELECT COUNT(*) FROM findings WHERE status='open' AND fix_in_repo=1{sc}) fixable,
                           (SELECT COUNT(*) FROM findings WHERE status='open' AND kev=1{sc}) kev,
                           (SELECT COUNT(DISTINCT vuln_id) FROM findings WHERE status='open'{sc}) cves,
                           (SELECT COUNT(DISTINCT vuln_id) FROM findings WHERE status='resolved' AND resolved_at >= ?{sc})
                             patched_7d""", (week,))
    top = db.q(f"""SELECT package, COUNT(DISTINCT vuln_id) cves, COUNT(DISTINCT host_id) hosts,
                  MAX(CASE severity WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 2 ELSE 1 END) worst
                  FROM findings WHERE status='open'{sc} GROUP BY package ORDER BY worst DESC, cves DESC LIMIT 15""")
    sql, p = hosts_query({})
    hosts = db.q(sql + " LIMIT 50", p)
    events = db.q("SELECT * FROM events ORDER BY id DESC LIMIT 15") if not sc else []
    return render(request, "dashboard.html", sev=sev, stats=stats, top=top, hosts=hosts, events=events)

@app.get("/alerts")
def alerts_moved():
    return RedirectResponse("/settings/notifications", 301)


@app.get("/sources")
def sources_moved():
    return RedirectResponse("/settings/sources", 301)


@app.get("/settings")
def settings_general(request: Request):
    from dataclasses import fields

    from diysca.core.config import default_config_path
    rows = []
    for f in fields(settings):
        if f.name in ("sources", "repo_managers"):
            continue
        v = getattr(settings, f.name)
        if any(s in f.name for s in _SECRET_KEYS) and v:
            v = "***"
        rows.append((f.name, _masked(v)))
    return render(request, "settings_general.html", tab="general", rows=rows,
                  config_path=os.environ.get("DIYSCA_CONFIG") or default_config_path(),
                  db_kind="PostgreSQL" if db.is_postgres() else "SQLite")


@app.get("/settings/backup")
def settings_backup(request: Request):
    return render(request, "settings_backup.html", tab="backup", parts=settings_io.PARTS,
                  result=None, msg=request.query_params.get("msg"))


@app.get("/settings/export.yml")
def settings_export(secrets: int = 0, parts: str = ""):
    want = [p for p in parts.split(",") if p in settings_io.PARTS] or list(settings_io.PARTS)
    return Response(settings_io.export_yaml(bool(secrets), want), media_type="application/x-yaml",
                    headers={"Content-Disposition": 'attachment; filename="diysca-settings.yml"'})


@app.post("/settings/import")
async def settings_import(request: Request, file: UploadFile | None = File(None), text: str = Form(""),
                          replace: str = Form(""), dry_run: str = Form("")):
    body = text
    if file is not None and file.filename:
        body = (await file.read()).decode("utf-8", "replace")
    try:
        result = settings_io.import_bundle(settings_io.parse(body), replace=bool(replace), dry_run=bool(dry_run))
    except ValueError as e:
        result = {"added": 0, "updated": 0, "removed": 0, "skipped": [], "errors": [str(e)]}
    result["dry_run"] = bool(dry_run) or bool(result["errors"])
    return render(request, "settings_backup.html", tab="backup", parts=settings_io.PARTS, result=result,
                  msg=None, text=body)


# -------------------------------------------------------------- actions
@app.post("/filters")
def save_filter(name: str = Form(...), page: str = Form(...), query: str = Form("")):
    if page not in ("systems", "packages", "findings"):
        raise HTTPException(400)
    db.x("INSERT INTO saved_filters(name,page,query) VALUES (?,?,?)", (name, page, query))
    return RedirectResponse(security.safe_next(f"/{page}?{query}", f"/{page}"), 303)


@app.post("/filters/{fid}/delete")
def del_filter(fid: int, back: str = Form("/")):
    db.x("DELETE FROM saved_filters WHERE id=?", (fid,))
    return RedirectResponse(security.safe_next(back), 303)


# ------------------------------------------------------------------ MCP
@app.post("/mcp", tags=["mcp"], summary="MCP endpoint")
async def mcp_endpoint(request: Request):
    """Model Context Protocol over streamable HTTP (JSON responses, no server-initiated messages).
    Point an MCP client at `<base_url>/mcp` with `Authorization: Bearer <token>`. See docs/mcp.md."""
    try:
        msg = await request.json()
    except ValueError:
        return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}, 400)
    ctx = mcp.Context(actor=actor(request), is_token=request.state.is_token, user=getattr(request.state, "user", None))
    out = await mcp.handle(msg, ctx)
    if out is None:
        return Response(status_code=202)
    return JSONResponse(out)


@app.get("/mcp", include_in_schema=False)
def mcp_get():
    return Response(status_code=405, headers={"Allow": "POST"})


@app.get("/healthz", tags=["health"], summary="Health check")
def healthz():
    """Always open, also with auth enabled. Use it for container and orchestrator probes. Answers 503 while the
    database can't be reached, so a probe sees more than "the process is up"."""
    try:
        db.q1("SELECT 1 AS ok")
    except Exception as e:  # noqa: BLE001 - whatever the driver raises, the answer is "not healthy"
        return JSONResponse({"ok": False, "version": __version__, "error": f"database: {type(e).__name__}"}, 503)
    return {"ok": True, "version": __version__}


_api_only_in_schema(app.routes)

