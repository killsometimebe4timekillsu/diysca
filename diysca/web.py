"""Web UI + JSON API."""
from __future__ import annotations

import asyncio
import os
import re
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlencode

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates

from . import __version__, db, mcp, mitigate, notify, patch, patched, repomgr, scanner, settings_io, sources
from .config import settings
from .feeds import SEVERITY_ORDER, sev_rank
from .sbom import build_sbom, sbom_json

BASE = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE / "templates"))
templates.env.globals.update(version=__version__, sev_rank=sev_rank)
_basic = HTTPBasic(auto_error=False)
_bg: set[asyncio.Task] = set()


def _token_name(token: str) -> str | None:
    for name, t in (settings.api_tokens or {}).items():
        if t and secrets.compare_digest(str(t), token):
            return name
    return None


def _machine_path(path: str) -> bool:
    return path.startswith("/api/") or path == "/mcp"


def auth(request: Request, creds: HTTPBasicCredentials | None = Depends(_basic)):
    """HTTP basic auth for people, bearer tokens (settings.api_tokens) for agents, CI/CD and MCP clients.

    Tokens only open /api/* and /mcp. Without web_user/web_password the UI is open; once api_tokens are
    configured, /api/* and /mcp need a token or the basic-auth login."""
    path = request.url.path
    request.state.actor = "web"
    request.state.is_token = False
    if path == "/healthz":
        return
    authz = request.headers.get("authorization", "")
    if authz.lower().startswith("bearer "):
        name = _token_name(authz[7:].strip())
        if name and _machine_path(path):
            request.state.actor, request.state.is_token = f"token:{name}", True
            return
        raise HTTPException(401, "invalid API token" if not name else "API tokens only work on /api/* and /mcp",
                            headers={"WWW-Authenticate": "Bearer"})
    basic_on = bool(settings.web_user and settings.web_password)
    if basic_on or (settings.api_tokens and _machine_path(path)):
        if basic_on and creds and secrets.compare_digest(creds.username, settings.web_user) and \
                secrets.compare_digest(creds.password, settings.web_password):
            request.state.actor = creds.username
            return
        raise HTTPException(401, headers={"WWW-Authenticate": "Basic" if basic_on else "Bearer"})


def actor(request: Request) -> str:
    return getattr(request.state, "actor", "web")


@asynccontextmanager
async def lifespan(app):
    db.connect()
    if settings.inventories:
        scanner.import_inventories()
    task = asyncio.create_task(scanner.scheduler())
    yield
    task.cancel()


API_DESCRIPTION = """
JSON API of diysca, the self-hosted CVE scanner and patcher. The full guide with examples is in
[docs/api.md](https://github.com/killsometimebe4timekillsu/diysca/blob/main/docs/api.md).

**Authentication.** People log in with HTTP basic auth (`web_user` / `web_password`). Agents, CI/CD jobs
and MCP clients send `Authorization: Bearer <token>` with a token from `api_tokens`. Tokens only open
`/api/*` and `/mcp`. Without basic auth and without tokens, everything is open (lab setups only).

**Filters.** List endpoints take the same query parameters as the filters in the web UI.

**Mitigations.** Approve findings (`POST /api/mitigations`), then whoever can reach the systems claims the
mitigation, runs its playbook and reports `running`, `done` or `failed`. On `done` diysca rescans the systems.
"""

OPENAPI_TAGS = [
    {"name": "inventory", "description": "Systems and installed packages."},
    {"name": "findings", "description": "Vulnerable packages per system (open, ignored, resolved)."},
    {"name": "mitigations", "description": "Approved findings handed to agents, CI/CD or people who can reach the systems."},
    {"name": "patched", "description": "What was fixed, when and how."},
    {"name": "sources", "description": "Vulnerability data sources."},
    {"name": "scans", "description": "Start scans."},
    {"name": "mcp", "description": "Model Context Protocol endpoint (JSON-RPC 2.0, streamable HTTP, JSON responses)."},
    {"name": "health", "description": "Liveness probe without authentication."},
]

app = FastAPI(title="diysca", version=__version__, description=API_DESCRIPTION, openapi_tags=OPENAPI_TAGS,
              lifespan=lifespan, dependencies=[Depends(auth)])


def _bg_run(coro):
    t = asyncio.create_task(coro)
    _bg.add(t)
    t.add_done_callback(_bg.discard)


def render(request: Request, name: str, **ctx):
    page = name.split(".")[0]
    ctx["saved_filters"] = db.q("SELECT * FROM saved_filters WHERE page=? ORDER BY name", (page,))
    ctx["page"] = page
    ctx["query_string"] = str(request.url.query)
    ctx["running"] = bool(scanner.running) or scanner._scan_lock.locked()
    ctx["extra_source_names"] = ", ".join(r["name"] for r in db.q("SELECT name FROM feed_sources WHERE enabled=1 ORDER BY name"))
    return templates.TemplateResponse(request, name, ctx)


def _like(v: str) -> str:
    return "%" + v.replace("*", "%") + "%"


# ------------------------------------------------------------ filters
def host_filter(args: dict, alias="h"):
    where, p = ["1=1"], []
    if args.get("host"):
        where.append(f"({alias}.name LIKE ? OR {alias}.address LIKE ?)")
        p += [_like(args["host"])] * 2
    if args.get("group"):
        where.append(f"(',' || {alias}.groups || ',') LIKE ?")
        p.append(f"%,{args['group']},%")
    if args.get("os"):
        where.append(f"({alias}.os_pretty LIKE ? OR {alias}.os_id LIKE ?)")
        p += [_like(args["os"])] * 2
    if args.get("kind") in ("host", "container"):
        where.append(f"{alias}.kind=?")
        p.append(args["kind"])
    return where, p


def finding_query(args: dict):
    where, p = host_filter(args)
    status = args.get("status", "open")
    if status and status != "all":
        where.append("f.status=?")
        p.append(status)
    if args.get("package"):
        where.append("(f.package LIKE ? OR f.binaries LIKE ?)")
        p += [_like(args["package"])] * 2
    if args.get("cve"):
        where.append("(f.vuln_id LIKE ? OR f.osv_ids LIKE ?)")
        p += [_like(args["cve"])] * 2
    if args.get("severity"):
        allowed = [s for s in SEVERITY_ORDER if sev_rank(s) >= sev_rank(args["severity"])]
        where.append(f"f.severity IN ({','.join('?' * len(allowed))})")
        p += allowed
    if args.get("fix") == "repo":
        where.append("f.fix_in_repo=1")
    elif args.get("fix") == "upstream":
        where.append("f.fixed_version IS NOT NULL AND f.fix_in_repo=0")
    elif args.get("fix") == "none":
        where.append("f.fixed_version IS NULL")
    if args.get("kev"):
        where.append("f.kev=1")
    eco = args.get("eco")
    if eco == "os":
        where.append("f.ecosystem=''")
    elif eco == "lang":
        where.append("f.ecosystem!=''")
    elif eco:
        where.append("f.ecosystem=?")
        p.append(eco)
    if args.get("approval") == "approved":
        where.append("mi.status IN ('approved','claimed','running')")
    elif args.get("approval") == "unapproved":
        where.append("(mi.id IS NULL OR mi.status NOT IN ('approved','claimed','running'))")
    sql = f"""SELECT f.*, h.name AS host_name, h.groups AS host_groups, mi.status AS mitigation_status
              FROM findings f JOIN hosts h ON h.id=f.host_id LEFT JOIN mitigations mi ON mi.id=f.mitigation_id
              WHERE {' AND '.join(where)}
              ORDER BY f.kev DESC, CASE f.severity WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4 WHEN 'MEDIUM' THEN 3
                       WHEN 'LOW' THEN 2 ELSE 1 END DESC, f.cvss_score DESC, h.name, f.package LIMIT 5000"""
    return sql, p


def package_query(args: dict):
    where, p = host_filter(args)
    if args.get("name"):
        where.append("(pk.name LIKE ? OR pk.source_name LIKE ?)")
        p += [_like(args["name"])] * 2
    if args.get("version"):
        where.append("pk.version LIKE ?")
        p.append(_like(args["version"]))
    if args.get("vulnerable"):
        where.append("""EXISTS(SELECT 1 FROM findings f WHERE f.host_id=pk.host_id AND f.status='open'
                         AND (f.package=pk.source_name OR f.package=pk.name))""")
    eco = args.get("eco")
    if eco == "os":
        where.append("pk.ecosystem=''")
    elif eco == "lang":
        where.append("pk.ecosystem!=''")
    elif eco:
        where.append("pk.ecosystem=?")
        p.append(eco)
    if args.get("upgradable"):
        where.append("pk.repo_version IS NOT NULL AND pk.repo_version != pk.version")
    sql = f"""SELECT pk.*, h.name AS host_name,
                (SELECT COUNT(*) FROM findings f WHERE f.host_id=pk.host_id AND f.status='open'
                   AND f.ecosystem=pk.ecosystem AND (f.package=pk.source_name OR f.package=pk.name)) AS vuln_count
              FROM packages pk JOIN hosts h ON h.id=pk.host_id WHERE {' AND '.join(where)}
              ORDER BY pk.name, h.name LIMIT 5000"""
    return sql, p


def hosts_query(args: dict):
    where, p = host_filter(args)
    if args.get("status"):
        where.append("h.last_status=?")
        p.append(args["status"])
    sql = f"""SELECT h.*,
       (SELECT COUNT(*) FROM packages WHERE host_id=h.id) AS pkg_count,
       (SELECT COUNT(*) FROM findings WHERE host_id=h.id AND status='open') AS open_count,
       (SELECT COUNT(*) FROM findings WHERE host_id=h.id AND status='open' AND severity IN ('CRITICAL','HIGH')) AS high_count,
       (SELECT COUNT(*) FROM findings WHERE host_id=h.id AND status='open' AND fix_in_repo=1) AS fixable_count,
       (SELECT COUNT(*) FROM repos WHERE host_id=h.id) AS repo_count
       FROM hosts h WHERE {' AND '.join(where)} ORDER BY h.name"""
    return sql, p


def all_groups():
    gs = set()
    for r in db.q("SELECT groups FROM hosts"):
        gs |= {g for g in (r["groups"] or "").split(",") if g}
    return sorted(gs)


# --------------------------------------------------------------- pages
@app.get("/")
def dashboard(request: Request):
    sev = {r["severity"]: r["n"] for r in db.q(
        "SELECT severity, COUNT(*) n FROM findings WHERE status='open' GROUP BY severity")}
    stats = db.q1("""SELECT (SELECT COUNT(*) FROM hosts) hosts,
                           (SELECT COUNT(*) FROM packages) packages,
                           (SELECT COUNT(*) FROM findings WHERE status='open') open,
                           (SELECT COUNT(*) FROM findings WHERE status='open' AND fix_in_repo=1) fixable,
                           (SELECT COUNT(*) FROM findings WHERE status='open' AND kev=1) kev,
                           (SELECT COUNT(DISTINCT vuln_id) FROM findings WHERE status='open') cves,
                           (SELECT COUNT(DISTINCT vuln_id) FROM findings WHERE status='resolved' AND resolved_at >= ?) patched_7d""",
                  (patched.window("7d")[1],))
    top = db.q("""SELECT package, COUNT(DISTINCT vuln_id) cves, COUNT(DISTINCT host_id) hosts,
                  MAX(CASE severity WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 2 ELSE 1 END) worst
                  FROM findings WHERE status='open' GROUP BY package ORDER BY worst DESC, cves DESC LIMIT 15""")
    hosts = db.q(hosts_query({})[0] + " LIMIT 50")
    events = db.q("SELECT * FROM events ORDER BY id DESC LIMIT 15")
    return render(request, "dashboard.html", sev=sev, stats=stats, top=top, hosts=hosts, events=events)


@app.get("/systems")
def systems(request: Request):
    args = dict(request.query_params)
    sql, p = hosts_query(args)
    return render(request, "systems.html", hosts=db.q(sql, p), args=args, groups=all_groups(),
                  inventories=settings.inventories)


@app.get("/systems/{host_id}")
def system_detail(request: Request, host_id: int):
    h = db.q1("SELECT * FROM hosts WHERE id=?", (host_id,))
    if not h:
        raise HTTPException(404)
    args = dict(request.query_params)
    fsql, fp = finding_query({**args, "host": None})
    fsql = fsql.replace("WHERE 1=1", "WHERE f.host_id=?", 1)
    findings = db.q(fsql, [host_id] + fp)
    repos = db.q("SELECT * FROM repos WHERE host_id=? ORDER BY kind, url", (host_id,))
    pkgs = db.q("""SELECT pk.*, (SELECT COUNT(*) FROM findings f WHERE f.host_id=pk.host_id AND f.status='open'
                     AND f.ecosystem=pk.ecosystem AND (f.package=pk.source_name OR f.package=pk.name)) AS vuln_count
                   FROM packages pk WHERE host_id=? AND (pk.name LIKE ? OR pk.source_name LIKE ?) ORDER BY vuln_count DESC, name""",
                (host_id, _like(args.get("pkg", "")), _like(args.get("pkg", ""))))
    return render(request, "system.html", h=h, findings=findings, repos=repos, pkgs=pkgs, args=args)


@app.get("/packages")
def packages(request: Request):
    args = dict(request.query_params)
    sql, p = package_query(args)
    return render(request, "packages.html", rows=db.q(sql, p), args=args, groups=all_groups())


@app.get("/findings")
def findings(request: Request):
    args = dict(request.query_params)
    args.setdefault("status", "open")
    sql, p = finding_query(args)
    return render(request, "findings.html", rows=db.q(sql, p), args=args, groups=all_groups(),
                  severities=SEVERITY_ORDER[2:], handoffs=mitigate.handoffs())


@app.get("/findings/{fid}")
def finding_detail(request: Request, fid: int):
    f = db.q1("SELECT f.*, h.name host_name FROM findings f JOIN hosts h ON h.id=f.host_id WHERE f.id=?", (fid,))
    if not f:
        raise HTTPException(404)
    advisories = [db.q1("SELECT * FROM vulns WHERE id=?", (i,)) for i in (f["osv_ids"] or "").split(",") if i]
    nvd = db.q1("SELECT * FROM nvd_cache WHERE cve=?", (f["vuln_id"],))
    kev = db.q1("SELECT * FROM kev WHERE cve=?", (f["vuln_id"],))
    others = db.q("""SELECT f.*, h.name host_name FROM findings f JOIN hosts h ON h.id=f.host_id
                     WHERE f.vuln_id=? AND f.status='open' AND f.id!=? ORDER BY h.name""", (f["vuln_id"], fid))
    sent = db.q("""SELECT n.*, c.name channel FROM notifications n JOIN channels c ON c.id=n.channel_id
                   WHERE n.finding_id=?""", (fid,))
    return render(request, "finding.html", f=f, advisories=[a for a in advisories if a], nvd=nvd, kev=kev,
                  others=others, sent=sent, message=notify.format_finding(f, {"name": f["host_name"]}),
                  hint=notify.action_hint(f), handoffs=mitigate.handoffs(),
                  mitigation=mitigate.get(f["mitigation_id"], with_playbook=False) if f["mitigation_id"] else None)


@app.post("/findings/{fid}/status")
def finding_status(fid: int, status: str = Form(...), back: str = Form("/findings")):
    if status not in ("open", "ignored"):
        raise HTTPException(400)
    db.x("UPDATE findings SET status=? WHERE id=?", (status, fid))
    return RedirectResponse(back, 303)


@app.get("/settings/notifications")
def alerts(request: Request):
    chans = db.q("SELECT * FROM channels ORDER BY name")
    subs = db.q("SELECT s.*, c.name channel FROM subscriptions s JOIN channels c ON c.id=s.channel_id ORDER BY s.name")
    log = db.q("""SELECT n.*, c.name channel, f.vuln_id, f.package, h.name host FROM notifications n
                  JOIN channels c ON c.id=n.channel_id JOIN findings f ON f.id=n.finding_id JOIN hosts h ON h.id=f.host_id
                  ORDER BY n.sent_at DESC LIMIT 50""")
    return render(request, "alerts.html", tab="notifications", chans=chans, subs=subs, log=log, severities=SEVERITY_ORDER[2:],
                  groups=all_groups(), msg=request.query_params.get("msg"))


@app.get("/patched")
def patched_view(request: Request):
    args = dict(request.query_params)
    data = patched.query(args)
    return render(request, "patched.html", args=args, groups=all_groups(), severities=SEVERITY_ORDER[2:],
                  ranges=patched.RANGES, **data)


def _builtin_sources() -> list[dict]:
    bulk = db.q1("SELECT COUNT(*) n, MAX(fetched_at) at FROM osv_bulk_meta")
    return [
        {"name": "OSV.dev", "kind": f"vulnerabilities ({settings.osv_mode})",
         "url": settings.osv_bulk_url if settings.osv_mode == "bulk" else settings.osv_url, "enabled": True,
         "info": f"{bulk['n']} ecosystems mirrored" if settings.osv_mode == "bulk" else "queried per scan",
         "fetched_at": bulk["at"] if settings.osv_mode == "bulk" else None},
        {"name": "NVD", "kind": "CVSS scores", "url": settings.nvd_url, "enabled": settings.nvd_enabled,
         "info": f"{db.q1('SELECT COUNT(*) n FROM nvd_cache')['n']} CVEs cached",
         "fetched_at": db.q1("SELECT MAX(fetched_at) at FROM nvd_cache")["at"]},
        {"name": "CISA KEV", "kind": "known exploited", "url": settings.kev_url, "enabled": settings.kev_enabled,
         "info": f"{db.q1('SELECT COUNT(*) n FROM kev')['n']} CVEs", "fetched_at": None},
    ]


@app.get("/settings/sources")
def sources_view(request: Request):
    sources.sync_config_sources()
    return render(request, "sources.html", tab="sources", builtin=_builtin_sources(), extra=[sources.public(s) for s in sources.all_sources()],
                  types=sources.TYPES, default_urls=sources.DEFAULT_URLS, msg=request.query_params.get("msg"),
                  err=request.query_params.get("err"))


@app.post("/settings/sources")
def add_source(name: str = Form(...), type: str = Form(...), url: str = Form(""), refresh_hours: str = Form("24"),
               options: str = Form("")):
    import yaml
    try:
        cfg = yaml.safe_load(options) or {} if options.strip() else {}
        if not isinstance(cfg, dict):
            raise ValueError("Options must be YAML key: value pairs.")
        if url.strip():
            cfg["url"] = url.strip()
        cfg["refresh_hours"] = float(refresh_hours or 24)
        sources.save(name.strip(), type, cfg)
    except (ValueError, yaml.YAMLError) as e:
        return RedirectResponse("/settings/sources?" + urlencode({"err": str(e)}), 303)
    _bg_run(sources.refresh(name.strip()))
    return RedirectResponse("/settings/sources?" + urlencode({"msg": f"Added {name}. Downloading it now."}), 303)


@app.post("/settings/sources/{name}/refresh")
def refresh_source(name: str):
    if not sources.get(name):
        raise HTTPException(404)
    _bg_run(sources.refresh(name))
    return RedirectResponse("/settings/sources?" + urlencode({"msg": f"Refreshing {name}. Reload in a moment."}), 303)


@app.post("/settings/sources/{name}/toggle")
def toggle_source(name: str):
    db.x("UPDATE feed_sources SET enabled=1-enabled WHERE name=? AND origin='ui'", (name,))
    return RedirectResponse("/settings/sources", 303)


@app.post("/settings/sources/{name}/delete")
def delete_source(name: str):
    s = sources.get(name)
    if s and s["origin"] == "ui":
        sources.remove(name)
    return RedirectResponse("/settings/sources", 303)


@app.get("/alerts")
def alerts_moved():
    return RedirectResponse("/settings/notifications", 301)


@app.get("/sources")
def sources_moved():
    return RedirectResponse("/settings/sources", 301)


_SECRET_KEYS = ("password", "token", "api_key", "secret")


def _masked(v):
    if isinstance(v, dict):
        return {k: ("***" if any(s in k for s in _SECRET_KEYS) and v[k] and not k.endswith("_env") else _masked(x))
                for k, x in v.items()}
    if isinstance(v, list):
        return [_masked(x) for x in v]
    if isinstance(v, str) and "://" in v and "@" in v:
        return re.sub(r"://[^@/]*@", "://***@", v)
    return v


@app.get("/settings")
def settings_general(request: Request):
    from dataclasses import fields
    from .config import default_config_path
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


@app.get("/settings/repos")
def settings_repos(request: Request):
    import yaml
    mgrs = [{"name": m["name"], "type": m.get("type"), "url": m.get("url"), "match": m.get("match"),
             "yaml": yaml.safe_dump(_masked(m), sort_keys=False)} for m in repomgr.managers()]
    return render(request, "settings_repos.html", tab="repos", mgrs=mgrs)


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
@app.post("/scan")
async def scan_all_now():
    _bg_run(scanner.scan_all())
    return RedirectResponse("/systems", 303)


@app.post("/systems/{host_id}/scan")
async def scan_one(host_id: int):
    async def run():
        await scanner.refresh_kev()
        await scanner.scan_host(host_id)
    _bg_run(run())
    return RedirectResponse(f"/systems/{host_id}", 303)


@app.post("/systems")
def add_system(name: str = Form(...), address: str = Form(""), port: int = Form(22), ssh_user: str = Form(""),
               groups: str = Form(""), connection: str = Form("ssh")):
    db.x("""INSERT INTO hosts(name,address,port,ssh_user,groups,connection,source) VALUES (?,?,?,?,?,?, 'manual')
            ON CONFLICT(name) DO UPDATE SET address=excluded.address, port=excluded.port, ssh_user=excluded.ssh_user,
            groups=excluded.groups, connection=excluded.connection""",
         (name, address or name, port, ssh_user or None, groups.replace(" ", ""), connection))
    return RedirectResponse("/systems", 303)


@app.post("/systems/{host_id}/delete")
def delete_system(host_id: int):
    db.x("DELETE FROM hosts WHERE id=?", (host_id,))
    return RedirectResponse("/systems", 303)


@app.post("/systems/{host_id}/toggle")
def toggle_system(host_id: int):
    db.x("UPDATE hosts SET enabled = 1 - enabled WHERE id=?", (host_id,))
    return RedirectResponse("/systems", 303)


@app.post("/inventory/import")
def inventory_import(path: str = Form("")):
    paths = [path] if path else None
    n = scanner.import_inventories(paths)
    if path and path not in settings.inventories:
        settings.inventories.append(path)
    db.event("inventory", f"manual import: {n} hosts")
    return RedirectResponse("/systems", 303)


@app.get("/systems/{host_id}/reprovision.yml")
def reprovision_host(host_id: int, mode: str = "fixed", target: str = ""):
    from . import reprovision
    h = db.q1("SELECT name FROM hosts WHERE id=?", (host_id,))
    if not h:
        raise HTTPException(404)
    try:
        text, _ = reprovision.for_host(host_id, "exact" if mode == "exact" else "fixed", target.strip() or None)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return Response(text, media_type="application/x-yaml",
                    headers={"Content-Disposition": f'attachment; filename="reprovision-{h["name"]}.yml"'})


@app.post("/reprovision")
async def reprovision_upload(request: Request, file: UploadFile = File(...), mode: str = Form("fixed"),
                             target: str = Form("")):
    import json as _json

    from . import reprovision
    try:
        sbom_doc = _json.loads((await file.read()).decode("utf-8", "replace"))
        text, summary = reprovision.build(sbom_doc, "exact" if mode == "exact" else "fixed", target.strip() or None)
    except ValueError as e:
        ctx = _patching_ctx()
        ctx["reprovision_error"] = f"{file.filename}: {e}"
        return render(request, "patching.html", **ctx)
    return Response(text, media_type="application/x-yaml",
                    headers={"Content-Disposition": f'attachment; filename="reprovision-{summary["system"]}.yml"'})


@app.get("/systems/{host_id}/sbom.json")
def sbom(host_id: int):
    h = db.q1("SELECT name FROM hosts WHERE id=?", (host_id,))
    if not h:
        raise HTTPException(404)
    return Response(sbom_json(host_id), media_type="application/vnd.cyclonedx+json",
                    headers={"Content-Disposition": f'attachment; filename="{h["name"]}.cdx.json"'})


@app.post("/channels")
def add_channel(name: str = Form(...), url: str = Form(...)):
    db.x("INSERT INTO channels(name,url) VALUES (?,?) ON CONFLICT(name) DO UPDATE SET url=excluded.url", (name, url))
    return RedirectResponse("/settings/notifications", 303)


@app.post("/channels/{cid}/delete")
def del_channel(cid: int):
    db.x("DELETE FROM channels WHERE id=?", (cid,))
    return RedirectResponse("/settings/notifications", 303)


@app.post("/channels/{cid}/test")
async def test_channel(cid: int):
    ch = db.q1("SELECT * FROM channels WHERE id=?", (cid,))
    ok, err = await notify.send_to_channel(ch, "[diysca] test", "Test notification from diysca. It works!")
    return RedirectResponse("/settings/notifications?" + urlencode({"msg": f"{ch['name']}: " + ("sent" if ok else err)}), 303)


@app.post("/subscriptions")
def add_sub(name: str = Form(...), channel_id: int = Form(...), host_pattern: str = Form("*"),
            package_pattern: str = Form("*"), min_severity: str = Form("LOW"), only_kev: str = Form(""),
            only_fixable: str = Form(""), sub_id: str = Form("")):
    vals = (name, channel_id, host_pattern or "*", package_pattern or "*", min_severity,
            int(bool(only_kev)), int(bool(only_fixable)))
    if sub_id:
        db.x("""UPDATE subscriptions SET name=?, channel_id=?, host_pattern=?, package_pattern=?, min_severity=?,
                only_kev=?, only_fixable=? WHERE id=?""", vals + (int(sub_id),))
    else:
        db.x("""INSERT INTO subscriptions(name,channel_id,host_pattern,package_pattern,min_severity,only_kev,only_fixable)
                VALUES (?,?,?,?,?,?,?)""", vals)
    return RedirectResponse("/settings/notifications", 303)


@app.post("/subscriptions/{sid}/delete")
def del_sub(sid: int):
    db.x("DELETE FROM subscriptions WHERE id=?", (sid,))
    return RedirectResponse("/settings/notifications", 303)


@app.post("/subscriptions/{sid}/toggle")
def toggle_sub(sid: int):
    db.x("UPDATE subscriptions SET enabled = 1 - enabled WHERE id=?", (sid,))
    return RedirectResponse("/settings/notifications", 303)


@app.post("/settings/notifications/dispatch")
async def dispatch_now():
    n = await notify.dispatch()
    return RedirectResponse("/settings/notifications?" + urlencode({"msg": f"sent {n} alerts"}), 303)


@app.post("/filters")
def save_filter(name: str = Form(...), page: str = Form(...), query: str = Form("")):
    if page not in ("systems", "packages", "findings"):
        raise HTTPException(400)
    db.x("INSERT INTO saved_filters(name,page,query) VALUES (?,?,?)", (name, page, query))
    return RedirectResponse(f"/{page}?{query}", 303)


@app.post("/filters/{fid}/delete")
def del_filter(fid: int, back: str = Form("/")):
    db.x("DELETE FROM saved_filters WHERE id=?", (fid,))
    return RedirectResponse(back, 303)


# ------------------------------------------------------------- patching
def _patching_ctx() -> dict:
    hosts = db.q("""SELECT h.id, h.name, h.os_pretty, h.kind,
                      SUM(CASE WHEN f.fix_in_repo=1 AND f.ecosystem='' THEN 1 ELSE 0 END) AS fixable,
                      SUM(CASE WHEN f.fix_in_repo=0 AND f.fixed_version IS NOT NULL AND f.ecosystem='' THEN 1 ELSE 0 END) AS repo_behind,
                      SUM(CASE WHEN f.ecosystem!='' THEN 1 ELSE 0 END) AS lang
                    FROM hosts h JOIN findings f ON f.host_id=h.id AND f.status='open'
                    GROUP BY h.id, h.name, h.os_pretty, h.kind ORDER BY fixable DESC, h.name""")
    mgrs = []
    for m in repomgr.managers():
        pend = repomgr.pending_for(m)
        mgrs.append({"name": m["name"], "type": m.get("type"), "url": m.get("url"), "match": m.get("match"),
                     "stages": m.get("promote_to") or [], "pending": pend[:50], "pending_count": len(pend)})
    return {"hosts": hosts, "mgrs": mgrs, "result": None}


@app.get("/patching")
def patching(request: Request):
    return render(request, "patching.html", **_patching_ctx())


def _ids_from_filter(query: str) -> list[int]:
    from urllib.parse import parse_qsl
    args = dict(parse_qsl(query))
    args.setdefault("status", "open")
    sql, p = finding_query(args)
    return [r["id"] for r in db.q(sql, p)]


@app.post("/patch/playbook")
async def patch_playbook(request: Request):
    form = await request.form()
    ids = [int(i) for i in form.getlist("ids") if str(i).isdigit()]
    if not ids and form.get("filter") is not None:
        ids = _ids_from_filter(str(form.get("filter")))
    if form.get("host_id"):
        ids = [r["id"] for r in db.q("SELECT id FROM findings WHERE host_id=? AND status='open'",
                                     (int(form.get("host_id")),))]
    text, summary = patch.build_playbook(ids)
    msg = f"playbook generated: {summary['hosts']} hosts, {summary['packages']} packages, {summary['manual']} manual items"
    db.event("patch", msg)
    if summary["hosts"]:
        db.patch_run("playbook", msg)
    return Response(text, media_type="application/x-yaml",
                    headers={"Content-Disposition": 'attachment; filename="diysca-patch.yml"'})


@app.post("/repos/{name}/run")
async def repo_run(request: Request, name: str):
    form = await request.form()
    dry = form.get("dry_run", "1") == "1"
    stages = form.getlist("stages") if form.get("stages_given") else None
    try:
        res = await repomgr.run(name, dry_run=dry, stages=stages)
    except KeyError:
        raise HTTPException(404)
    if not dry and res.ok and form.get("rescan"):
        ids = sorted({db.q1("SELECT id FROM hosts WHERE name=?", (p["host_name"],))["id"]
                      for p in repomgr.pending_for(repomgr.get_manager(name))})
        _bg_run(scanner.scan_all(host_ids=ids or None))
    return render(request, "patching.html", **{**_patching_ctx(), "result": res})




# ------------------------------------------------------------- mitigations (UI)
def _form_ids(form) -> list[int]:
    ids = [int(i) for i in form.getlist("ids") if str(i).isdigit()]
    if not ids and form.get("filter") is not None:
        ids = _ids_from_filter(str(form.get("filter")))
    if not ids and form.get("finding_id"):
        ids = [int(form.get("finding_id"))]
    return ids


@app.get("/mitigations")
def mitigations_view(request: Request, status: str = "open"):
    return render(request, "mitigations.html", rows=mitigate.list_(status), status=status,
                  statuses=("open",) + mitigate.STATUSES + ("all",), handoffs=mitigate.handoffs())


@app.post("/mitigations")
async def mitigation_create(request: Request):
    form = await request.form()
    try:
        m = await asyncio.to_thread(mitigate.approve, _form_ids(form), actor(request), str(form.get("note") or ""),
                                    str(form.get("handoff") or "") or None, bool(form.get("rescan", "1") == "1"))
    except mitigate.MitigationError as e:
        return RedirectResponse(f"/mitigations?{urlencode({'error': str(e)})}", 303)
    return RedirectResponse(f"/mitigations/{m['id']}", 303)


@app.get("/mitigations/{mid}")
def mitigation_view(request: Request, mid: int):
    m = mitigate.get(mid)
    if not m:
        raise HTTPException(404)
    return render(request, "mitigation.html", mi=m, handoffs=mitigate.handoffs(), msg=request.query_params.get("msg"))


@app.get("/mitigations/{mid}/playbook.yml", include_in_schema=False)
def mitigation_playbook_ui(mid: int):
    return api_mitigation_playbook(mid)


@app.post("/mitigations/{mid}/cancel")
def mitigation_cancel_ui(request: Request, mid: int, reason: str = Form("")):
    try:
        mitigate.cancel(mid, actor(request), reason)
    except mitigate.MitigationError as e:
        return RedirectResponse(f"/mitigations/{mid}?{urlencode({'msg': str(e)})}", 303)
    return RedirectResponse(f"/mitigations/{mid}", 303)


@app.post("/mitigations/{mid}/report")
async def mitigation_report_ui(request: Request, mid: int, status: str = Form(...), log: str = Form("")):
    try:
        _, rescan = await asyncio.to_thread(mitigate.report, mid, status, actor(request), log)
    except mitigate.MitigationError as e:
        return RedirectResponse(f"/mitigations/{mid}?{urlencode({'msg': str(e)})}", 303)
    if rescan:
        _bg_run(scanner.scan_all(host_ids=rescan))
    return RedirectResponse(f"/mitigations/{mid}", 303)


@app.post("/mitigations/{mid}/handoff")
async def mitigation_handoff_ui(mid: int, target: str = Form(...)):
    ok, res = await asyncio.to_thread(mitigate.deliver, mid, target)
    return RedirectResponse(f"/mitigations/{mid}?{urlencode({'msg': ('Sent: ' if ok else 'Failed: ') + res})}", 303)


@app.get("/settings/handoff")
def handoff_view(request: Request):
    return render(request, "settings_handoff.html", tab="handoff", targets=mitigate.handoffs(), types=mitigate.HANDOFF_TYPES,
                  tokens=sorted(settings.api_tokens or {}), msg=request.query_params.get("msg"))


@app.post("/settings/handoff")
async def handoff_save(request: Request):
    form = await request.form()
    cfg = {}
    if form.get("ref"):
        cfg["ref"] = str(form.get("ref"))
    if form.get("event_type"):
        cfg["event_type"] = str(form.get("event_type"))
    try:
        mitigate.save_handoff(str(form.get("name") or ""), str(form.get("type") or ""), str(form.get("url") or ""),
                              str(form.get("token")) if form.get("token") else None, cfg,
                              enabled=True, auto=form.get("auto") == "1")
    except mitigate.MitigationError as e:
        return RedirectResponse(f"/settings/handoff?{urlencode({'msg': str(e)})}", 303)
    return RedirectResponse("/settings/handoff?msg=saved", 303)


@app.post("/settings/handoff/{name}/delete")
def handoff_delete(name: str):
    mitigate.remove_handoff(name)
    return RedirectResponse("/settings/handoff", 303)


# ------------------------------------------------------------------ API
def rows(r):
    return [dict(x) for x in r]


@app.get("/api/hosts", tags=["inventory"], summary="List systems")
def api_hosts(request: Request):
    """Systems (hosts and containers) with open-finding counts.

    Query parameters: `host` (name or address, `*` wildcards), `group`, `os`, `kind` (`host` / `container`)."""
    sql, p = hosts_query(dict(request.query_params))
    return rows(db.q(sql, p))


@app.get("/api/packages", tags=["inventory"], summary="List installed packages")
def api_packages(request: Request):
    """Installed packages across systems.

    Query parameters: `name`, `version`, `host`, `group`, `os`, `eco` (`os`, `lang` or an ecosystem such as
    `PyPI`), `vulnerable=1`, `upgradable=1` (the repos offer a newer version)."""
    sql, p = package_query(dict(request.query_params))
    return rows(db.q(sql, p))


@app.get("/api/findings", tags=["findings"], summary="List findings")
def api_findings(request: Request):
    """Vulnerable packages, worst first (KEV, severity, CVSS). At most 5000 rows.

    Query parameters: `status` (`open` default, `ignored`, `resolved`, `all`), `host`, `group`, `os`, `package`,
    `cve`, `severity` (minimum: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), `fix` (`repo` = fix in your repos,
    `upstream` = released but not in your repos, `none`), `kev=1`, `eco`, `approval` (`approved` = in an open
    mitigation, `unapproved`)."""
    args = dict(request.query_params)
    args.setdefault("status", "open")
    sql, p = finding_query(args)
    return rows(db.q(sql, p))


@app.get("/api/findings/{fid}", tags=["findings"], summary="Get one finding")
def api_finding(fid: int):
    """One finding with its system, the advisories that report it and the mitigation it is approved in."""
    f = db.q1("""SELECT f.*, h.name host_name FROM findings f JOIN hosts h ON h.id=f.host_id WHERE f.id=?""", (fid,))
    if not f:
        raise HTTPException(404)
    out = dict(f)
    out["mitigation"] = mitigate.get(f["mitigation_id"], with_playbook=False) if f["mitigation_id"] else None
    return out


@app.get("/api/patched", tags=["patched"], summary="Patched findings in a time range")
def api_patched(request: Request):
    """Findings that went away in a time range, with how (`upgraded`, `removed`, `not-affected`).

    Query parameters: `range` (`last` = each system's latest patching, `24h`, `7d`, `30d`, `90d`, `1y`, `custom`),
    `from` / `to` (dates, with `range=custom`), `host`, `group`, `severity`, `eco`, `how`."""
    d = patched.query(dict(request.query_params))
    return {"range": d["range"], "start": d["start"], "end": d["end"], "stats": d["stats"], "findings": rows(d["rows"])}


@app.get("/api/sources", tags=["sources"], summary="List vulnerability sources")
def api_sources():
    """Extra vulnerability sources with their state. Header values are masked."""
    return [sources.public(s) for s in sources.all_sources()]


@app.get("/api/hosts/{host_id}/sbom", tags=["inventory"], summary="CycloneDX SBOM of a system")
def api_sbom(host_id: int):
    """CycloneDX 1.5 JSON with OS packages, language packages, container images, repos and OS facts."""
    try:
        return JSONResponse(build_sbom(host_id))
    except KeyError:
        raise HTTPException(404)


@app.post("/api/scan", tags=["scans"], summary="Scan one or all systems")
async def api_scan(host: str | None = None):
    """Scans now and waits for the result. `host` = system name; without it, every enabled system is scanned."""
    if host:
        h = db.q1("SELECT id FROM hosts WHERE name=?", (host,))
        if not h:
            raise HTTPException(404)
        return await scanner.scan_host(h["id"])
    return await scanner.scan_all()


# ------------------------------------------------------------------ API: mitigations
@app.get("/api/mitigations", tags=["mitigations"], summary="List mitigations")
def api_mitigations(status: str = "open"):
    """`status`: `open` (approved, claimed or running; default), `approved` (waiting for someone to claim it),
    `claimed`, `running`, `done`, `failed`, `cancelled` or `all`. The playbook is left out; fetch it per mitigation."""
    return mitigate.list_(status)


@app.post("/api/mitigations", tags=["mitigations"], summary="Approve findings for mitigation", status_code=201)
async def api_mitigation_create(request: Request):
    """Body (JSON): `finding_ids` (list) or `filter` (a findings query string, e.g. `host=web1&fix=repo`),
    optional `note`, `handoff` (target name; without it, targets marked *auto* are used) and `rescan` (default
    true). Only open findings are taken. Token holders may approve only when `agents_can_approve` is set."""
    if request.state.is_token and not settings.agents_can_approve:
        raise HTTPException(403, "approving needs a person (or agents_can_approve: true)")
    body = await request.json()
    ids = [int(i) for i in body.get("finding_ids") or []]
    if not ids and body.get("filter") is not None:
        ids = _ids_from_filter(str(body["filter"]))
    try:
        return await asyncio.to_thread(mitigate.approve, ids, actor(request), str(body.get("note") or ""),
                                       body.get("handoff") or None, bool(body.get("rescan", True)))
    except mitigate.MitigationError as e:
        raise HTTPException(422, str(e))


@app.get("/api/mitigations/{mid}", tags=["mitigations"], summary="Get a mitigation")
def api_mitigation(mid: int):
    """The mitigation with its findings, the playbook (YAML text), log and links."""
    m = mitigate.get(mid)
    if not m:
        raise HTTPException(404)
    return m


@app.get("/api/mitigations/{mid}/playbook.yml", tags=["mitigations"], summary="Playbook of a mitigation")
def api_mitigation_playbook(mid: int):
    """The Ansible playbook created at approval time, pinned to the versions your repos offered then.
    Items a playbook can't fix (language packages, images, fixes not yet in your repos) are comments at the top."""
    m = db.q1("SELECT playbook FROM mitigations WHERE id=?", (mid,))
    if not m:
        raise HTTPException(404)
    return Response(m["playbook"] or "", media_type="application/x-yaml",
                    headers={"Content-Disposition": f'attachment; filename="diysca-mitigation-{mid}.yml"'})


@app.post("/api/mitigations/{mid}/claim", tags=["mitigations"], summary="Claim a mitigation")
def api_mitigation_claim(request: Request, mid: int):
    """Marks an `approved` mitigation as yours, so no other agent runs it. 409 if it isn't `approved` any more."""
    try:
        return mitigate.claim(mid, actor(request))
    except KeyError:
        raise HTTPException(404)
    except mitigate.MitigationError as e:
        raise HTTPException(409, str(e))


@app.post("/api/mitigations/{mid}/report", tags=["mitigations"], summary="Report progress")
async def api_mitigation_report(request: Request, mid: int):
    """Body (JSON): `status` (`running`, `done` or `failed`) and optional `log` (text, e.g. the ansible output).
    On `done` the affected systems are rescanned in the background (unless the mitigation was created with
    `rescan: false`), and the channels that alerted about the findings are told."""
    body = await request.json()
    try:
        m, rescan = await asyncio.to_thread(mitigate.report, mid, str(body.get("status") or ""), actor(request),
                                            str(body.get("log") or ""))
    except KeyError:
        raise HTTPException(404)
    except mitigate.MitigationError as e:
        raise HTTPException(409, str(e))
    if rescan:
        _bg_run(scanner.scan_all(host_ids=rescan))
    return {**m, "rescan_hosts": rescan}


@app.post("/api/mitigations/{mid}/cancel", tags=["mitigations"], summary="Cancel a mitigation")
async def api_mitigation_cancel(request: Request, mid: int):
    """Optional body (JSON): `reason`. The findings can be approved again afterwards."""
    if request.state.is_token and not settings.agents_can_approve:
        raise HTTPException(403, "cancelling needs a person (or agents_can_approve: true)")
    try:
        body = await request.json()
    except ValueError:
        body = {}
    try:
        return mitigate.cancel(mid, actor(request), str((body or {}).get("reason") or ""))
    except KeyError:
        raise HTTPException(404)
    except mitigate.MitigationError as e:
        raise HTTPException(409, str(e))


# ------------------------------------------------------------------ MCP
@app.post("/mcp", tags=["mcp"], summary="MCP endpoint")
async def mcp_endpoint(request: Request):
    """Model Context Protocol over streamable HTTP (JSON responses, no server-initiated messages).
    Point an MCP client at `<base_url>/mcp` with `Authorization: Bearer <token>`. See docs/mcp.md."""
    try:
        msg = await request.json()
    except ValueError:
        return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}, 400)
    ctx = mcp.Context(actor=actor(request), is_token=request.state.is_token)
    out = await mcp.handle(msg, ctx)
    if out is None:
        return Response(status_code=202)
    return JSONResponse(out)


@app.get("/mcp", include_in_schema=False)
def mcp_get():
    return Response(status_code=405, headers={"Allow": "POST"})


@app.get("/healthz", tags=["health"], summary="Health check")
def healthz():
    """Always open, also with auth enabled. Use it for container and orchestrator probes."""
    return {"ok": True, "version": __version__}


for _r in app.routes:  # the OpenAPI document covers the machine API, not the HTML pages
    if getattr(_r, "path", "").startswith(("/api/", "/mcp", "/healthz")) is False and hasattr(_r, "include_in_schema"):
        _r.include_in_schema = False
