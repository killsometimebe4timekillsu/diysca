"""Web UI + JSON API."""
from __future__ import annotations

import asyncio
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlencode

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates

from . import __version__, db, notify, patch, patched, repomgr, scanner, sources
from .config import settings
from .feeds import SEVERITY_ORDER, sev_rank
from .sbom import build_sbom, sbom_json

BASE = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE / "templates"))
templates.env.globals.update(version=__version__, sev_rank=sev_rank)
_basic = HTTPBasic(auto_error=False)
_bg: set[asyncio.Task] = set()


def auth(request: Request, creds: HTTPBasicCredentials | None = Depends(_basic)):
    if not (settings.web_user and settings.web_password) or request.url.path == "/healthz":
        return
    if creds and secrets.compare_digest(creds.username, settings.web_user) and \
            secrets.compare_digest(creds.password, settings.web_password):
        return
    raise HTTPException(401, headers={"WWW-Authenticate": "Basic"})


@asynccontextmanager
async def lifespan(app):
    db.connect()
    if settings.inventories:
        scanner.import_inventories()
    task = asyncio.create_task(scanner.scheduler())
    yield
    task.cancel()


app = FastAPI(title="diysca", lifespan=lifespan, dependencies=[Depends(auth)])


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
    sql = f"""SELECT f.*, h.name AS host_name, h.groups AS host_groups FROM findings f JOIN hosts h ON h.id=f.host_id
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
                  severities=SEVERITY_ORDER[2:])


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
                  others=others, sent=sent, message=notify.format_finding(f, {"name": f["host_name"]}))


@app.post("/findings/{fid}/status")
def finding_status(fid: int, status: str = Form(...), back: str = Form("/findings")):
    if status not in ("open", "ignored"):
        raise HTTPException(400)
    db.x("UPDATE findings SET status=? WHERE id=?", (status, fid))
    return RedirectResponse(back, 303)


@app.get("/alerts")
def alerts(request: Request):
    chans = db.q("SELECT * FROM channels ORDER BY name")
    subs = db.q("SELECT s.*, c.name channel FROM subscriptions s JOIN channels c ON c.id=s.channel_id ORDER BY s.name")
    log = db.q("""SELECT n.*, c.name channel, f.vuln_id, f.package, h.name host FROM notifications n
                  JOIN channels c ON c.id=n.channel_id JOIN findings f ON f.id=n.finding_id JOIN hosts h ON h.id=f.host_id
                  ORDER BY n.sent_at DESC LIMIT 50""")
    return render(request, "alerts.html", chans=chans, subs=subs, log=log, severities=SEVERITY_ORDER[2:],
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


@app.get("/sources")
def sources_view(request: Request):
    sources.sync_config_sources()
    return render(request, "sources.html", builtin=_builtin_sources(), extra=[sources.public(s) for s in sources.all_sources()],
                  types=sources.TYPES, default_urls=sources.DEFAULT_URLS, msg=request.query_params.get("msg"),
                  err=request.query_params.get("err"))


@app.post("/sources")
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
        return RedirectResponse("/sources?" + urlencode({"err": str(e)}), 303)
    _bg_run(sources.refresh(name.strip()))
    return RedirectResponse("/sources?" + urlencode({"msg": f"Added {name}. Downloading it now."}), 303)


@app.post("/sources/{name}/refresh")
def refresh_source(name: str):
    if not sources.get(name):
        raise HTTPException(404)
    _bg_run(sources.refresh(name))
    return RedirectResponse("/sources?" + urlencode({"msg": f"Refreshing {name}. Reload in a moment."}), 303)


@app.post("/sources/{name}/toggle")
def toggle_source(name: str):
    db.x("UPDATE feed_sources SET enabled=1-enabled WHERE name=? AND origin='ui'", (name,))
    return RedirectResponse("/sources", 303)


@app.post("/sources/{name}/delete")
def delete_source(name: str):
    s = sources.get(name)
    if s and s["origin"] == "ui":
        sources.remove(name)
    return RedirectResponse("/sources", 303)


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
    return RedirectResponse("/alerts", 303)


@app.post("/channels/{cid}/delete")
def del_channel(cid: int):
    db.x("DELETE FROM channels WHERE id=?", (cid,))
    return RedirectResponse("/alerts", 303)


@app.post("/channels/{cid}/test")
async def test_channel(cid: int):
    ch = db.q1("SELECT * FROM channels WHERE id=?", (cid,))
    ok, err = await notify.send_to_channel(ch, "[diysca] test", "Test notification from diysca. It works!")
    return RedirectResponse("/alerts?" + urlencode({"msg": f"{ch['name']}: " + ("sent" if ok else err)}), 303)


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
    return RedirectResponse("/alerts", 303)


@app.post("/subscriptions/{sid}/delete")
def del_sub(sid: int):
    db.x("DELETE FROM subscriptions WHERE id=?", (sid,))
    return RedirectResponse("/alerts", 303)


@app.post("/subscriptions/{sid}/toggle")
def toggle_sub(sid: int):
    db.x("UPDATE subscriptions SET enabled = 1 - enabled WHERE id=?", (sid,))
    return RedirectResponse("/alerts", 303)


@app.post("/alerts/dispatch")
async def dispatch_now():
    n = await notify.dispatch()
    return RedirectResponse("/alerts?" + urlencode({"msg": f"sent {n} alerts"}), 303)


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


# ------------------------------------------------------------------ API
def rows(r):
    return [dict(x) for x in r]


@app.get("/api/hosts")
def api_hosts(request: Request):
    sql, p = hosts_query(dict(request.query_params))
    return rows(db.q(sql, p))


@app.get("/api/packages")
def api_packages(request: Request):
    sql, p = package_query(dict(request.query_params))
    return rows(db.q(sql, p))


@app.get("/api/findings")
def api_findings(request: Request):
    args = dict(request.query_params)
    args.setdefault("status", "open")
    sql, p = finding_query(args)
    return rows(db.q(sql, p))


@app.get("/api/patched")
def api_patched(request: Request):
    d = patched.query(dict(request.query_params))
    return {"range": d["range"], "start": d["start"], "end": d["end"], "stats": d["stats"], "findings": rows(d["rows"])}


@app.get("/api/sources")
def api_sources():
    return [sources.public(s) for s in sources.all_sources()]


@app.get("/api/hosts/{host_id}/sbom")
def api_sbom(host_id: int):
    try:
        return JSONResponse(build_sbom(host_id))
    except KeyError:
        raise HTTPException(404)


@app.post("/api/scan")
async def api_scan(host: str | None = None):
    if host:
        h = db.q1("SELECT id FROM hosts WHERE name=?", (host,))
        if not h:
            raise HTTPException(404)
        return await scanner.scan_host(h["id"])
    return await scanner.scan_all()


@app.get("/healthz")
def healthz():
    return {"ok": True, "version": __version__}
