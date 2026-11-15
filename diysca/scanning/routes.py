"""Scanning module: systems, packages, findings, CVE sources, scans, SBOMs (pages and API)."""
from __future__ import annotations

from urllib.parse import urlencode

from fastapi import APIRouter, Form, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from diysca.core import db, modules, scope
from diysca.core.config import settings
from diysca.scanning import scanner, sources
from diysca.scanning.describe import action_hint, format_finding
from diysca.scanning.feeds import SEVERITY_ORDER
from diysca.scanning.sbom import build_sbom, sbom_json
from diysca.ui import (
    _bg_run,
    _like,
    all_groups,
    check_host,
    finding_query,
    hosts_query,
    package_query,
    render,
    rows,
    scope_clause,
)

router = APIRouter()


def _handoffs() -> list:
    if not modules.enabled("mitigation"):
        return []
    from diysca.mitigation import mitigate
    return mitigate.handoffs()


def _mitigation(mid):
    if not mid or not modules.enabled("mitigation"):
        return None
    from diysca.mitigation import mitigate
    return mitigate.get(mid, with_playbook=False)


@router.get("/systems")
def systems(request: Request):
    args = dict(request.query_params)
    sql, p = hosts_query(args)
    return render(request, "systems.html", hosts=db.q(sql, p), args=args, groups=all_groups(),
                  inventories=settings.inventories)


@router.get("/systems/{host_id}")
def system_detail(request: Request, host_id: int):
    check_host(host_id)
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


@router.get("/packages")
def packages(request: Request):
    args = dict(request.query_params)
    sql, p = package_query(args)
    return render(request, "packages.html", rows=db.q(sql, p), args=args, groups=all_groups())


@router.get("/findings")
def findings(request: Request):
    args = dict(request.query_params)
    args.setdefault("status", "open")
    sql, p = finding_query(args)
    return render(request, "findings.html", rows=db.q(sql, p), args=args, groups=all_groups(),
                  severities=SEVERITY_ORDER[2:], handoffs=_handoffs())


@router.get("/findings/{fid}")
def finding_detail(request: Request, fid: int):
    f = db.q1("SELECT f.*, h.name host_name FROM findings f JOIN hosts h ON h.id=f.host_id WHERE f.id=?", (fid,))
    if not f:
        raise HTTPException(404)
    check_host(f["host_id"])
    advisories = [db.q1("SELECT * FROM vulns WHERE id=?", (i,)) for i in (f["osv_ids"] or "").split(",") if i]
    nvd = db.q1("SELECT * FROM nvd_cache WHERE cve=?", (f["vuln_id"],))
    kev = db.q1("SELECT * FROM kev WHERE cve=?", (f["vuln_id"],))
    others = db.q(f"""SELECT f.*, h.name host_name FROM findings f JOIN hosts h ON h.id=f.host_id
                     WHERE f.vuln_id=? AND f.status='open' AND f.id!=?{scope_clause("h.id")} ORDER BY h.name""",
                  (f["vuln_id"], fid))
    sent = db.q("""SELECT n.*, c.name channel FROM notifications n JOIN channels c ON c.id=n.channel_id
                   WHERE n.finding_id=?""", (fid,))
    return render(request, "finding.html", f=f, advisories=[a for a in advisories if a], nvd=nvd, kev=kev,
                  others=others, sent=sent, message=format_finding(f, {"name": f["host_name"]}),
                  hint=action_hint(f), handoffs=_handoffs(), mitigation=_mitigation(f["mitigation_id"]))


@router.post("/findings/{fid}/status")
def finding_status(fid: int, status: str = Form(...), back: str = Form("/findings")):
    if status not in ("open", "ignored"):
        raise HTTPException(400)
    f = db.q1("SELECT host_id FROM findings WHERE id=?", (fid,))
    if not f:
        raise HTTPException(404)
    check_host(f["host_id"])
    db.x("UPDATE findings SET status=? WHERE id=?", (status, fid))
    return RedirectResponse(back, 303)


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


@router.get("/settings/sources")
def sources_view(request: Request):
    sources.sync_config_sources()
    return render(request, "sources.html", tab="sources", builtin=_builtin_sources(), extra=[sources.public(s) for s in sources.all_sources()],
                  types=sources.TYPES, default_urls=sources.DEFAULT_URLS, msg=request.query_params.get("msg"),
                  err=request.query_params.get("err"))


@router.post("/settings/sources")
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


@router.post("/settings/sources/{name}/refresh")
def refresh_source(name: str):
    if not sources.get(name):
        raise HTTPException(404)
    _bg_run(sources.refresh(name))
    return RedirectResponse("/settings/sources?" + urlencode({"msg": f"Refreshing {name}. Reload in a moment."}), 303)


@router.post("/settings/sources/{name}/toggle")
def toggle_source(name: str):
    db.x("UPDATE feed_sources SET enabled=1-enabled WHERE name=? AND origin='ui'", (name,))
    return RedirectResponse("/settings/sources", 303)


@router.post("/settings/sources/{name}/delete")
def delete_source(name: str):
    s = sources.get(name)
    if s and s["origin"] == "ui":
        sources.remove(name)
    return RedirectResponse("/settings/sources", 303)


@router.post("/scan")
async def scan_all_now(request: Request):
    """Scan all (no form fields), the ticked systems (host_id=..., repeated) or a pattern (hosts=web*,group:db)."""
    form = await request.form()
    ids = [int(i) for i in form.getlist("host_id") if str(i).isdigit()]
    pats = str(form.get("hosts") or "")
    if form.get("selected") and not ids:
        return RedirectResponse(str(form.get("back") or "/systems"), 303)
    sel = scanner.select_hosts(pats, ids)
    _bg_run(scanner.scan_all(host_ids=sel))
    back = str(form.get("back") or "/systems")
    return RedirectResponse(back if back.startswith("/") else "/systems", 303)


@router.post("/systems/{host_id}/scan")
async def scan_one(host_id: int):
    check_host(host_id)
    async def run():
        await scanner.refresh_kev()
        await scanner.scan_host(host_id)
        scanner.start_nvd_enrichment([host_id])
    _bg_run(run())
    return RedirectResponse(f"/systems/{host_id}", 303)


@router.post("/systems")
def add_system(name: str = Form(...), address: str = Form(""), port: int = Form(22), ssh_user: str = Form(""),
               groups: str = Form(""), connection: str = Form("ssh")):
    db.x("""INSERT INTO hosts(name,address,port,ssh_user,groups,connection,source) VALUES (?,?,?,?,?,?, 'manual')
            ON CONFLICT(name) DO UPDATE SET address=excluded.address, port=excluded.port, ssh_user=excluded.ssh_user,
            groups=excluded.groups, connection=excluded.connection""",
         (name, address or name, port, ssh_user or None, groups.replace(" ", ""), connection))
    return RedirectResponse("/systems", 303)


@router.post("/systems/{host_id}/delete")
def delete_system(host_id: int):
    check_host(host_id)
    db.x("DELETE FROM hosts WHERE id=?", (host_id,))
    return RedirectResponse("/systems", 303)


@router.post("/systems/{host_id}/toggle")
def toggle_system(host_id: int):
    check_host(host_id)
    db.x("UPDATE hosts SET enabled = 1 - enabled WHERE id=?", (host_id,))
    return RedirectResponse("/systems", 303)


@router.get("/settings/inventory")
def inventory_settings(request: Request):
    from diysca.scanning import providers
    counts = {r["source"]: r["n"] for r in db.q("SELECT source, COUNT(*) n FROM hosts GROUP BY source")}
    rows = [{"label": p, "type": "Ansible inventory", "where": p, "count": counts.get(p, 0), "group": "",
             "status": scanner.inventory_status.get(p, {})} for p in settings.inventories]
    for cfg in settings.inventory_providers or []:
        if not isinstance(cfg, dict):
            continue
        src = providers.source(cfg)
        where = cfg.get("url") or cfg.get("auth_url") or cfg.get("uri") or ",".join(providers.split(cfg.get("uris") or cfg.get("regions") or ""))
        rows.append({"label": src, "type": str(cfg.get("type")) + ("" if cfg.get("enabled", True) else " (disabled)"),
                     "where": where, "count": counts.get(src, 0), "group": providers.label(cfg),
                     "status": scanner.inventory_status.get(src, {})})
    return render(request, "settings_inventory.html", tab="inventory", rows=rows, msg=request.query_params.get("msg"))


@router.post("/settings/inventory/import")
async def inventory_settings_import():
    import asyncio
    n = await asyncio.to_thread(scanner.import_inventories)
    return RedirectResponse("/settings/inventory?" + urlencode({"msg": f"Imported {n} systems."}), 303)


@router.post("/inventory/import")
def inventory_import(path: str = Form("")):
    paths = [path] if path else None
    n = scanner.import_inventories(paths)
    if path and path not in settings.inventories:
        settings.inventories.append(path)
    db.event("inventory", f"manual import: {n} hosts")
    return RedirectResponse("/systems", 303)


@router.get("/systems/{host_id}/sbom.json")
def sbom(host_id: int):
    check_host(host_id)
    h = db.q1("SELECT name FROM hosts WHERE id=?", (host_id,))
    if not h:
        raise HTTPException(404)
    return Response(sbom_json(host_id), media_type="application/vnd.cyclonedx+json",
                    headers={"Content-Disposition": f'attachment; filename="{h["name"]}.cdx.json"'})


@router.get("/api/hosts", tags=["inventory"], summary="List systems")
def api_hosts(request: Request):
    """Systems (hosts and containers) with open-finding counts.

    Query parameters: `host` (name or address, `*` wildcards), `group`, `os`, `kind` (`host` / `container`)."""
    sql, p = hosts_query(dict(request.query_params))
    return rows(db.q(sql, p))


@router.get("/api/packages", tags=["inventory"], summary="List installed packages")
def api_packages(request: Request):
    """Installed packages across systems.

    Query parameters: `name`, `version`, `host`, `group`, `os`, `eco` (`os`, `lang` or an ecosystem such as
    `PyPI`), `vulnerable=1`, `upgradable=1` (the repos offer a newer version)."""
    sql, p = package_query(dict(request.query_params))
    return rows(db.q(sql, p))


@router.get("/api/findings", tags=["findings"], summary="List findings")
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


@router.get("/api/findings/{fid}", tags=["findings"], summary="Get one finding")
def api_finding(fid: int):
    """One finding with its system, the advisories that report it and the mitigation it is approved in."""
    f = db.q1("""SELECT f.*, h.name host_name FROM findings f JOIN hosts h ON h.id=f.host_id WHERE f.id=?""", (fid,))
    if not f:
        raise HTTPException(404)
    check_host(f["host_id"])
    out = dict(f)
    out["mitigation"] = _mitigation(f["mitigation_id"])
    return out


@router.get("/api/sources", tags=["sources"], summary="List vulnerability sources")
def api_sources():
    """Extra vulnerability sources with their state. Header values are masked."""
    return [sources.public(s) for s in sources.all_sources()]


@router.get("/api/hosts/{host_id}/sbom", tags=["inventory"], summary="CycloneDX SBOM of a system")
def api_sbom(host_id: int):
    """CycloneDX 1.5 JSON with OS packages, language packages, container images, repos and OS facts."""
    check_host(host_id)
    try:
        return JSONResponse(build_sbom(host_id))
    except KeyError:
        raise HTTPException(404)


@router.post("/api/scan", tags=["scans"], summary="Scan all, one or selected systems")
async def api_scan(host: str | None = None, hosts: str | None = None, id: list[int] = Query(default=[]),
                   wait: bool = True):
    """Scans now.

    * nothing: every enabled system
    * `host=web1`: that one system (returns its result object)
    * `hosts=web*,group:prod,!test-*`: systems matching the patterns (same syntax as alert subscriptions)
    * `id=3&id=7`: those systems by id (also disabled ones)

    `hosts` and `id` combine. With `wait=false` the scan runs in the background and the answer lists the
    systems it started. Only systems in your scope are scanned."""
    if host:
        h = db.q1("SELECT id FROM hosts WHERE name=?", (host,))
        if not h or not scope.allows(h["id"]):
            raise HTTPException(404)
        res = await scanner.scan_host(h["id"])
        scanner.start_nvd_enrichment([h["id"]])
        return res
    sel = scanner.select_hosts(hosts, id)
    if (hosts or id) and not sel:
        raise HTTPException(404, "no system matches")
    if not wait:
        _bg_run(scanner.scan_all(host_ids=sel))
        names = [r["name"] for r in db.q(f"SELECT name FROM hosts WHERE id IN ({','.join('?' * len(sel))})", sel)] if sel else []
        return JSONResponse({"started": names}, 202)
    return await scanner.scan_all(host_ids=sel)
