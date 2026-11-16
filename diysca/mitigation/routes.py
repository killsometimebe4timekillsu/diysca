"""Mitigation module: patch playbooks, repo managers, reprovisioning, approvals, hand-off, patched CVEs."""
from __future__ import annotations

import asyncio
from urllib.parse import urlencode

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import RedirectResponse, Response

from diysca.core import db, scope
from diysca.core.config import settings
from diysca.mitigation import mitigate, patch, patched, patchlog, repomgr
from diysca.scanning import scanner
from diysca.scanning.feeds import SEVERITY_ORDER
from diysca.ui import (
    check_host,
    download_name,
    _bg_run,
    _ids_from_filter,
    _masked,
    actor,
    all_groups,
    render,
    require,
    rows,
)

router = APIRouter()


@router.get("/patched")
def patched_view(request: Request):
    args = dict(request.query_params)
    data = patched.query(args)
    return render(request, "patched.html", args=args, groups=all_groups(), severities=SEVERITY_ORDER[2:],
                  ranges=patched.RANGES, **data)


@router.get("/settings/repos")
def settings_repos(request: Request):
    import yaml
    mgrs = [{"name": m["name"], "type": m.get("type"), "url": m.get("url"), "match": m.get("match"),
             "yaml": yaml.safe_dump(_masked(m), sort_keys=False)} for m in repomgr.managers()]
    return render(request, "settings_repos.html", tab="repos", mgrs=mgrs)


@router.get("/systems/{host_id}/reprovision.yml")
def reprovision_host(request: Request, host_id: int, mode: str = "fixed", target: str = ""):
    from diysca.mitigation import reprovision
    check_host(host_id)
    h = db.q1("SELECT name FROM hosts WHERE id=?", (host_id,))
    if not h:
        raise HTTPException(404)
    try:
        text, summary = reprovision.for_host(host_id, "exact" if mode == "exact" else "fixed", target.strip() or None)
    except ValueError as e:
        raise HTTPException(400, str(e))
    db.patch_run("reprovision", f"rebuild playbook for {h['name']} ({mode}): {summary.get('packages', 0)} packages",
                 actor=actor(request), status="generated", hosts=h["name"])
    return Response(text, media_type="application/x-yaml",
                    headers={"Content-Disposition": f'attachment; filename="reprovision-{download_name(h["name"])}.yml"'})


@router.post("/reprovision")
async def reprovision_upload(request: Request, file: UploadFile = File(...), mode: str = Form("fixed"),
                             target: str = Form("")):
    import json as _json

    from diysca.mitigation import reprovision
    try:
        sbom_doc = _json.loads((await file.read()).decode("utf-8", "replace"))
        text, summary = reprovision.build(sbom_doc, "exact" if mode == "exact" else "fixed", target.strip() or None)
    except ValueError as e:
        ctx = _patching_ctx()
        ctx["reprovision_error"] = f"{file.filename}: {e}"
        return render(request, "patching.html", **ctx)
    return Response(text, media_type="application/x-yaml",
                    headers={"Content-Disposition": f'attachment; filename="reprovision-{download_name(summary["system"])}.yml"'})


def _patching_ctx() -> dict:
    hosts = db.q("""SELECT h.id, h.name, h.os_pretty, h.kind,
                      SUM(CASE WHEN f.fix_in_repo=1 AND f.ecosystem='' THEN 1 ELSE 0 END) AS fixable,
                      SUM(CASE WHEN f.fix_in_repo=0 AND f.fixed_version IS NOT NULL AND f.ecosystem='' THEN 1 ELSE 0 END) AS repo_behind,
                      SUM(CASE WHEN f.ecosystem!='' THEN 1 ELSE 0 END) AS lang
                    FROM hosts h JOIN findings f ON f.host_id=h.id AND f.status='open'
                    WHERE 1=1""" + scope.clause("h.id") + """
                    GROUP BY h.id, h.name, h.os_pretty, h.kind ORDER BY fixable DESC, h.name""")
    mgrs = []
    for m in repomgr.managers():
        pend = repomgr.pending_for(m)
        mgrs.append({"name": m["name"], "type": m.get("type"), "url": m.get("url"), "match": m.get("match"),
                     "stages": m.get("promote_to") or [], "pending": pend[:50], "pending_count": len(pend)})
    return {"hosts": hosts, "mgrs": mgrs, "result": None}


@router.get("/patching")
def patching(request: Request):
    return render(request, "patching.html", **_patching_ctx())


@router.post("/patch/playbook")
async def patch_playbook(request: Request):
    form = await request.form()
    ids = [int(i) for i in form.getlist("ids") if str(i).isdigit()]
    if not ids and form.get("filter") is not None:
        ids = _ids_from_filter(str(form.get("filter")))
    if form.get("host_id"):
        check_host(int(form.get("host_id")))
        ids = [r["id"] for r in db.q("SELECT id FROM findings WHERE host_id=? AND status='open'",
                                     (int(form.get("host_id")),))]
    text, summary = patch.build_playbook(ids)
    msg = f"playbook generated: {summary['hosts']} hosts, {summary['packages']} packages, {summary['manual']} manual items"
    db.event("patch", msg)
    if summary["hosts"]:
        patchlog.record_playbook(ids, summary, actor(request))
    return Response(text, media_type="application/x-yaml",
                    headers={"Content-Disposition": 'attachment; filename="diysca-patch.yml"'})


@router.post("/repos/{name}/run")
async def repo_run(request: Request, name: str):
    form = await request.form()
    dry = form.get("dry_run", "1") == "1"
    stages = form.getlist("stages") if form.get("stages_given") else None
    try:
        res = await repomgr.run(name, dry_run=dry, stages=stages, actor=actor(request))
    except KeyError:
        raise HTTPException(404)
    if not dry and res.ok and form.get("rescan"):
        names = sorted({p["host_name"] for p in repomgr.pending_for(repomgr.get_manager(name))})
        ids = [r["id"] for r in db.q(f"SELECT id FROM hosts WHERE name IN ({','.join('?' * len(names))})", names)] \
            if names else []
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


@router.get("/mitigations")
def mitigations_view(request: Request, status: str = "open"):
    return render(request, "mitigations.html", rows=mitigate.list_(status), status=status,
                  statuses=("open",) + mitigate.STATUSES + ("all",), handoffs=mitigate.handoffs())


@router.post("/mitigations")
async def mitigation_create(request: Request):
    form = await request.form()
    try:
        m = await asyncio.to_thread(mitigate.approve, _form_ids(form), actor(request), str(form.get("note") or ""),
                                    str(form.get("handoff") or "") or None, bool(form.get("rescan", "1") == "1"),
                                    str(form.get("filter") or "") or None)
    except mitigate.MitigationError as e:
        return RedirectResponse(f"/mitigations?{urlencode({'error': str(e)})}", 303)
    return RedirectResponse(f"/mitigations/{m['id']}", 303)


@router.get("/mitigations/{mid}")
def mitigation_view(request: Request, mid: int):
    m = mitigate.get(mid)
    if not m:
        raise HTTPException(404)
    return render(request, "mitigation.html", mi=m, handoffs=mitigate.handoffs(), msg=request.query_params.get("msg"))


@router.get("/mitigations/{mid}/playbook.yml", include_in_schema=False)
def mitigation_playbook_ui(mid: int):
    return api_mitigation_playbook(mid)


@router.post("/mitigations/{mid}/cancel")
def mitigation_cancel_ui(request: Request, mid: int, reason: str = Form("")):
    try:
        mitigate.cancel(mid, actor(request), reason)
    except mitigate.MitigationError as e:
        return RedirectResponse(f"/mitigations/{mid}?{urlencode({'msg': str(e)})}", 303)
    return RedirectResponse(f"/mitigations/{mid}", 303)


@router.post("/mitigations/{mid}/report")
async def mitigation_report_ui(request: Request, mid: int, status: str = Form(...), log: str = Form("")):
    try:
        _, rescan = await asyncio.to_thread(mitigate.report, mid, status, actor(request), log)
    except mitigate.MitigationError as e:
        return RedirectResponse(f"/mitigations/{mid}?{urlencode({'msg': str(e)})}", 303)
    if rescan:
        _bg_run(scanner.scan_all(host_ids=rescan))
    return RedirectResponse(f"/mitigations/{mid}", 303)


@router.post("/mitigations/{mid}/handoff")
async def mitigation_handoff_ui(mid: int, target: str = Form(...)):
    if not mitigate._in_scope(mid):
        raise HTTPException(404)
    ok, res = await asyncio.to_thread(mitigate.deliver, mid, target)
    return RedirectResponse(f"/mitigations/{mid}?{urlencode({'msg': ('Sent: ' if ok else 'Failed: ') + res})}", 303)


@router.get("/settings/handoff")
def handoff_view(request: Request):
    return render(request, "settings_handoff.html", tab="handoff", targets=mitigate.handoffs(), types=mitigate.HANDOFF_TYPES,
                  tokens=sorted(settings.api_tokens or {}), msg=request.query_params.get("msg"))


@router.post("/settings/handoff")
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


@router.post("/settings/handoff/{name}/delete")
def handoff_delete(name: str):
    mitigate.remove_handoff(name)
    return RedirectResponse("/settings/handoff", 303)


@router.get("/api/patched", tags=["patched"], summary="Patched findings in a time range")
def api_patched(request: Request):
    """Findings that went away in a time range, with how (`upgraded`, `removed`, `not-affected`).

    Query parameters: `range` (`last` = each system's latest patching, `24h`, `7d`, `30d`, `90d`, `1y`, `custom`),
    `from` / `to` (dates, with `range=custom`), `host`, `group`, `severity`, `eco`, `how`."""
    d = patched.query(dict(request.query_params))
    return {"range": d["range"], "start": d["start"], "end": d["end"], "stats": d["stats"], "findings": rows(d["rows"])}


@router.get("/api/mitigations", tags=["mitigations"], summary="List mitigations")
def api_mitigations(status: str = "open"):
    """`status`: `open` (approved, claimed or running; default), `approved` (waiting for someone to claim it),
    `claimed`, `running`, `done`, `failed`, `cancelled` or `all`. The playbook is left out; fetch it per mitigation."""
    return mitigate.list_(status)


@router.post("/api/mitigations", tags=["mitigations"], summary="Approve findings for mitigation", status_code=201)
async def api_mitigation_create(request: Request):
    """Body (JSON): `finding_ids` (list) or `filter` (a findings query string, e.g. `host=web1&fix=repo`),
    optional `note`, `handoff` (target name; without it, targets marked *auto* are used) and `rescan` (default
    true). Only open findings are taken. Token holders may approve when `agents_can_approve` is set, or when their token has `role: approver` or higher."""
    require(request, "approver")
    try:
        body = await request.json()
    except ValueError:
        raise HTTPException(422, "the body must be JSON")
    if not isinstance(body, dict):
        raise HTTPException(422, "the body must be a JSON object with finding_ids or filter")
    raw = body.get("finding_ids") or []
    if not isinstance(raw, list) or not all(isinstance(i, int) or (isinstance(i, str) and i.isdigit()) for i in raw):
        raise HTTPException(422, "finding_ids must be a list of finding ids (numbers)")
    ids = [int(i) for i in raw]
    if not ids and body.get("filter") is not None:
        ids = _ids_from_filter(str(body["filter"]))
    try:
        return await asyncio.to_thread(mitigate.approve, ids, actor(request), str(body.get("note") or ""),
                                       body.get("handoff") or None, bool(body.get("rescan", True)),
                                       str(body.get("filter") or "") or None)
    except mitigate.MitigationError as e:
        raise HTTPException(422, str(e))


@router.get("/api/mitigations/{mid}", tags=["mitigations"], summary="Get a mitigation")
def api_mitigation(mid: int):
    """The mitigation with its findings, the playbook (YAML text), log and links."""
    m = mitigate.get(mid)
    if not m:
        raise HTTPException(404)
    return m


@router.get("/api/mitigations/{mid}/playbook.yml", tags=["mitigations"], summary="Playbook of a mitigation")
def api_mitigation_playbook(mid: int):
    """The Ansible playbook created at approval time, pinned to the versions your repos offered then.
    Items a playbook can't fix (language packages, images, fixes not yet in your repos) are comments at the top."""
    m = mitigate.get(mid)
    if not m:
        raise HTTPException(404)
    return Response(m["playbook"] or "", media_type="application/x-yaml",
                    headers={"Content-Disposition": f'attachment; filename="diysca-mitigation-{mid}.yml"'})


@router.post("/api/mitigations/{mid}/claim", tags=["mitigations"], summary="Claim a mitigation")
def api_mitigation_claim(request: Request, mid: int):
    """Marks an `approved` mitigation as yours, so no other agent runs it. 409 if it isn't `approved` any more."""
    try:
        return mitigate.claim(mid, actor(request))
    except KeyError:
        raise HTTPException(404)
    except mitigate.MitigationError as e:
        raise HTTPException(409, str(e))


@router.post("/api/mitigations/{mid}/report", tags=["mitigations"], summary="Report progress")
async def api_mitigation_report(request: Request, mid: int):
    """Body (JSON): `status` (`running`, `done` or `failed`) and optional `log` (text, e.g. the ansible output).
    On `done` the affected systems are rescanned in the background (unless the mitigation was created with
    `rescan: false`), and the channels that alerted about the findings are told."""
    try:
        body = await request.json()
    except ValueError:
        body = None
    if not isinstance(body, dict):
        raise HTTPException(422, 'the body must be a JSON object like {"status": "done", "log": "..."}')
    try:
        m, rescan = await asyncio.to_thread(mitigate.report, mid, str(body.get("status") or ""), actor(request),
                                            str(body.get("log") or ""))
    except KeyError:
        raise HTTPException(404)
    except mitigate.MitigationError as e:
        raise HTTPException(409, str(e))
    if rescan:
        _bg_run(scanner.scan_all(host_ids=rescan))
    return {**m, "rescan_hosts": mitigate.host_names(rescan)}


@router.post("/api/mitigations/{mid}/cancel", tags=["mitigations"], summary="Cancel a mitigation")
async def api_mitigation_cancel(request: Request, mid: int):
    """Optional body (JSON): `reason`. The findings can be approved again afterwards."""
    require(request, "approver")
    try:
        body = await request.json()
    except ValueError:
        body = {}
    if not isinstance(body, dict):
        body = {}
    try:
        return mitigate.cancel(mid, actor(request), str(body.get("reason") or ""))
    except KeyError:
        raise HTTPException(404)
    except mitigate.MitigationError as e:
        raise HTTPException(409, str(e))


# ------------------------------------------------------------------ patch log
def _log_args(request: Request) -> dict:
    return {k: v for k, v in request.query_params.items() if v}


@router.get("/patchlog")
def patchlog_view(request: Request):
    args = _log_args(request)
    d = patchlog.query(args)
    return render(request, "patchlog.html", args=args, kinds=patchlog.KINDS, **d)


@router.get("/patchlog.csv", include_in_schema=False)
def patchlog_csv(request: Request):
    d = patchlog.query(_log_args(request))
    return Response(patchlog.to_csv(d["rows"]), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="diysca-patchlog-{d["start"][:10]}-{d["end"][:10]}.csv"'})


@router.get("/api/patchlog", tags=["patch log"], summary="Patch log")
def api_patchlog(request: Request, format: str = "json"):
    """One entry per patching: playbooks generated, repo updates, reprovision playbooks and finished
    mitigations, with who approved (and when), who ran it, when it started and finished, the result, the
    systems, CVEs and whether the rescan confirmed the fix (`verified`: resolved/total findings).

    Query parameters: `range` (`24h`, `7d`, `30d` default, `90d`, `1y`, `custom` with `from` / `to`), `kind`
    (`playbook`, `repo`, `mitigation`, `reprovision`), `status`, `host`, `cve`, `approver`, `executor`, `actor`,
    `format` (`json` default or `csv`)."""
    args = _log_args(request)
    args.pop("format", None)
    d = patchlog.query(args)
    if format == "csv":
        return Response(patchlog.to_csv(d["rows"]), media_type="text/csv",
                        headers={"Content-Disposition": 'attachment; filename="diysca-patchlog.csv"'})
    return {"range": d["range"], "start": d["start"], "end": d["end"], "entries": d["rows"]}


@router.get("/mitigations/{mid}/log.json", include_in_schema=False)
def mitigation_export(mid: int):
    m = mitigate.get(mid)
    if not m:
        raise HTTPException(404)
    entries = [r for r in patchlog.query({"range": "custom", "from": "2000-01-01", "kind": "mitigation"})["rows"]
               if r["mitigation_id"] == mid]
    return Response(patchlog.to_json(entries, {"mitigation": m}), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="diysca-mitigation-{mid}.json"'})
