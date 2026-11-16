"""The patch log: one entry per patching, exportable.

Every way diysca patches leaves an entry:

    playbook      a patch playbook was generated (UI, API, CLI): who, which systems, CVEs
    repo          a self-hosted repo was synced / published / promoted (aptly, Pulp, Foreman): who, result
    mitigation    an approved mitigation finished (done, failed or cancelled): who approved it and when,
                  who ran it, when it started and ended, the result and the last lines of its log
    reprovision   a rebuild playbook was generated from an SBOM

For mitigations the log also shows whether the rescan confirmed the fix ("verified": findings of the
mitigation that are resolved now, out of all of them).

Export: CSV (spreadsheets, auditors) or JSON, over a time range and filters. Same columns everywhere.
"""
from __future__ import annotations

import csv
import io
import json

from diysca.core import db, scope
from diysca.mitigation.patched import RANGES, window
from diysca.ui import LIKE, name_like

KINDS = ("playbook", "repo", "mitigation", "reprovision")
COLUMNS = ("id", "at", "kind", "status", "summary", "hosts", "findings", "cves", "approver", "approved_at",
           "executor", "started_at", "finished_at", "verified", "mitigation_id", "actor", "detail")


def hosts_and_cves(finding_ids: list[int]) -> tuple[list[str], list[str]]:
    if not finding_ids:
        return [], []
    marks = ",".join("?" * len(finding_ids))
    rows = db.q(f"""SELECT DISTINCT h.name, f.vuln_id FROM findings f JOIN hosts h ON h.id=f.host_id
                    WHERE f.id IN ({marks})""", list(finding_ids))
    return sorted({r["name"] for r in rows}), sorted({r["vuln_id"] for r in rows})


def record_playbook(finding_ids: list[int], summary: dict, actor: str, kind: str = "playbook", text: str = ""):
    hosts, cves = hosts_and_cves(finding_ids)
    msg = text or (f"playbook generated: {summary.get('hosts', 0)} hosts, {summary.get('packages', 0)} packages, "
                   f"{summary.get('manual', 0)} manual items")
    return db.patch_run(kind, msg, actor=actor, status="generated", hosts=",".join(hosts),
                        findings=len(finding_ids), cves=",".join(cves[:500]))


def record_mitigation(mid: int, status: str, actor: str):
    m = db.q1("SELECT * FROM mitigations WHERE id=?", (mid,))
    if not m:
        return None
    ids = [r["finding_id"] for r in db.q("SELECT finding_id FROM mitigation_findings WHERE mitigation_id=?", (mid,))]
    hosts, cves = hosts_and_cves(ids)
    tail = "\n".join((m["log"] or "").splitlines()[-15:])
    try:
        sm = json.loads(m["summary"] or "{}")
    except ValueError:
        sm = {}
    # say what the run could do at all: a mitigation with manual items only is "done" without a package patched
    what = f" ({sm.get('playbook_packages', 0)} packages, {sm.get('manual_items', 0)} manual items)" if sm else ""
    # a cancelled mitigation that nobody claimed was not run by anyone: the canceller is the actor only
    executor = m["claimed_by"] or ("" if status == "cancelled" else actor)
    return db.patch_run("mitigation", f"mitigation #{mid} {status}{what}" + (f": {m['note']}" if m["note"] else ""),
                        actor=actor, approver=m["approved_by"], approved_at=m["created_at"],
                        executor=executor, status=status, hosts=",".join(hosts), findings=len(ids),
                        cves=",".join(cves[:500]), mitigation_id=mid, started_at=m["claimed_at"], detail=tail[-4000:])


def _verified(mid) -> str:
    if not mid:
        return ""
    r = db.q1("""SELECT COUNT(*) n, SUM(CASE WHEN f.status='resolved' THEN 1 ELSE 0 END) done
                 FROM mitigation_findings mf JOIN findings f ON f.id=mf.finding_id WHERE mf.mitigation_id=?""", (mid,))
    return f"{r['done'] or 0}/{r['n']}" if r and r["n"] else ""


def query(args: dict) -> dict:
    rng, start, end, label = window(args.get("range") or "30d", args.get("from", ""), args.get("to", ""))
    if rng == "last":  # "since last patching" makes no sense for a log; show 30 days
        rng, start, end, label = window("30d")
    where, p = ["at >= ?", "at <= ?"], [start, end]
    if args.get("kind") in KINDS:
        where.append("kind=?")
        p.append(args["kind"])
    if args.get("status"):
        where.append("status=?")
        p.append(args["status"])
    if args.get("host"):
        where.append(f"(',' || hosts || ',') {LIKE}")
        p.append(f"%,{name_like(args['host'])},%")
    for col in ("approver", "executor", "actor"):
        if args.get(col):
            where.append(f"{col} LIKE ?")
            p.append(f"%{args[col]}%")
    if args.get("cve"):
        where.append("cves LIKE ?")
        p.append(f"%{args['cve']}%")
    rows = []
    allowed = scope.current()
    names = None
    if allowed is not None:
        names = {r["name"] for r in db.q(f"SELECT name FROM hosts WHERE 1=1{scope.clause('id')}")}
    for r in db.q(f"SELECT * FROM patch_runs WHERE {' AND '.join(where)} ORDER BY at DESC, id DESC LIMIT 5000", p):
        d = {c: r[c] if c in r.keys() else None for c in COLUMNS if c not in ("finished_at", "verified")}
        hosts = [h for h in (r["hosts"] or "").split(",") if h]
        if names is not None and not (set(hosts) & names):
            continue  # entries without a system in the user's scope are hidden
        d["finished_at"] = r["at"] if r["kind"] == "mitigation" else None
        d["verified"] = _verified(r["mitigation_id"])
        d["hosts"] = hosts
        d["cves"] = [c for c in (r["cves"] or "").split(",") if c]
        d["status"] = r["status"] or ("ok" if r["kind"] == "repo" else "generated")
        rows.append(d)
    return {"range": rng, "start": start, "end": end, "label": label, "rows": rows, "ranges": RANGES}


def to_csv(rows: list[dict]) -> str:
    from diysca.ui import csv_cell
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(COLUMNS)
    for r in rows:
        w.writerow([csv_cell(" ".join(r[c]) if isinstance(r[c], list) else r[c]) for c in COLUMNS])
    return buf.getvalue()


def to_json(rows: list[dict], meta: dict) -> str:
    return json.dumps({**meta, "entries": rows}, indent=1, default=str)
