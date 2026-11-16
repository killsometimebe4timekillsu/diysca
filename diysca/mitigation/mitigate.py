"""Approve findings for mitigation and hand them off.

diysca often can't reach the systems it reports on (another network, an
air gap, a team that owns the deploy pipeline). So instead of patching
itself, a person approves findings, and diysca turns the approval into a
*mitigation*: a work item with the findings, a ready-to-run Ansible
playbook and links to report back. Whoever can reach the systems picks it
up:

* pull: an agent, a cron job or an MCP client lists approved mitigations
  via the API (`GET /api/mitigations?status=approved`), claims one, runs it
  and reports the result.
* push: diysca sends the mitigation to a hand-off target as soon as it's
  approved: a generic webhook (full JSON incl. playbook), a GitHub
  repository_dispatch (starts a GitHub Actions workflow) or a GitLab
  pipeline trigger.

Lifecycle: approved -> claimed -> running -> done | failed, or cancelled.
On done, the affected systems are rescanned, so fixed findings move to
Patched CVEs. Status changes are sent to the channels that alerted about
the findings.
"""
from __future__ import annotations

import json
import re
import threading

import httpx

from diysca import __version__
from diysca.core import db, events, scope
from diysca.core.config import settings
from diysca.mitigation import patch, patchlog
from diysca.scanning.feeds import sev_rank

STATUSES = ("approved", "claimed", "running", "done", "failed", "cancelled")
OPEN_STATUSES = ("approved", "claimed", "running")
REPORTABLE = ("running", "done", "failed")
HANDOFF_TYPES = {
    "webhook": "POST the whole mitigation as JSON (findings, playbook, links) to any URL",
    "github": "GitHub repository_dispatch: starts a GitHub Actions workflow with the mitigation id and links",
    "gitlab": "GitLab pipeline trigger: starts a pipeline with DIYSCA_* variables",
}


class MitigationError(ValueError):
    pass


def _base() -> str:
    return settings.base_url.rstrip("/")


def links(mid: int) -> dict:
    b = _base()
    return {"ui": f"{b}/mitigations/{mid}", "self": f"{b}/api/mitigations/{mid}",
            "playbook": f"{b}/api/mitigations/{mid}/playbook.yml", "claim": f"{b}/api/mitigations/{mid}/claim",
            "report": f"{b}/api/mitigations/{mid}/report"}


# ------------------------------------------------------------------ queries
def _findings(mid: int) -> list[dict]:
    return [dict(r) for r in db.q(
        """SELECT f.id, h.name host, f.host_id, f.package, f.version, f.ecosystem, f.location, f.vuln_id, f.severity,
                  f.cvss_score, f.kev, f.epss, f.fixed_version, f.repo_version, f.fix_in_repo, f.status
           FROM mitigation_findings mf JOIN findings f ON f.id=mf.finding_id JOIN hosts h ON h.id=f.host_id
           WHERE mf.mitigation_id=? ORDER BY h.name, f.package""", (mid,))]


def get(mid: int, with_playbook: bool = True) -> dict | None:
    m = db.q1("SELECT * FROM mitigations WHERE id=?", (mid,))
    if not m or not _in_scope(mid):
        return None
    out = dict(m)
    out["summary"] = json.loads(m["summary"] or "{}")
    out["findings"] = _findings(mid)
    if not _all_in_scope(mid):
        # A user limited to some systems sees their part only: not the other systems' findings, and not the
        # playbook, which names every system and package in the mitigation.
        total = len(out["findings"])
        out["findings"] = [f for f in out["findings"] if scope.allows(f["host_id"])]
        out["partial"] = f"{len(out['findings'])} of {total} findings are on systems you may see"
        out["playbook"] = "# This mitigation also covers systems outside your scope, so its playbook is not shown.\n"
        mine = {f["host"] for f in out["findings"]}
        out["summary"] = {**out["summary"], "hosts": [h for h in out["summary"].get("hosts", []) if h in mine],
                          "cves": sorted({f["vuln_id"] for f in out["findings"]})[:50],
                          "cves_total": len({f["vuln_id"] for f in out["findings"]}), "findings": len(out["findings"])}
    out["hosts"] = sorted({f["host"] for f in out["findings"]})
    out["open_findings"] = sum(1 for f in out["findings"] if f["status"] == "open")
    # Same fields as the patch log: when it ended, and how many findings the rescan confirmed fixed.
    out["finished_at"] = m["updated_at"] if m["status"] in ("done", "failed", "cancelled") else None
    n = len(out["findings"])
    out["verified"] = f"{sum(1 for f in out['findings'] if f['status'] == 'resolved')}/{n}" if n else ""
    out["links"] = links(mid)
    if not with_playbook:
        out.pop("playbook", None)
    return out


def list_(status: str | None = None, limit: int = 200) -> list[dict]:
    where, p = "", []
    if status == "open":
        where = f"WHERE m.status IN ({','.join('?' * len(OPEN_STATUSES))})"
        p = list(OPEN_STATUSES)
    elif status and status != "all":
        where, p = "WHERE m.status=?", [status]
    rows = db.q(f"""SELECT m.id, m.created_at, m.approved_by, m.note, m.status, m.handoff, m.handoff_result,
                           m.claimed_by, m.claimed_at, m.updated_at, m.summary,
                           (SELECT COUNT(*) FROM mitigation_findings mf WHERE mf.mitigation_id=m.id) findings,
                           (SELECT COUNT(*) FROM mitigation_findings mf JOIN findings f ON f.id=mf.finding_id
                             WHERE mf.mitigation_id=m.id AND f.status='open') still_open
                    FROM mitigations m {where} ORDER BY m.id DESC LIMIT {int(limit)}""", p)
    rows = [r for r in rows if _in_scope(r["id"])]
    out = []
    for r in rows:
        d = dict(r)
        d["summary"] = json.loads(r["summary"] or "{}")
        d["links"] = links(r["id"])
        out.append(d)
    return out


def _in_scope(mid: int) -> bool:
    """A mitigation is visible when at least one of its systems is in the user's scope."""
    if scope.current() is None:
        return True
    return bool(db.q1(f"""SELECT 1 x FROM mitigation_findings mf JOIN findings f ON f.id=mf.finding_id
                          WHERE mf.mitigation_id=?{scope.clause("f.host_id")} LIMIT 1""", (mid,)))


def _all_in_scope(mid: int) -> bool:
    """Acting on a mitigation (claim, report, cancel) touches every system in it: all of them must be in scope."""
    if scope.current() is None:
        return True
    return all(scope.allows(r["host_id"]) for r in db.q(
        """SELECT DISTINCT f.host_id FROM mitigation_findings mf JOIN findings f ON f.id=mf.finding_id
           WHERE mf.mitigation_id=?""", (mid,)))


def _need_all(mid: int, what: str):
    if not _all_in_scope(mid):
        raise MitigationError(f"mitigation #{mid} also covers systems outside your scope, so you can't {what} it")


# ------------------------------------------------------------------ lifecycle
_approve_lock = threading.Lock()  # two approvals at once must not both take the same findings


def approve(finding_ids: list[int], approved_by: str, note: str = "", handoff: str | None = None,
            rescan: bool = True, filter: str | None = None) -> dict:
    """Create a mitigation for the open findings among `finding_ids` and hand it off. Findings that already are
    in an open mitigation are left out. `filter` is the findings filter the ids came from, for the error text."""
    with _approve_lock:
        return _approve(finding_ids, approved_by, note, handoff, rescan, filter)


def _approve(finding_ids, approved_by, note, handoff, rescan, filter) -> dict:
    ids = sorted({int(i) for i in finding_ids})
    if not ids:
        raise MitigationError(f"no open findings match the filter '{filter}'" if filter
                              else "select at least one finding")
    marks = ",".join("?" * len(ids))
    rows = db.q(f"""SELECT f.id, f.vuln_id, f.severity, f.kev, h.name host FROM findings f JOIN hosts h ON h.id=f.host_id
                    WHERE f.id IN ({marks}) AND f.status='open'{scope.clause("f.host_id")}""", ids)
    if not rows:
        raise MitigationError("none of the selected findings is open")
    busy = {r["finding_id"]: r["id"] for r in db.q(
        f"""SELECT mf.finding_id, m.id FROM mitigation_findings mf JOIN mitigations m ON m.id=mf.mitigation_id
            WHERE mf.finding_id IN ({marks}) AND m.status IN ({",".join("?" * len(OPEN_STATUSES))})""",
        ids + list(OPEN_STATUSES))}
    rows = [r for r in rows if r["id"] not in busy]
    if not rows:
        raise MitigationError("the selected findings are already in open mitigation " +
                              ", ".join(f"#{m}" for m in sorted(set(busy.values()))[:10]))
    if handoff and not db.q1("SELECT name FROM handoffs WHERE name=?", (handoff,)):
        raise MitigationError(f"unknown hand-off target '{handoff}'")
    ids = [r["id"] for r in rows]
    playbook, pb = patch.build_playbook(ids)
    worst = max((r["severity"] or "UNKNOWN" for r in rows), key=sev_rank)
    summary = {"findings": len(rows), "hosts": sorted({r["host"] for r in rows}), "worst_severity": worst,
               "kev": sum(1 for r in rows if r["kev"]), "cves": sorted({r["vuln_id"] for r in rows})[:50],
               "cves_total": len({r["vuln_id"] for r in rows}),  # `cves` holds the first 50 only
               "playbook_hosts": pb["hosts"], "playbook_packages": pb["packages"], "manual_items": pb["manual"]}
    ts = db.now()
    mid = db.x("""INSERT INTO mitigations(created_at, approved_by, note, status, handoff, updated_at, playbook, summary,
                                          log, rescan) VALUES (?,?,?,'approved',?,?,?,?,?,?)""",
               (ts, approved_by, note, handoff, ts, playbook, json.dumps(summary),
                f"{ts} approved by {approved_by}" + (f": {note}" if note else ""), int(rescan)))
    if mid is None:  # very old psycopg paths; fall back to the newest row
        mid = db.q1("SELECT MAX(id) id FROM mitigations")["id"]
    db.xmany("INSERT INTO mitigation_findings(mitigation_id, finding_id) VALUES (?,?)", [(mid, i) for i in ids])
    db.x(f"UPDATE findings SET mitigation_id=? WHERE id IN ({','.join('?' * len(ids))})", [mid] + ids)
    db.event("mitigation", f"#{mid} approved by {approved_by}: {len(ids)} findings on {len(summary['hosts'])} systems")
    targets = [handoff] if handoff else [h["name"] for h in db.q("SELECT name FROM handoffs WHERE enabled=1 AND auto=1")]
    for t in targets:
        deliver(mid, t)
    return get(mid)


def host_names(host_ids: list[int]) -> list[str]:
    """Names for the host ids `report` returns, for API answers (the API speaks in system names)."""
    if not host_ids:
        return []
    marks = ",".join("?" * len(host_ids))
    return sorted(r["name"] for r in db.q(f"SELECT name FROM hosts WHERE id IN ({marks})", list(host_ids)))


def _append_log(mid: int, line: str):
    m = db.q1("SELECT log FROM mitigations WHERE id=?", (mid,))
    log = ((m["log"] or "") + "\n" + f"{db.now()} {line}").strip()
    db.x("UPDATE mitigations SET log=?, updated_at=? WHERE id=?", (log[-60000:], db.now(), mid))


def claim(mid: int, by: str) -> dict:
    m = db.q1("SELECT status, claimed_by FROM mitigations WHERE id=?", (mid,))
    if not m or not _in_scope(mid):
        raise KeyError(mid)
    _need_all(mid, "claim")
    if m["status"] != "approved":
        raise MitigationError(f"mitigation #{mid} is {m['status']}" +
                              (f" (claimed by {m['claimed_by']})" if m["claimed_by"] else ""))
    db.x("UPDATE mitigations SET status='claimed', claimed_by=?, claimed_at=? WHERE id=? AND status='approved'",
         (by, db.now(), mid))
    if db.q1("SELECT claimed_by FROM mitigations WHERE id=?", (mid,))["claimed_by"] != by:
        raise MitigationError(f"mitigation #{mid} was claimed by someone else")
    _append_log(mid, f"claimed by {by}")
    _notify(mid, f"claimed by {by}")
    return get(mid, with_playbook=False)


def report(mid: int, status: str, by: str, log: str = "") -> tuple[dict, list[int]]:
    """Record progress. Returns (mitigation, host ids to rescan)."""
    if status not in REPORTABLE:
        raise MitigationError(f"status must be one of {', '.join(REPORTABLE)}")
    m = db.q1("SELECT status, rescan, claimed_by FROM mitigations WHERE id=?", (mid,))
    if not m or not _in_scope(mid):
        raise KeyError(mid)
    _need_all(mid, "report on")
    if m["status"] in ("done", "cancelled"):
        raise MitigationError(f"mitigation #{mid} is already {m['status']}")
    db.x("UPDATE mitigations SET status=?, claimed_by=COALESCE(claimed_by, ?), claimed_at=COALESCE(claimed_at, ?) WHERE id=?",
         (status, by, db.now(), mid))
    _append_log(mid, f"{status} ({by})" + (f":\n{log.strip()[:20000]}" if log and log.strip() else ""))
    db.event("mitigation", f"#{mid} {status} ({by})")
    rescan: list[int] = []
    if status == "done":
        if m["rescan"]:
            rescan = [r["host_id"] for r in db.q(
                """SELECT DISTINCT f.host_id FROM mitigation_findings mf JOIN findings f ON f.id=mf.finding_id
                   WHERE mf.mitigation_id=?""", (mid,))]
    if status in ("done", "failed"):
        patchlog.record_mitigation(mid, status, by)
        _notify(mid, status + (f": {log.strip().splitlines()[-1][:200]}" if log and log.strip() else ""))
    return get(mid, with_playbook=False), rescan


def cancel(mid: int, by: str, reason: str = "") -> dict:
    m = db.q1("SELECT status FROM mitigations WHERE id=?", (mid,))
    if not m or not _in_scope(mid):
        raise KeyError(mid)
    _need_all(mid, "cancel")
    if m["status"] in ("done", "cancelled"):
        raise MitigationError(f"mitigation #{mid} is already {m['status']}")
    db.x("UPDATE mitigations SET status='cancelled' WHERE id=?", (mid,))
    db.x("UPDATE findings SET mitigation_id=NULL WHERE mitigation_id=?", (mid,))
    _append_log(mid, f"cancelled by {by}" + (f": {reason}" if reason else ""))
    patchlog.record_mitigation(mid, "cancelled", by)
    db.event("mitigation", f"#{mid} cancelled by {by}")
    return get(mid, with_playbook=False)


def _notify(mid: int, what: str):
    """Tell other modules (alerting sends it to the channels that alerted about the findings)."""
    events.emit("mitigation.status", mitigation_id=mid, status=what.split(":")[0], detail=what)


# ------------------------------------------------------------------ hand-off targets
def handoffs(public: bool = True) -> list[dict]:
    out = []
    for h in db.q("SELECT * FROM handoffs ORDER BY name"):
        d = dict(h)
        d["config"] = json.loads(h["config"] or "{}")
        if public:
            d["token"] = "***" if h["token"] else ""
        out.append(d)
    return out


def save_handoff(name: str, typ: str, url: str, token: str | None = None, config: dict | None = None,
                 enabled: bool = True, auto: bool = False):
    name = name.strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name):
        raise MitigationError("name: letters, digits, - _ . only")
    if typ not in HANDOFF_TYPES:
        raise MitigationError(f"type must be one of {', '.join(HANDOFF_TYPES)}")
    url = _normalize_url(typ, url.strip())
    if not url.startswith(("http://", "https://")):
        raise MitigationError("url must start with http:// or https://")
    old = db.q1("SELECT token FROM handoffs WHERE name=?", (name,))
    if token in (None, "***"):
        token = old["token"] if old else ""
    db.x("""INSERT INTO handoffs(name, type, url, token, config, enabled, auto) VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(name) DO UPDATE SET type=excluded.type, url=excluded.url, token=excluded.token,
              config=excluded.config, enabled=excluded.enabled, auto=excluded.auto""",
         (name, typ, url, token, json.dumps(config or {}), int(enabled), int(auto)))


def remove_handoff(name: str):
    db.x("DELETE FROM handoffs WHERE name=?", (name,))


def _normalize_url(typ: str, url: str) -> str:
    """Accept the repo page URL for GitHub ("https://github.com/o/r" or "o/r")."""
    if typ == "github":
        m = re.fullmatch(r"(?:https?://github\.com/)?([\w.-]+)/([\w.-]+?)(?:\.git)?/?", url)
        if m:
            return f"https://api.github.com/repos/{m.group(1)}/{m.group(2)}/dispatches"
    return url


def payload(mid: int) -> dict:
    m = get(mid)
    return {"event": "mitigation.approved", "diysca": __version__,
            "mitigation": {k: m[k] for k in ("id", "status", "created_at", "approved_by", "note", "hosts", "summary")},
            "findings": m["findings"], "links": m["links"], "playbook": m["playbook"]}


def _request(h: dict, mid: int) -> tuple[str, dict, dict]:
    """Returns (url, httpx kwargs, description)."""
    cfg = h["config"]
    lk = links(mid)
    m = get(mid, with_playbook=False)
    if h["type"] == "github":
        body = {"event_type": cfg.get("event_type") or "diysca-mitigation",
                "client_payload": {"mitigation_id": mid, "hosts": ",".join(m["hosts"])[:1000],
                                   "findings": m["summary"].get("findings"), "worst_severity": m["summary"].get("worst_severity"),
                                   "approved_by": m["approved_by"], "note": (m["note"] or "")[:500],
                                   "playbook_url": lk["playbook"], "report_url": lk["report"], "ui_url": lk["ui"]}}
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if h["token"]:
            headers["Authorization"] = f"Bearer {h['token']}"
        return h["url"], {"json": body, "headers": headers}, {}
    if h["type"] == "gitlab":
        data = {"token": h["token"] or "", "ref": cfg.get("ref") or "main",
                "variables[DIYSCA_MITIGATION_ID]": str(mid), "variables[DIYSCA_HOSTS]": ",".join(m["hosts"]),
                "variables[DIYSCA_PLAYBOOK_URL]": lk["playbook"], "variables[DIYSCA_REPORT_URL]": lk["report"],
                "variables[DIYSCA_UI_URL]": lk["ui"]}
        return h["url"], {"data": data}, {}
    headers = {"Content-Type": "application/json", "User-Agent": f"diysca/{__version__}"}
    if h["token"]:
        headers["Authorization"] = f"Bearer {h['token']}"
    for k, v in (cfg.get("headers") or {}).items():
        headers[str(k)] = str(v)
    return h["url"], {"content": json.dumps(payload(mid), default=str), "headers": headers}, {}


def deliver(mid: int, target: str) -> tuple[bool, str]:
    row = db.q1("SELECT * FROM handoffs WHERE name=?", (target,))
    if not row:
        return False, f"unknown hand-off target '{target}'"
    h = dict(row)
    h["config"] = json.loads(row["config"] or "{}")
    url, kw, _ = _request(h, mid)
    try:
        with httpx.Client(timeout=settings.http_timeout, verify=settings.http_proxy_ca or True) as c:
            r = c.post(url, **kw)
        ok = r.status_code < 300
        res = f"{target}: HTTP {r.status_code}" + ("" if ok else f" {r.text[:300]}")
    except httpx.HTTPError as e:
        ok, res = False, f"{target}: {type(e).__name__}: {e}"
    db.x("UPDATE mitigations SET handoff=COALESCE(handoff, ?), handoff_result=? WHERE id=?", (target, res, mid))
    _append_log(mid, f"handed off to {res}")
    if not ok:
        db.event("mitigation", f"#{mid} hand-off failed: {res}")
    return ok, res
