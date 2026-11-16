"""Shared web helpers: templates, rendering, query builders for the UI filters and the API."""
from __future__ import annotations

import asyncio
import re
from pathlib import Path

from fastapi import HTTPException, Request
from fastapi.templating import Jinja2Templates

from diysca import __version__
from diysca.core import db, modules, scope, security
from diysca.scanning import scanner
from diysca.scanning.feeds import SEVERITY_ORDER, sev_rank

BASE = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE / "templates"))
templates.env.globals.update(version=__version__, ui_open=security.ui_open, sev_rank=sev_rank, has_module=modules.enabled,
                             nav_items=modules.nav, module_tabs=modules.tabs, tab_group=modules.tab_group,
                             settings_tab_list=modules.settings_tabs)
PAGE_ALIASES = {"system": "systems", "finding": "findings", "mitigation": "mitigations"}
scope_clause = scope.clause


def check_host(host_id: int | None):
    """404 for systems outside the user's scope (so their existence isn't revealed either)."""
    if not scope.allows(host_id):
        raise HTTPException(404)
_bg: set[asyncio.Task] = set()


def actor(request: Request) -> str:
    return getattr(request.state, "actor", "web")


def require(request: Request, role: str):
    """403 unless the user has at least `role` (viewer < operator < approver < admin)."""
    user = getattr(request.state, "user", None)
    if user is not None and not user.can(role):
        raise HTTPException(403, f"needs the {role} role (you are {user.role})")


def _bg_done(t: asyncio.Task):
    _bg.discard(t)
    if not t.cancelled() and t.exception() is not None:  # a background scan or refresh that died: say so
        e = t.exception()
        import logging
        logging.getLogger("diysca").error("background task failed", exc_info=e)
        try:
            db.event("error", f"background task failed: {type(e).__name__}: {e}"[:500])
        except Exception:  # noqa: BLE001
            pass


def _bg_run(coro):
    t = asyncio.create_task(coro)
    _bg.add(t)
    t.add_done_callback(_bg_done)


def render(request: Request, name: str, **ctx):
    page = name.split(".")[0]
    ctx["saved_filters"] = db.q("SELECT * FROM saved_filters WHERE page=? ORDER BY name", (page,))
    ctx["page"] = page
    ctx["tab_page"] = PAGE_ALIASES.get(page, page)
    group = modules.tab_group(ctx["tab_page"])
    ctx["section"] = "settings" if "tab" in ctx else (group or ctx["tab_page"])
    ctx["user"] = getattr(request.state, "user", None)
    ctx["query_string"] = str(request.url.query)
    ctx["running"] = bool(scanner.running) or scanner._scan_lock.locked()
    ctx["extra_source_names"] = ", ".join(r["name"] for r in db.q("SELECT name FROM feed_sources WHERE enabled=1 ORDER BY name"))
    return templates.TemplateResponse(request, name, ctx)


def _esc(v: str) -> str:
    return v.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_").replace("*", "%")


def _like(v: str) -> str:
    """Substring match, * as wildcard."""
    return "%" + _esc(v) + "%"


def name_like(v: str) -> str:
    """A system name matches as a whole: `web1` is not `web10`. Use * for the rest (`web*`)."""
    return _esc(v.strip())


LIKE = "LIKE ? ESCAPE '\\'"


# ------------------------------------------------------------ filters
def host_filter(args: dict, alias="h"):
    where, p = ["1=1" + scope.clause(f"{alias}.id")], []
    if args.get("host"):
        where.append(f"({alias}.name {LIKE} OR {alias}.address {LIKE})")
        p += [name_like(args["host"])] * 2
    if args.get("group"):
        where.append(f"(',' || {alias}.groups || ',') LIKE ?")
        p.append(f"%,{args['group']},%")
    if args.get("os"):
        where.append(f"({alias}.os_pretty {LIKE} OR {alias}.os_id {LIKE})")
        p += [_like(args["os"])] * 2
    if args.get("kind") in ("host", "container"):
        where.append(f"{alias}.kind=?")
        p.append(args["kind"])
    return where, p


FINDINGS_LIMIT = 5000  # rows a list page or API list shows at most


def finding_query(args: dict, limit: int | None = FINDINGS_LIMIT):
    """SQL for the findings list. `limit=None` gives every match: anything that acts on "all findings in this
    filter" (approve, playbook) must not stop at what a page can show."""
    where, p = _finding_where(args)
    sql = f"""SELECT f.*, h.name AS host_name, h.groups AS host_groups, mi.status AS mitigation_status
              FROM findings f JOIN hosts h ON h.id=f.host_id LEFT JOIN mitigations mi ON mi.id=f.mitigation_id
              WHERE {' AND '.join(where)}
              ORDER BY f.kev DESC, CASE f.severity WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4 WHEN 'MEDIUM' THEN 3
                       WHEN 'LOW' THEN 2 ELSE 1 END DESC, f.cvss_score DESC, h.name, f.package"""
    return sql + (f" LIMIT {int(limit)}" if limit else ""), p


def finding_count(args: dict) -> int:
    where, p = _finding_where(args)
    return db.q1(f"""SELECT COUNT(*) n FROM findings f JOIN hosts h ON h.id=f.host_id
                     LEFT JOIN mitigations mi ON mi.id=f.mitigation_id WHERE {' AND '.join(where)}""", p)["n"]


def _finding_where(args: dict):
    where, p = host_filter(args)
    status = args.get("status", "open")
    if status and status != "all":
        where.append("f.status=?")
        p.append(status)
    if args.get("package"):
        where.append(f"(f.package {LIKE} OR f.binaries {LIKE})")
        p += [_like(args["package"])] * 2
    if args.get("cve"):
        where.append(f"(f.vuln_id {LIKE} OR f.osv_ids {LIKE})")
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
    return where, p


def package_query(args: dict):
    where, p = host_filter(args)
    if args.get("name"):
        where.append(f"(pk.name {LIKE} OR pk.source_name {LIKE})")
        p += [_like(args["name"])] * 2
    if args.get("version"):
        where.append(f"pk.version {LIKE}")
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



def _ids_from_filter(query: str) -> list[int]:
    from urllib.parse import parse_qsl
    args = dict(parse_qsl(query))
    args.setdefault("status", "open")
    sql, p = finding_query(args, limit=None)
    return [r["id"] for r in db.q(sql, p)]


def csv_cell(v):
    """A CSV cell that a spreadsheet won't run as a formula. Host, package and actor names come from scanned
    systems and logins; one that starts with = + - @ would be evaluated when the export is opened."""
    v = "" if v is None else v
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


def download_name(name: str) -> str:
    """A file name that is safe inside a Content-Disposition header."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(name))[:100] or "diysca"


def rows(r):
    return [dict(x) for x in r]



_SECRET_KEYS = ("password", "token", "api_key", "secret", "credential", "private_key")


def _masked(v):
    if isinstance(v, dict):
        return {k: ("***" if any(s in k for s in _SECRET_KEYS) and v[k] and not k.endswith(("_env", "_file")) else _masked(x))
                for k, x in v.items()}
    if isinstance(v, list):
        return [_masked(x) for x in v]
    if isinstance(v, str) and "://" in v and "@" in v:
        return re.sub(r"://[^@/]*@", "://***@", v)
    return v
