"""MCP (Model Context Protocol) server for diysca.

Two transports, same tools:

* stdio:  `diysca mcp` (for desktop MCP clients and local agents; uses config.yml and the database directly)
* HTTP:   `POST <base_url>/mcp` (streamable HTTP with plain JSON responses; send `Authorization: Bearer <token>`)

The tools let an agent look at systems, findings, SBOMs and patched CVEs, and work through approved
mitigations: list them, claim one, fetch its playbook, report running / done / failed. Approving or
cancelling is a person's decision, so those tools only appear when `agents_can_approve: true`.
"""
from __future__ import annotations

import asyncio
import json
import sys

from diysca import __version__
from diysca.core import db, modules
from diysca.core.config import settings
from diysca.mitigation import mitigate, patch, patched
from diysca.scanning import scanner

PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
MAX_TEXT = 200_000
_tasks: set[asyncio.Task] = set()

INSTRUCTIONS = (
    "diysca is a self-hosted CVE scanner. Findings are vulnerable packages on systems. A person approves findings "
    "into a mitigation; an agent that can reach the systems claims it (claim_mitigation), runs the playbook from "
    "get_mitigation with ansible-playbook (dry run with --check first), and reports the result with "
    "report_mitigation (running, then done or failed, with the output as log). On done, diysca rescans the systems."
)


class Context:
    """Who is calling. Agents (token holders, stdio) may approve only with the approver role
    (agents_can_approve: true, or a token with role: approver)."""

    def __init__(self, actor: str = "mcp", is_token: bool = True, is_agent: bool | None = None, user=None):
        from diysca.core.security import User, token_user
        if user is None:
            user = token_user(actor.removeprefix("token:"), {}) if (is_token if is_agent is None else is_agent) \
                else User(name=actor)
            user.name = actor
        self.user = user
        self.actor = user.name
        self.is_agent = user.is_agent if is_agent is None else is_agent

    @property
    def may_approve(self) -> bool:
        return self.user.can("approver")


def _s(desc: str, **props) -> dict:
    req = [k for k, v in props.items() if v.pop("required", False)]
    return {"description": desc, "inputSchema": {"type": "object", "properties": props, "required": req,
                                                 "additionalProperties": False}}


_SEV = {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"], "description": "minimum severity"}
_IDS = {"type": "array", "items": {"type": "integer"}, "description": "finding ids"}
_FILTER = {"type": "string", "description": "findings filter as a query string, e.g. host=web1&fix=repo&severity=HIGH"}

TOOLS: dict[str, dict] = {
    "list_systems": _s("List scanned systems (hosts and containers) with open finding counts.",
                       host={"type": "string", "description": "name or address, * wildcards"},
                       group={"type": "string"}, os={"type": "string"}),
    "search_findings": _s(
        "Search vulnerable packages, worst first. Returns at most `limit` rows.",
        status={"type": "string", "enum": ["open", "ignored", "resolved", "all"], "default": "open"},
        host={"type": "string"}, group={"type": "string"}, package={"type": "string"},
        cve={"type": "string", "description": "CVE or advisory id, prefix match"}, severity=_SEV,
        fix={"type": "string", "enum": ["repo", "upstream", "none"],
             "description": "repo: fix is in your repos; upstream: released but not in your repos; none: no fix yet"},
        kev={"type": "boolean", "description": "only known exploited (CISA KEV)"},
        eco={"type": "string", "description": "os, lang, or an ecosystem like PyPI, npm, Maven"},
        approval={"type": "string", "enum": ["approved", "unapproved"]},
        limit={"type": "integer", "default": 100, "minimum": 1, "maximum": 5000}),
    "get_finding": _s("One finding with its mitigation, if any.", id={"type": "integer", "required": True}),
    "get_sbom": _s("CycloneDX SBOM of a system (OS and language packages, container images, repos).",
                   host={"type": "string", "required": True, "description": "system name or id"}),
    "list_patched": _s(
        "Findings that were patched in a time range, with how (upgraded, removed, not-affected).",
        range={"type": "string", "enum": ["last", "24h", "7d", "30d", "90d", "1y", "custom"], "default": "7d"},
        **{"from": {"type": "string", "description": "YYYY-MM-DD, with range=custom"},
           "to": {"type": "string", "description": "YYYY-MM-DD, with range=custom"}},
        host={"type": "string"}, group={"type": "string"}, severity=_SEV),
    "generate_playbook": _s("Ansible playbook that upgrades the given findings to the version your repos offer. "
                            "Read only: it does not run anything.", finding_ids=_IDS, filter=_FILTER),
    "list_mitigations": _s("List mitigations. status=approved are waiting for someone to claim them.",
                           status={"type": "string", "enum": ["open", "approved", "claimed", "running", "done",
                                                              "failed", "cancelled", "all"], "default": "open"}),
    "get_mitigation": _s("A mitigation with its findings, links, log and (by default) the playbook.",
                         id={"type": "integer", "required": True},
                         include_playbook={"type": "boolean", "default": True}),
    "claim_mitigation": _s("Claim an approved mitigation so no one else runs it. Fails if it is not approved any more.",
                           id={"type": "integer", "required": True}),
    "report_mitigation": _s("Report progress on a mitigation you claimed. done triggers a rescan of its systems.",
                            id={"type": "integer", "required": True},
                            status={"type": "string", "enum": ["running", "done", "failed"], "required": True},
                            log={"type": "string", "description": "what was done, e.g. the ansible-playbook output"}),
    "patch_log": _s("The patch log: one entry per playbook, repo update, rebuild playbook and finished mitigation, with "
                    "approver, executor, result and whether the rescan verified the fix.",
                    range={"type": "string", "enum": ["24h", "7d", "30d", "90d", "1y", "custom"], "default": "30d"},
                    **{"from": {"type": "string"}, "to": {"type": "string"}},
                    kind={"type": "string", "enum": ["playbook", "repo", "mitigation", "reprovision"]},
                    host={"type": "string"}, cve={"type": "string"}, status={"type": "string"}),
    "start_scan": _s("Scan systems now and return the results: one (host), a selection (hosts patterns and / or "
                     "host_ids) or every enabled system (nothing given).",
                     host={"type": "string", "description": "one system name"},
                     hosts={"type": "string", "description": "patterns: web*,db1 | group:prod | !test-*"},
                     host_ids={"type": "array", "items": {"type": "integer"}, "description": "system ids"}),
    "approve_findings": _s("Approve findings for mitigation (only offered when agents_can_approve is on).",
                           finding_ids=_IDS, filter=_FILTER, note={"type": "string"},
                           handoff={"type": "string", "description": "hand-off target name"}),
    "cancel_mitigation": _s("Cancel a mitigation (only offered when agents_can_approve is on).",
                            id={"type": "integer", "required": True}, reason={"type": "string"}),
}
_APPROVER_TOOLS = {"approve_findings", "cancel_mitigation"}
_OPERATOR_TOOLS = {"claim_mitigation", "report_mitigation", "start_scan"}
_READ_ONLY = {"patch_log", "list_systems", "search_findings", "get_finding", "get_sbom", "list_patched", "generate_playbook",
              "list_mitigations", "get_mitigation"}


def tool_list(ctx: Context) -> list[dict]:
    out = []
    enabled = modules.mcp_tools()
    for name, t in TOOLS.items():
        if name not in enabled or (name in _APPROVER_TOOLS and not ctx.may_approve) or \
                (name in _OPERATOR_TOOLS and not ctx.user.can("operator")):
            continue
        out.append({"name": name, **t, "annotations": {"readOnlyHint": name in _READ_ONLY}})
    return out


def _ids(args: dict) -> list[int]:
    from diysca.ui import _ids_from_filter
    ids = [int(i) for i in args.get("finding_ids") or []]
    if not ids and args.get("filter"):
        ids = _ids_from_filter(str(args["filter"]))
    return ids


def _host_id(ref: str) -> int:
    row = db.q1("SELECT id FROM hosts WHERE name=?", (ref,))
    if not row and str(ref).isdigit():
        row = db.q1("SELECT id FROM hosts WHERE id=?", (int(ref),))
    from diysca.core import scope
    if not row or not scope.allows(row["id"]):  # systems outside the token's scope don't exist for it
        raise ValueError(f"no system '{ref}'")
    return row["id"]


def _bg(coro):
    t = asyncio.get_running_loop().create_task(coro)
    _tasks.add(t)
    t.add_done_callback(_tasks.discard)


async def call(name: str, args: dict, ctx: Context):
    from diysca import ui as web
    from diysca.scanning.sbom import build_sbom

    if name not in {t["name"] for t in tool_list(ctx)}:
        raise ValueError(f"unknown tool {name}")
    a = {k: v for k, v in (args or {}).items() if v is not None}
    if name == "list_systems":
        sql, p = web.hosts_query({k: str(v) for k, v in a.items()})
        return [dict(r) for r in db.q(sql, p)]
    if name == "search_findings":
        limit = int(a.pop("limit", 100))
        if a.pop("kev", False):
            a["kev"] = "1"
        a.setdefault("status", "open")
        sql, p = web.finding_query({k: str(v) for k, v in a.items()})
        rows = db.q(sql, p)
        keep = ("id", "host_name", "package", "version", "ecosystem", "location", "vuln_id", "severity", "cvss_score",
                "kev", "epss", "fixed_version", "repo_version", "fix_in_repo", "status", "mitigation_id",
                "mitigation_status", "first_seen", "summary")
        return {"total": len(rows), "findings": [{k: r[k] for k in keep} for r in rows[:limit]]}
    if name == "get_finding":
        from diysca.scanning.routes import api_finding
        return api_finding(int(a["id"]))
    if name == "get_sbom":
        return build_sbom(_host_id(str(a["host"])))
    if name == "list_patched":
        d = patched.query({k: str(v) for k, v in a.items()})
        return {"range": d["range"], "start": d["start"], "end": d["end"], "stats": d["stats"],
                "findings": [dict(r) for r in d["rows"]]}
    if name == "generate_playbook":
        text, summary = patch.build_playbook(_ids(a))
        return {"summary": summary, "playbook": text}
    if name == "list_mitigations":
        return mitigate.list_(a.get("status", "open"))
    if name == "get_mitigation":
        m = mitigate.get(int(a["id"]), with_playbook=a.get("include_playbook", True))
        if not m:
            raise ValueError(f"no mitigation #{a['id']}")
        return m
    if name == "claim_mitigation":
        return mitigate.claim(int(a["id"]), ctx.actor)
    if name == "report_mitigation":
        m, rescan = mitigate.report(int(a["id"]), str(a["status"]), ctx.actor, str(a.get("log") or ""))
        if rescan:
            _bg(scanner.scan_all(host_ids=rescan))
        return {**m, "rescan_hosts": mitigate.host_names(rescan)}
    if name == "patch_log":
        from diysca.mitigation import patchlog
        d = patchlog.query({k: str(v) for k, v in a.items()})
        return {"range": d["range"], "start": d["start"], "end": d["end"], "entries": d["rows"]}
    if name == "start_scan":
        if a.get("host"):
            hid = _host_id(str(a["host"]))
            res = await scanner.scan_host(hid)
            scanner.start_nvd_enrichment([hid])
            return res
        sel = scanner.select_hosts(a.get("hosts"), a.get("host_ids"))
        if (a.get("hosts") or a.get("host_ids")) and not sel:
            raise ValueError("no system matches")
        return await scanner.scan_all(host_ids=sel)
    if name == "approve_findings":
        return mitigate.approve(_ids(a), ctx.actor, str(a.get("note") or ""), a.get("handoff") or None,
                                filter=str(a.get("filter") or "") or None)
    if name == "cancel_mitigation":
        return mitigate.cancel(int(a["id"]), ctx.actor, str(a.get("reason") or ""))
    raise ValueError(f"unknown tool {name}")


def _err(id_, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


async def _one(msg, ctx: Context):
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or "method" not in msg:
        return _err(msg.get("id") if isinstance(msg, dict) else None, -32600, "invalid request")
    method, id_, params = msg["method"], msg.get("id"), msg.get("params") or {}
    if "id" not in msg:  # notification (initialized, cancelled, ...)
        return None
    if method == "initialize":
        want = params.get("protocolVersion")
        result = {"protocolVersion": want if want in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
                  "capabilities": {"tools": {"listChanged": False}},
                  "serverInfo": {"name": "diysca", "title": "diysca CVE scanner", "version": __version__},
                  "instructions": INSTRUCTIONS}
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": tool_list(ctx)}
    elif method in ("resources/list", "prompts/list", "resources/templates/list"):
        result = {{"resources/list": "resources", "prompts/list": "prompts",
                   "resources/templates/list": "resourceTemplates"}[method]: []}
    elif method == "tools/call":
        name = params.get("name")
        if name not in {t["name"] for t in tool_list(ctx)}:
            return _err(id_, -32602, f"unknown tool: {name}")
        try:
            data = await call(name, params.get("arguments") or {}, ctx)
            text = json.dumps(data, default=str, indent=1)
            if len(text) > MAX_TEXT:
                text = text[:MAX_TEXT] + "\n... (truncated; narrow the query)"
            result = {"content": [{"type": "text", "text": text}], "isError": False}
        except (ValueError, KeyError, mitigate.MitigationError) as e:
            result = {"content": [{"type": "text", "text": f"Error: {e}"}], "isError": True}
    else:
        return _err(id_, -32601, f"method not found: {method}")
    return {"jsonrpc": "2.0", "id": id_, "result": result}


async def handle(msg, ctx: Context):
    """Handle one JSON-RPC message or a batch. Returns the response (None for notifications)."""
    if isinstance(msg, list):
        out = [r for r in [await _one(m, ctx) for m in msg] if r is not None]
        return out or None
    return await _one(msg, ctx)


async def serve_stdio(actor: str = "mcp:stdio"):
    """Newline-delimited JSON-RPC on stdin/stdout. Logs go to stderr."""
    db.connect()
    ctx = Context(actor=actor, is_agent=True)
    loop = asyncio.get_running_loop()
    print(f"diysca {__version__} MCP server on stdio (database: "
          f"{'PostgreSQL' if db.is_postgres() else settings.database})", file=sys.stderr)
    while True:
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            out = _err(None, -32700, "parse error")
        else:
            out = await handle(msg, ctx)
        if out is not None:
            sys.stdout.write(json.dumps(out, default=str) + "\n")
            sys.stdout.flush()
    if _tasks:
        await asyncio.gather(*_tasks, return_exceptions=True)

