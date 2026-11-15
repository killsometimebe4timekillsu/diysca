"""Command line: diysca serve | scan | import | sbom | feeds | notify."""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys

from diysca import __version__
from diysca.alerting import notify
from diysca.core import db
from diysca.core.config import reload, settings
from diysca.scanning import scanner
from diysca.scanning.feeds import BulkOSVClient, refresh_kev
from diysca.scanning.sbom import sbom_json


def main(argv=None):
    try:
        _main(argv)
    except BrokenPipeError:  # `diysca findings | head`: the reader went away, that's fine
        import os
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(0)


def _main(argv=None):
    ap = argparse.ArgumentParser("diysca", description="poor man's DIY CVE scanner")
    ap.add_argument("-c", "--config", help="config.yml (default: ./config.yml or $DIYSCA_CONFIG)")
    ap.add_argument("--version", action="version", version=__version__)
    sp = ap.add_subparsers(dest="cmd", required=True)

    s = sp.add_parser("serve", help="run web UI + scheduler")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", type=int, default=8080)

    s = sp.add_parser("desktop", help="run the UI on localhost and open it in the browser (AppImage/Flatpak launcher)")
    s.add_argument("--port", type=int, default=8765)

    s = sp.add_parser("scan", help="scan hosts now")
    s.add_argument("hosts", nargs="*", help="host names or patterns: web* db1 group:prod !test-* (default: all enabled)")
    s.add_argument("--no-alerts", action="store_true")
    s.add_argument("--no-nvd", action="store_true", help="skip the NVD lookup after the scan (it is time-boxed anyway)")

    s = sp.add_parser("patchlog", help="export the patch log (who patched what, when, approved by whom)")
    s.add_argument("--range", default="30d", help="24h, 7d, 30d, 90d, 1y or custom (with --from / --to)")
    s.add_argument("--from", dest="from_", default="")
    s.add_argument("--to", default="")
    s.add_argument("--kind", default="", help="playbook, repo, mitigation, reprovision")
    s.add_argument("--host", default="")
    s.add_argument("--cve", default="")
    s.add_argument("--format", choices=["csv", "json"], default="csv")
    s.add_argument("-o", "--output", default="-", help="file (default: stdout)")

    s = sp.add_parser("import", help="import Ansible inventories and inventory providers")
    s.add_argument("paths", nargs="*", help="inventory files/dirs (default: config inventories)")

    s = sp.add_parser("add-host", help="add a host manually")
    s.add_argument("name")
    s.add_argument("--address")
    s.add_argument("--port", type=int, default=22)
    s.add_argument("--user")
    s.add_argument("--groups", default="")
    s.add_argument("--local", action="store_true", help="scan the machine diysca runs on")

    s = sp.add_parser("hosts", help="list hosts")
    s = sp.add_parser("findings", help="list open findings")
    s.add_argument("--host")
    s.add_argument("--json", action="store_true")

    s = sp.add_parser("sbom", help="print CycloneDX SBOM for a host")
    s.add_argument("host")

    s = sp.add_parser("feeds", help="refresh vulnerability feeds (bulk OSV mirror, KEV)")
    s.add_argument("ecosystems", nargs="*", help="e.g. 'Debian:12' 'Ubuntu:24.04:LTS' (default: from scanned hosts)")

    s = sp.add_parser("channel", help="add/replace an alert channel")
    s.add_argument("name")
    s.add_argument("url", help="Apprise URL, e.g. ntfy://ntfy.sh/topic")

    s = sp.add_parser("subscribe", help="add a subscription")
    s.add_argument("name")
    s.add_argument("--channel", required=True)
    s.add_argument("--hosts", default="*")
    s.add_argument("--packages", default="*")
    s.add_argument("--min-severity", default="HIGH")
    s.add_argument("--only-kev", action="store_true")
    s.add_argument("--only-fixable", action="store_true")

    s = sp.add_parser("playbook", help="generate an Ansible patch playbook")
    s.add_argument("--host", action="append", help="only these hosts (repeatable)")
    s.add_argument("--filter", default="fix=repo", help="findings filter like the UI, e.g. 'fix=repo&severity=HIGH'")
    s.add_argument("-o", "--output", help="write to file instead of stdout")

    s = sp.add_parser("repo-update", help="sync/publish/promote a self-hosted repo (aptly, pulp, foreman)")
    s.add_argument("name", nargs="?", help="repo manager name from config (omit to list them)")
    s.add_argument("--run", action="store_true", help="really do it (default is a dry run)")
    s.add_argument("--stage", action="append", help="Foreman lifecycle environment(s) to promote to")

    s = sp.add_parser("notify", help="send pending alerts")
    s.add_argument("--dry-run", action="store_true")

    s = sp.add_parser("reprovision", help="Ansible playbook that rebuilds a system from its SBOM")
    s.add_argument("host", nargs="?", help="system name (or use --sbom)")
    s.add_argument("--sbom", help="CycloneDX JSON file instead of a scanned system")
    s.add_argument("--mode", choices=["fixed", "exact"], default="fixed")
    s.add_argument("--target", help="inventory host or group to run against (default: the system name)")
    s.add_argument("-o", "--output")

    s = sp.add_parser("settings", help="export or import settings (sources, channels, subscriptions, saved filters)")
    s.add_argument("action", choices=["export", "import"])
    s.add_argument("file", nargs="?", help="import: YAML/JSON file (default stdin)")
    s.add_argument("--secrets", action="store_true", help="export: include channel URLs and source headers")
    s.add_argument("--replace", action="store_true", help="import: remove items that are not in the file")
    s.add_argument("--dry-run", action="store_true")

    s = sp.add_parser("sources", help="list or refresh the extra CVE sources (config.yml `sources:` / web UI)")
    s.add_argument("--refresh", nargs="?", const="all", metavar="NAME", help="download now (all, or one source)")

    s = sp.add_parser("patched", help="list patched CVEs in a time range")
    s.add_argument("--range", default="last", help="last | 24h | 7d | 30d | 90d | 1y | custom")
    s.add_argument("--from", dest="frm", default="", help="custom range start (YYYY-MM-DD)")
    s.add_argument("--to", default="", help="custom range end (YYYY-MM-DD)")
    s.add_argument("--host", default="")

    s = sp.add_parser("mcp", help="run the MCP server on stdio (for MCP clients and agents)")
    s.add_argument("--actor", default="mcp:stdio", help="name recorded when this client claims or reports")

    s = sp.add_parser("mitigations", help="approved findings handed off for mitigation")
    s.add_argument("action", nargs="?", default="list",
                   choices=["list", "show", "approve", "claim", "report", "cancel", "playbook"])
    s.add_argument("id", nargs="?", type=int, help="mitigation id (show, claim, report, cancel, playbook)")
    s.add_argument("--status", default="", help="list: open|approved|...|all; report: running|done|failed")
    s.add_argument("--ids", default="", help="approve: comma separated finding ids")
    s.add_argument("--filter", default="", help="approve: findings filter, e.g. 'host=web1&fix=repo'")
    s.add_argument("--note", default="")
    s.add_argument("--handoff", default="", help="approve: hand-off target name")
    s.add_argument("--log", default="", help="report: text or @file")
    s.add_argument("--by", default=os.environ.get("USER", "cli"), help="who approves / claims / reports")

    a = ap.parse_args(argv)
    if a.config:
        reload(a.config)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    db.connect()

    if a.cmd == "serve":
        import uvicorn

        from diysca.core.security import LOOPBACK, open_listen_error, ui_open
        from diysca.web import app
        err = open_listen_error(a.host)
        if err:
            logging.error(err)
            sys.exit(2)
        if ui_open() and a.host not in LOOPBACK:
            logging.warning("allow_no_login is set and no login is configured: everyone who can reach %s:%s is an "
                            "admin.", a.host, a.port)
        uvicorn.run(app, host=a.host, port=a.port, proxy_headers=True)
    elif a.cmd == "desktop":
        import threading
        import webbrowser

        import uvicorn

        from diysca.web import app
        url = f"http://127.0.0.1:{a.port}/"
        settings.base_url = url.rstrip("/")
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()
        print(f"diysca UI on {url} (Ctrl+C to quit)")
        uvicorn.run(app, host="127.0.0.1", port=a.port)
    elif a.cmd == "scan":
        ids = None
        if settings.inventories:
            scanner.import_inventories()
        if a.hosts:
            ids = scanner.select_hosts(a.hosts)
            if not ids:
                sys.exit("no system matches " + " ".join(a.hosts))
        if a.no_alerts:
            async def run():
                await refresh_kev()
                return [await scanner.scan_host(i, send_alerts=False) for i in ids or
                        [r["id"] for r in db.q("SELECT id FROM hosts WHERE enabled=1")]]
            res = asyncio.run(run())
        else:
            res = asyncio.run(scanner.scan_all(host_ids=ids, enrich="off" if a.no_nvd else "inline"))
        for r in res:
            print(json.dumps(r))
    elif a.cmd == "patchlog":
        from diysca.mitigation import patchlog
        d = patchlog.query({"range": a.range, "from": a.from_, "to": a.to, "kind": a.kind, "host": a.host,
                            "cve": a.cve})
        text = patchlog.to_csv(d["rows"]) if a.format == "csv" else \
            patchlog.to_json(d["rows"], {"range": d["range"], "start": d["start"], "end": d["end"]})
        if a.output == "-":
            sys.stdout.write(text)
        else:
            with open(a.output, "w") as fh:
                fh.write(text)
            print(f"{len(d['rows'])} entries -> {a.output}", file=sys.stderr)
    elif a.cmd == "import":
        print(f"imported {scanner.import_inventories(a.paths or None)} hosts")
    elif a.cmd == "add-host":
        db.x("""INSERT INTO hosts(name,address,port,ssh_user,groups,connection) VALUES (?,?,?,?,?,?)
                ON CONFLICT(name) DO UPDATE SET address=excluded.address, port=excluded.port,
                ssh_user=excluded.ssh_user, groups=excluded.groups, connection=excluded.connection""",
             (a.name, a.address or a.name, a.port, a.user, a.groups, "local" if a.local else "ssh"))
        print("ok")
    elif a.cmd == "hosts":
        for h in db.q("SELECT * FROM hosts ORDER BY name"):
            print(f"{h['name']:24} {h['address'] or '':20} {h['os_pretty'] or '-':28} {h['groups'] or '':20} "
                  f"{h['last_scan'] or 'never'} {h['last_status'] or ''}")
    elif a.cmd == "findings":
        sql = """SELECT f.*, h.name host FROM findings f JOIN hosts h ON h.id=f.host_id WHERE f.status='open'"""
        params = []
        if a.host:
            sql += " AND h.name=?"
            params.append(a.host)
        rows = db.q(sql + " ORDER BY f.cvss_score DESC", params)
        if a.json:
            print(json.dumps([dict(r) for r in rows], indent=2))
        else:
            for r in rows:
                print(notify.format_finding(r, {"name": r["host"]}))
    elif a.cmd == "sbom":
        h = db.q1("SELECT id FROM hosts WHERE name=?", (a.host,))
        if not h:
            sys.exit("no such host")
        print(sbom_json(h["id"]))
    elif a.cmd == "feeds":
        ecos = a.ecosystems or sorted({r["ecosystem"] for r in db.q("SELECT DISTINCT ecosystem FROM hosts") if r["ecosystem"]})

        async def run():
            c = BulkOSVClient()
            try:
                for e in ecos:
                    print(e, await c.ensure(e, force=True))
            finally:
                await c.close()
            print("KEV", await refresh_kev(force=True))
        asyncio.run(run())
    elif a.cmd == "channel":
        db.x("INSERT INTO channels(name,url) VALUES (?,?) ON CONFLICT(name) DO UPDATE SET url=excluded.url", (a.name, a.url))
        print("ok")
    elif a.cmd == "subscribe":
        ch = db.q1("SELECT id FROM channels WHERE name=?", (a.channel,))
        if not ch:
            sys.exit("no such channel")
        db.x("""INSERT INTO subscriptions(name,channel_id,host_pattern,package_pattern,min_severity,only_kev,only_fixable)
                VALUES (?,?,?,?,?,?,?)""", (a.name, ch["id"], a.hosts, a.packages, a.min_severity.upper(),
                                            int(a.only_kev), int(a.only_fixable)))
        print("ok")
    elif a.cmd == "playbook":
        from urllib.parse import parse_qsl

        from diysca.mitigation import patch
        from diysca.ui import finding_query
        args = dict(parse_qsl(a.filter))
        args.setdefault("status", "open")
        sql, params = finding_query(args)
        rows = db.q(sql, params)
        if a.host:
            rows = [r for r in rows if r["host_name"] in a.host]
        text, summary = patch.build_playbook([r["id"] for r in rows])
        if summary["hosts"]:
            from diysca.mitigation import patchlog
            patchlog.record_playbook([r["id"] for r in rows], summary, f"cli:{os.environ.get('USER', 'cli')}")
        if a.output:
            with open(a.output, "w") as fh:
                fh.write(text)
            print(f"wrote {a.output}: {summary}", file=sys.stderr)
        else:
            print(text)
    elif a.cmd == "repo-update":
        from diysca.mitigation import repomgr
        if not a.name:
            for m in repomgr.managers():
                print(f"{m['name']:20} {m.get('type', '?'):8} {m.get('url', '')}  pending: {len(repomgr.pending_for(m))}")
            return
        res = asyncio.run(repomgr.run(a.name, dry_run=not a.run, stages=a.stage))
        for st in res.steps:
            print(f"[{st.status:7}] {st.action}: {st.detail} {st.info}")
        if not res.ok:
            sys.exit(1)
    elif a.cmd == "notify":
        print(f"sent {asyncio.run(notify.dispatch(dry_run=a.dry_run))} alerts")
    elif a.cmd == "reprovision":
        from diysca.mitigation import reprovision
        if a.sbom:
            with open(a.sbom) as fh:
                text, summary = reprovision.build(json.load(fh), a.mode, a.target)
        else:
            h = db.q1("SELECT id FROM hosts WHERE name=?", (a.host,))
            if not h:
                sys.exit(f"unknown system {a.host!r}")
            text, summary = reprovision.for_host(h["id"], a.mode, a.target)
        if a.output:
            with open(a.output, "w") as fh:
                fh.write(text)
            print(f"wrote {a.output}: {summary}", file=sys.stderr)
        else:
            print(text)
    elif a.cmd == "settings":
        from diysca.core import settings_io
        if a.action == "export":
            print(settings_io.export_yaml(a.secrets), end="")
        else:
            body = open(a.file).read() if a.file else sys.stdin.read()
            res = settings_io.import_bundle(settings_io.parse(body), replace=a.replace, dry_run=a.dry_run)
            print(res)
            if res["errors"]:
                sys.exit(1)
    elif a.cmd == "sources":
        from diysca.scanning import sources
        sources.sync_config_sources()
        if a.refresh:
            names = [s["name"] for s in sources.all_sources() if s["enabled"]] if a.refresh == "all" else [a.refresh]
            for n in names:
                print(asyncio.run(sources.refresh(n, force=True)))
        for s in sources.all_sources():
            print(f"{s['name']:<20} {s['type']:<15} {'on ' if s['enabled'] else 'off'} {s['origin']:<6} "
                  f"{s['count'] or 0:>8} {s['status'] or 'not loaded'} {s['error'] or ''}")
    elif a.cmd == "patched":
        from diysca.mitigation import patched
        d = patched.query({"range": a.range, "from": a.frm, "to": a.to, "host": a.host})
        st = d["stats"]
        print(f"# {d['label']}: {st['cves']} CVEs / {st['findings']} findings patched on {st['systems']} systems, "
              f"median {st['median_days']} days to patch")
        for f in d["rows"]:
            print(f"{f['resolved_at'][:16]}  {f['host_name']:<20} {f['severity'] or '':<8} {f['vuln_id']:<18} "
                  f"{f['package']} {f['version']} -> {f['resolved_version'] or '-'} ({f['resolution'] or '?'})")
    elif a.cmd == "mcp":
        from diysca import mcp
        asyncio.run(mcp.serve_stdio(a.actor))
    elif a.cmd == "mitigations":
        _mitigations(a)


def _mitigations(a):
    from diysca.mitigation import mitigate
    try:
        if a.action == "list":
            for m in mitigate.list_(a.status or "open"):
                print(f"#{m['id']:<5} {m['status']:<9} {m['created_at'][:16]}  {m['findings']:>4} findings "
                      f"({m['still_open']} open)  {', '.join(m['summary'].get('hosts', [])[:5])}  by {m['approved_by']}"
                      + (f"  -> {m['handoff']}" if m["handoff"] else ""))
            return
        if a.action == "approve":
            ids = [int(i) for i in a.ids.split(",") if i.strip()]
            if not ids and a.filter:
                from diysca.ui import _ids_from_filter
                ids = _ids_from_filter(a.filter)
            m = mitigate.approve(ids, a.by, a.note, a.handoff or None)
            print(f"mitigation #{m['id']} approved: {len(m['findings'])} findings on {', '.join(m['hosts'])}")
            print(m["links"]["ui"])
            return
        if a.id is None:
            sys.exit("give the mitigation id")
        if a.action == "show":
            m = mitigate.get(a.id, with_playbook=False)
            if not m:
                sys.exit(f"no mitigation #{a.id}")
            print(json.dumps(m, indent=2, default=str))
        elif a.action == "playbook":
            m = mitigate.get(a.id)
            if not m:
                sys.exit(f"no mitigation #{a.id}")
            print(m["playbook"])
        elif a.action == "claim":
            print(f"#{a.id}: {mitigate.claim(a.id, a.by)['status']}")
        elif a.action == "report":
            log = open(a.log[1:]).read() if a.log.startswith("@") else a.log
            m, rescan = mitigate.report(a.id, a.status, a.by, log)
            print(f"#{a.id}: {m['status']}")
            if rescan:
                asyncio.run(scanner.scan_all(host_ids=rescan))
                print(f"rescanned {len(rescan)} system(s)")
        elif a.action == "cancel":
            print(f"#{a.id}: {mitigate.cancel(a.id, a.by, a.note)['status']}")
    except (mitigate.MitigationError, KeyError) as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
