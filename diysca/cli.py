"""Command line: diysca serve | scan | import | sbom | feeds | notify."""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys

from . import __version__, db, notify, scanner
from .config import reload, settings
from .feeds import BulkOSVClient, osv_ecosystem, refresh_kev
from .sbom import sbom_json


def main(argv=None):
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
    s.add_argument("hosts", nargs="*", help="host names (default: all enabled)")
    s.add_argument("--no-alerts", action="store_true")

    s = sp.add_parser("import", help="import Ansible inventory")
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

    a = ap.parse_args(argv)
    if a.config:
        reload(a.config)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    db.connect()

    if a.cmd == "serve":
        import uvicorn

        from .web import app
        uvicorn.run(app, host=a.host, port=a.port, proxy_headers=True)
    elif a.cmd == "desktop":
        import threading
        import webbrowser

        import uvicorn

        from .web import app
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
            ids = [r["id"] for r in db.q(f"SELECT id FROM hosts WHERE name IN ({','.join('?' * len(a.hosts))})", a.hosts)]
            if not ids:
                sys.exit("no such host(s)")
        if a.no_alerts:
            async def run():
                await refresh_kev()
                return [await scanner.scan_host(i, send_alerts=False) for i in ids or
                        [r["id"] for r in db.q("SELECT id FROM hosts WHERE enabled=1")]]
            res = asyncio.run(run())
        else:
            res = asyncio.run(scanner.scan_all(host_ids=ids))
        for r in res:
            print(json.dumps(r))
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

        from . import patch
        from .web import finding_query
        args = dict(parse_qsl(a.filter))
        args.setdefault("status", "open")
        sql, params = finding_query(args)
        rows = db.q(sql, params)
        if a.host:
            rows = [r for r in rows if r["host_name"] in a.host]
        text, summary = patch.build_playbook([r["id"] for r in rows])
        if a.output:
            with open(a.output, "w") as fh:
                fh.write(text)
            print(f"wrote {a.output}: {summary}", file=sys.stderr)
        else:
            print(text)
    elif a.cmd == "repo-update":
        from . import repomgr
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


if __name__ == "__main__":
    main()
