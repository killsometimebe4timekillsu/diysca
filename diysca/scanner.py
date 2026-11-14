"""Scan orchestration: inventory -> hosts -> facts -> repos -> CVEs -> findings -> alerts."""
from __future__ import annotations

import asyncio
import logging

from . import db, notify
from .collectors import COLLECT_SCRIPT, HostFacts, parse_collect_output
from .containers import discover_containers, sync_container_hosts
from .langpkgs import lang_script, parse_lang_output
from .config import settings
from .correlate import correlate, correlate_lang
from .feeds import OSVClient, apply_enrichment, make_osv_client, nvd_enrich, osv_ecosystem, refresh_kev
from .inventory import load_inventory
from .repos import collect_repo_versions
from .transport import transport_for

log = logging.getLogger("diysca")
_scan_lock = asyncio.Lock()
running: set[int] = set()


def import_inventories(paths: list[str] | None = None) -> int:
    n = 0
    for path in paths or settings.inventories:
        try:
            hosts = load_inventory(path, settings.use_ansible_inventory_cli)
        except Exception as e:
            db.event("inventory", f"{path}: {e}")
            continue
        for h in hosts:
            db.x("""INSERT INTO hosts(name, address, port, ssh_user, key_file, connection, groups, source)
                    VALUES (?,?,?,?,?,?,?,?)
                    ON CONFLICT(name) DO UPDATE SET address=excluded.address, port=excluded.port,
                      ssh_user=excluded.ssh_user, key_file=excluded.key_file, connection=excluded.connection,
                      groups=excluded.groups, source=excluded.source""",
                 (h.name, h.address, h.port, h.user, h.key_file, h.connection, ",".join(sorted(h.groups)), path))
            n += 1
        db.event("inventory", f"imported {len(hosts)} hosts from {path}")
    return n


def store_results(host_id: int, facts: HostFacts, ecosystem: str | None, repo_versions, repo_status,
                  candidates, lang_pkgs=None, lang_candidates=None):
    """candidates / lang_candidates = None means "that feed failed": keep those findings as they are."""
    now = db.now()
    lang_pkgs = lang_pkgs or []
    with db.tx() as c:
        c.execute("""UPDATE hosts SET os_id=?, os_version=?, os_pretty=?, os_codename=?, arch=?, kernel=?,
                     ecosystem=?, pkg_type=?, last_scan=?, last_status='ok', last_error=NULL WHERE id=?""",
                  (facts.os_id, facts.os_version, facts.os_pretty, facts.os_codename, facts.arch, facts.kernel,
                   ecosystem, facts.pkg_type, now, host_id))
        c.execute("DELETE FROM packages WHERE host_id=?", (host_id,))
        rows = [(host_id, p.name, p.version, p.arch, p.source_name, p.source_version, p.type,
                 repo_versions.get(p.name), "", None) for p in facts.packages]
        rows += [(host_id, p.name, p.version, "", p.name, p.version, "lang", None, p.ecosystem,
                  ", ".join(p.locations[:5])) for p in lang_pkgs]
        c.executemany("""INSERT INTO packages(host_id,name,version,arch,source_name,source_version,type,repo_version,
                           ecosystem,location) VALUES (?,?,?,?,?,?,?,?,?,?)""", rows)
        c.execute("DELETE FROM repos WHERE host_id=?", (host_id,))
        c.executemany("""INSERT INTO repos(host_id,kind,url,suite,components,name,file,enabled,status,error,pkg_count,fetched_at)
                         VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                      [(host_id, r.kind, r.url, r.suite, " ".join(r.components), r.name, r.file, int(r.enabled),
                        st, err, cnt, now) for r, st, err, cnt in repo_status])
        evaluated, all_cands = set(), []
        if candidates is not None:
            evaluated.add("os")
            all_cands += candidates
        if lang_candidates is not None:
            evaluated.add("lang")
            all_cands += lang_candidates
        seen = set()
        for cd in all_cands:
            seen.add((cd.ecosystem, cd.package, cd.vuln_id))
            c.execute("""INSERT INTO findings(host_id,package,version,source_name,ecosystem,location,binaries,osv_ids,summary,
                           vuln_id,cve,fixed_version,repo_version,fix_in_repo,severity,cvss_score,status,first_seen,last_seen)
                         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'open',?,?)
                         ON CONFLICT(host_id,ecosystem,package,vuln_id) DO UPDATE SET
                           version=excluded.version, location=excluded.location, binaries=excluded.binaries,
                           osv_ids=excluded.osv_ids, summary=excluded.summary, fixed_version=excluded.fixed_version,
                           repo_version=excluded.repo_version, fix_in_repo=excluded.fix_in_repo,
                           severity=CASE WHEN excluded.severity='UNKNOWN' THEN findings.severity ELSE excluded.severity END,
                           cvss_score=COALESCE(excluded.cvss_score, findings.cvss_score),
                           status=CASE WHEN findings.status='ignored' THEN 'ignored' ELSE 'open' END,
                           resolved_at=NULL, last_seen=excluded.last_seen""",
                      (host_id, cd.package, cd.version, cd.package, cd.ecosystem, cd.location or None,
                       ",".join(cd.binaries), ",".join(cd.osv_ids), cd.summary[:500], cd.vuln_id,
                       cd.vuln_id if cd.vuln_id.startswith("CVE-") else None, cd.fixed_version, cd.repo_version,
                       int(cd.fix_in_repo), cd.severity, cd.cvss_score, now, now))
        for row in c.execute("SELECT id, ecosystem, package, vuln_id FROM findings WHERE host_id=? AND status='open'",
                             (host_id,)).fetchall():
            kind = "lang" if row["ecosystem"] else "os"
            if kind in evaluated and (row["ecosystem"], row["package"], row["vuln_id"]) not in seen:
                c.execute("UPDATE findings SET status='resolved', resolved_at=? WHERE id=?", (now, row["id"]))


async def scan_host(host_id: int, client: OSVClient | None = None, send_alerts: bool = True,
                    with_containers: bool = True) -> dict:
    h = db.q1("SELECT * FROM hosts WHERE id=?", (host_id,))
    if h is None:
        raise KeyError(host_id)
    running.add(host_id)
    own_client = client is None
    client = client or make_osv_client()
    problems: list[str] = []
    containers: list = []
    try:
        lang_pkgs = []
        async with transport_for(h) as t:
            facts = parse_collect_output(await t.run(COLLECT_SCRIPT))
            if not facts.packages:
                raise RuntimeError("no package manager database found (dpkg/rpm/apk)")
            repo_versions, repo_status = await collect_repo_versions(facts, t)
            if settings.scan_languages:
                paths = settings.lang_scan_paths if h["kind"] != "container" else settings.container_lang_scan_paths
                try:
                    lang_pkgs = parse_lang_output(await t.run(lang_script(paths), timeout=settings.lang_scan_timeout))
                except Exception as e:
                    problems.append(f"language package scan failed: {e}")
            if with_containers and settings.scan_containers and h["kind"] != "container":
                try:
                    containers = await discover_containers(t)
                except Exception as e:
                    problems.append(f"container discovery failed: {e}")
        eco = osv_ecosystem(facts.os_id, facts.os_version, facts.os_pretty)
        candidates = lang_candidates = None
        if eco is None:
            problems.append(f"OS '{facts.os_pretty or facts.os_id}' has no OSV ecosystem mapping yet")
        else:
            try:
                candidates = await correlate(facts, eco, client, repo_versions)
            except Exception as e:
                problems.append(f"vulnerability feed error: {e}")
        try:
            lang_candidates = await correlate_lang(lang_pkgs, client)
        except Exception as e:
            problems.append(f"vulnerability feed error (language packages): {e}")
        store_results(host_id, facts, eco, repo_versions, repo_status, candidates, lang_pkgs, lang_candidates)
        apply_enrichment()
        feed_err = "; ".join(problems) or None
        if feed_err:
            db.x("UPDATE hosts SET last_status='partial', last_error=? WHERE id=?", (feed_err[:1000], host_id))
        n_open = db.q1("SELECT COUNT(*) n FROM findings WHERE host_id=? AND status='open'", (host_id,))["n"]
        db.event("scan", f"{h['name']}: {len(facts.packages)} OS + {len(lang_pkgs)} language packages, "
                         f"{n_open} open findings" + (f" ({feed_err})" if feed_err else ""))
        sent = await notify.dispatch(host_id) if send_alerts else 0
        result = {"host": h["name"], "packages": len(facts.packages), "language_packages": len(lang_pkgs),
                  "open_findings": n_open, "alerts_sent": sent, "error": feed_err}
    except Exception as e:
        db.x("UPDATE hosts SET last_scan=?, last_status='error', last_error=? WHERE id=?",
             (db.now(), str(e)[:500], host_id))
        db.event("scan", f"{h['name']}: FAILED {e}")
        return {"host": h["name"], "error": str(e)}
    finally:
        running.discard(host_id)
        if own_client and not containers:
            await client.close()
    try:
        if with_containers and settings.scan_containers and h["kind"] != "container":
            child_ids = sync_container_hosts(h, containers)
            result["containers"] = [await scan_host(cid, client, send_alerts, with_containers=False)
                                    for cid in child_ids]
    finally:
        if own_client and containers:
            await client.close()
    return result


async def scan_all(client: OSVClient | None = None, host_ids: list[int] | None = None) -> list[dict]:
    async with _scan_lock:
        if settings.inventories:
            import_inventories()
        await refresh_kev()
        ids = host_ids or [r["id"] for r in db.q("SELECT id FROM hosts WHERE enabled=1")]
        sem = asyncio.Semaphore(settings.scan_concurrency)
        own = client is None
        client = client or make_osv_client()

        async def one(i):
            async with sem:
                return await scan_host(i, client)

        try:
            results = await asyncio.gather(*(one(i) for i in ids))
        finally:
            if own:
                await client.close()
        try:
            await nvd_enrich()
            await notify.dispatch()  # severities may have changed after enrichment
        except Exception as e:
            db.event("feed", f"NVD enrichment failed: {e}")
        return list(results)


async def scheduler():
    if settings.scan_interval_hours <= 0:
        return
    await asyncio.sleep(10)
    while True:
        try:
            await scan_all()
        except Exception as e:  # never let the loop die
            log.exception("scheduled scan failed")
            db.event("scan", f"scheduled scan failed: {e}")
        await asyncio.sleep(settings.scan_interval_hours * 3600)
