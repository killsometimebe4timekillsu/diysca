"""Extra CVE sources and the Patched CVEs view."""
import asyncio
import gzip
import io
import json
import zipfile
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from diysca.core import db
from diysca.core.config import settings
from diysca.mitigation import patched
from diysca.scanning import scanner, sources

from . import test_pipeline as tp
from .test_pipeline import (  # noqa: F401  (fixtures share the fake host)
    FakeOSV,
    FakeTransport,
)

TRACKER = {
    "bash": {
        "CVE-2031-0001": {"description": "bash: unfixed bug", "releases": {
            "bookworm": {"status": "open", "urgency": "medium"}}},
        "CVE-2031-0002": {"releases": {"bookworm": {"status": "open", "urgency": "unimportant"}}},
        "CVE-2031-0003": {"releases": {"bookworm": {"status": "resolved", "fixed_version": "0", "urgency": "low"}}},
        "CVE-2031-0004": {"releases": {"bookworm": {"status": "resolved", "fixed_version": "5.0-1", "urgency": "high"}}},
    },
    "postgresql-16": {
        "CVE-2025-1094": {"releases": {"bookworm": {"status": "resolved", "fixed_version": "16.7-0+deb12u1",
                                                     "urgency": "high"}}},
    },
}


def _write(tmp_path, name, data: bytes) -> str:
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def _add(name, typ, **cfg):
    db.x("INSERT INTO feed_sources(name,type,config,origin) VALUES (?,?,?,'config')", (name, typ, json.dumps(cfg)))
    return asyncio.run(sources.refresh(name))


def test_debian_tracker_conversion(tmp_path):
    res = _add("debian-tracker", "debian-tracker", path=_write(tmp_path, "t.json", json.dumps(TRACKER).encode()),
               releases=["bookworm"])
    assert res["count"] == 3  # unimportant and not-affected are skipped
    ids = {r["id"] for r in db.q("SELECT id FROM advisories")}
    assert ids == {"debian-tracker/CVE-2031-0001", "debian-tracker/CVE-2031-0004", "debian-tracker/CVE-2025-1094"}


def test_extra_source_adds_findings(tmp_path, monkeypatch):
    _add("debian-tracker", "debian-tracker", path=_write(tmp_path, "t.json", json.dumps(TRACKER).encode()),
         releases=["bookworm"])
    monkeypatch.setattr(scanner, "transport_for", lambda h: tp.FakeTransport())

    async def fake_repo_versions(facts, t):
        return {"postgresql-16": "16.7-0+deb12u1"}, []
    monkeypatch.setattr(scanner, "collect_repo_versions", fake_repo_versions)
    db.x("INSERT INTO hosts(name,address) VALUES ('system_a','10.0.0.11')")
    client = sources.MultiClient(tp.FakeOSV(), sources.SourcesClient())
    asyncio.run(scanner.scan_host(1, client=client, send_alerts=False))
    f = {r["vuln_id"]: r for r in db.q("SELECT * FROM findings WHERE status='open'")}
    assert "CVE-2031-0001" in f and f["CVE-2031-0001"]["severity"] == "MEDIUM"  # from the tracker only
    assert "CVE-2031-0004" not in f  # fixed before the installed version
    pg = f["CVE-2025-1094"]  # reported by OSV and by the tracker: one finding, both advisories
    assert set(pg["osv_ids"].split(",")) == {"DSA-5850-1", "DEBIAN-CVE-2025-1094", "debian-tracker/CVE-2025-1094"}


def test_alpine_secdb(tmp_path):
    secdb = {"distroversion": "v3.20", "packages": [{"pkg": {"name": "busybox", "secfixes": {
        "1.36.1-r31": ["CVE-2023-42366 ALPINE-13661"], "0": ["CVE-2021-0000"]}}}]}
    _add("alpine", "alpine-secdb", path=_write(tmp_path, "main.json", json.dumps(secdb).encode()))
    ids = asyncio.run(sources.SourcesClient().query_ids([
        {"package": {"name": "busybox", "ecosystem": "Alpine:v3.20"}, "version": "1.36.1-r29"},
        {"package": {"name": "busybox", "ecosystem": "Alpine:v3.20"}, "version": "1.36.1-r31"}]))
    assert ids == [["alpine/CVE-2023-42366"], []]


def test_osv_zip_with_ecosystem_filter(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.json", json.dumps({"id": "GHSA-1", "aliases": ["CVE-2030-1"], "affected": [
            {"package": {"ecosystem": "PyPI", "name": "Requests"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.32.0"}]}]}]}))
        z.writestr("b.json", json.dumps({"id": "GHSA-2", "affected": [
            {"package": {"ecosystem": "npm", "name": "x"}, "versions": ["1.0.0"]}]}))
    _add("ghsa", "osv", path=_write(tmp_path, "g.zip", buf.getvalue()), ecosystems=["PyPI"])
    ids = asyncio.run(sources.SourcesClient().query_ids([
        {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.31.0"},
        {"package": {"name": "x", "ecosystem": "npm"}, "version": "1.0.0"}]))
    assert ids == [["ghsa/GHSA-1"], []]


def test_custom_csv_and_json(tmp_path):
    csv_text = "advisory,pkg,fixed_in,score,cves\nACME-1,openssl,3.0.16-1~deb12u1,7.5,CVE-2030-7\n"
    _add("acme-csv", "custom", path=_write(tmp_path, "a.csv", csv_text.encode()),
         fields={"id": "advisory", "package": "pkg", "fixed": "fixed_in", "cvss": "score", "aliases": "cves"},
         defaults={"ecosystem": "Debian:12"})
    v = asyncio.run(sources.SourcesClient().get_vuln("acme-csv/ACME-1"))
    from diysca.scanning.feeds import vuln_cves, vuln_severity
    assert vuln_cves(v) == ["CVE-2030-7"] and vuln_severity(v)[:2] == (7.5, "HIGH")
    doc = {"data": {"items": [{"id": "V-9", "product": {"name": "left-pad", "eco": "npm"}, "affected": ["1.0.0", "1.0.1"],
                               "sev": "critical"}]}}
    _add("vendor", "custom", path=_write(tmp_path, "v.json", json.dumps(doc).encode()), records="data.items",
         fields={"id": "id", "package": "product.name", "ecosystem": "product.eco", "versions": "affected", "severity": "sev"})
    c = sources.SourcesClient()
    ids = asyncio.run(c.query_ids([{"package": {"name": "left-pad", "ecosystem": "npm"}, "version": "1.0.1"},
                                   {"package": {"name": "left-pad", "ecosystem": "npm"}, "version": "1.0.2"}]))
    assert ids == [["vendor/V-9"], []]
    assert vuln_severity(asyncio.run(c.get_vuln("vendor/V-9")))[1] == "CRITICAL"


def test_epss(tmp_path):
    data = gzip.compress(b"#model_version:v2025.03.14,score_date:2025-07-01\ncve,epss,percentile\nCVE-2025-1094,0.81,0.99\n")
    res = _add("epss", "epss", path=_write(tmp_path, "e.csv.gz", data))
    assert res["count"] == 1
    db.x("INSERT INTO hosts(name) VALUES ('a')")
    db.x("INSERT INTO findings(host_id,package,version,vuln_id,cve,status) VALUES (1,'p','1','CVE-2025-1094','CVE-2025-1094','open')")
    from diysca.scanning.feeds import apply_enrichment
    apply_enrichment()
    assert db.q1("SELECT epss FROM findings")["epss"] == pytest.approx(0.81)


def test_config_sources_sync_and_ui_rules(monkeypatch):
    monkeypatch.setattr(settings, "sources", [{"name": "deb", "type": "debian-tracker", "refresh_hours": 6}])
    sources.sync_config_sources()
    assert sources.get("deb")["origin"] == "config"
    with pytest.raises(ValueError):
        sources.save("deb", "osv", {"url": "https://x"})  # owned by config.yml
    with pytest.raises(ValueError):
        sources.save("local", "osv", {"path": "/etc"})  # UI sources must be URLs
    with pytest.raises(ValueError):
        sources.save("bad", "custom", {"url": "https://x", "fields": {"package": "p"}})
    sources.save("ok", "osv", {"url": "https://example.net/a.zip", "headers": {"Authorization": "secret"}})
    assert sources.public(sources.get("ok"))["cfg"]["headers"] == {"Authorization": "***"}
    monkeypatch.setattr(settings, "sources", [])
    sources.sync_config_sources()
    assert sources.get("deb") is None and sources.get("ok") is not None


def _resolved(host, pkg, cve, sev, at, first, how="upgraded"):
    return db.x("""INSERT INTO findings(host_id,package,version,vuln_id,cve,severity,status,first_seen,resolved_at,
                   resolved_version,resolution) VALUES (?,?,?,?,?,?,'resolved',?,?,?,?)""",
                (host, pkg, "1.0", cve, cve, sev, first, at, "1.1", how))


def test_patched_ranges():
    now = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)
    iso = lambda d: d.replace(microsecond=0).isoformat()
    db.x("INSERT INTO hosts(name, groups) VALUES ('a','db'),('b','web')")
    _resolved(1, "openssl", "CVE-1", "HIGH", iso(now - timedelta(days=20)), iso(now - timedelta(days=30)))
    _resolved(1, "bash", "CVE-2", "LOW", iso(now - timedelta(hours=2)), iso(now - timedelta(days=4)))
    _resolved(2, "curl", "CVE-3", "CRITICAL", iso(now - timedelta(days=3)), iso(now - timedelta(days=5)), "removed")
    db.patch_run("playbook", "playbook generated: 1 hosts")
    assert patched.query({"range": "24h"}, now)["stats"]["cves"] == 1
    d = patched.query({"range": "7d"}, now)
    assert {r["vuln_id"] for r in d["rows"]} == {"CVE-2", "CVE-3"}
    assert d["stats"]["critical_high"] == 1 and d["stats"]["removed"] == 1
    last = patched.query({"range": "last"}, now)  # latest batch per system
    assert {r["vuln_id"] for r in last["rows"]} == {"CVE-2", "CVE-3"}
    assert patched.query({"range": "30d", "severity": "HIGH"}, now)["stats"]["cves"] == 2
    assert patched.query({"range": "30d", "group": "db"}, now)["stats"]["cves"] == 2
    c = patched.query({"range": "custom", "from": "2026-10-25", "to": "2026-10-25"}, now)
    assert [r["vuln_id"] for r in c["rows"]] == ["CVE-1"] and c["stats"]["median_days"] == 10.0
    # "still open" follows the system filters, like every other number
    db.x("INSERT INTO findings(host_id,package,version,vuln_id,severity,status,first_seen) VALUES "
         "(1,'zlib','1','CVE-8','HIGH','open','x'),(2,'zlib','1','CVE-8','LOW','open','x'),(2,'xz','1','CVE-9','LOW','open','x')")
    assert patched.query({"range": "30d"}, now)["stats"]["open_now"] == 3
    assert patched.query({"range": "30d", "host": "a"}, now)["stats"]["open_now"] == 1
    assert patched.query({"range": "30d", "group": "web"}, now)["stats"]["open_now"] == 2
    assert patched.query({"range": "30d", "severity": "HIGH"}, now)["stats"]["open_now"] == 1
    assert "<svg" in d["chart"] and "bar HIGH" not in d["chart"] and "bar CRITICAL" in d["chart"]


def test_resolution_recorded(monkeypatch):
    monkeypatch.setattr(scanner, "transport_for", lambda h: tp.FakeTransport())

    async def fake_repo_versions(facts, t):
        return {}, []
    monkeypatch.setattr(scanner, "collect_repo_versions", fake_repo_versions)
    db.x("INSERT INTO hosts(name,address) VALUES ('system_a','10.0.0.11')")
    asyncio.run(scanner.scan_host(1, client=tp.FakeOSV(), send_alerts=False))
    old = tp.HOST_OUTPUT
    tp.HOST_OUTPUT = old.replace("16.6-1~deb12u1", "16.7-0+deb12u1")
    try:
        asyncio.run(scanner.scan_host(1, client=tp.FakeOSV(), send_alerts=False))
    finally:
        tp.HOST_OUTPUT = old
    f = db.q1("SELECT * FROM findings WHERE vuln_id='CVE-2025-1094'")
    assert f["status"] == "resolved" and f["resolution"] == "upgraded" and f["resolved_version"] == "16.7-0+deb12u1"


def test_pages(monkeypatch):
    from diysca.web import app
    db.x("INSERT INTO hosts(name) VALUES ('a')")
    _resolved(1, "openssl", "CVE-1", "HIGH", db.now(), db.now())
    with TestClient(app) as c:
        for url in ["/patched", "/patched?range=24h", "/patched?range=custom&from=2026-01-01&to=2026-12-31",
                    "/patched?range=bogus", "/sources", "/api/patched?range=7d", "/api/sources", "/"]:
            assert c.get(url).status_code == 200, url
        assert "CVE-1" in c.get("/patched?range=24h").text
        r = c.post("/settings/sources", data={"name": "Bad Name", "type": "osv", "url": "https://x"}, follow_redirects=False)
        assert r.status_code == 303 and "err=" in r.headers["location"]
