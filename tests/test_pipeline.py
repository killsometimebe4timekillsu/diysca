"""End-to-end: fake host + fake OSV -> findings -> SBOM -> alerts -> web UI."""
import asyncio
import json

import pytest
from fastapi.testclient import TestClient

from diysca import db, notify, scanner
from diysca.collectors import SEP
from diysca.correlate import evaluate
from diysca.feeds import cvss3_base_score, osv_ecosystem, vuln_severity
from diysca.sbom import build_sbom

HOST_OUTPUT = (
    f"{SEP}os-release\nID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n"
    f"{SEP}hostname\nsystem_a\n{SEP}arch\nx86_64\n{SEP}kernel\n6.1.0\n{SEP}dpkg-arch\namd64\n"
    f"{SEP}dpkg\npostgresql-16\t16.6-1~deb12u1\tamd64\t\tinstalled\n"
    "libpq5\t16.6-1~deb12u1\tamd64\tpostgresql-16\tinstalled\n"
    "bash\t5.2.15-2+b7\tamd64\tbash (5.2.15-2)\tinstalled\n"
    f"{SEP}apt-sources\ndeb http://mirror.local/debian bookworm main\n{SEP}end\n"
)

VULNS = {
    "DSA-5850-1": {
        "id": "DSA-5850-1", "summary": "postgresql-16 security update", "upstream": ["CVE-2025-1094"],
        "affected": [{"package": {"name": "postgresql-16", "ecosystem": "Debian:12"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "16.7-0+deb12u1"}]}]}],
    },
    "DEBIAN-CVE-2025-1094": {
        "id": "DEBIAN-CVE-2025-1094", "upstream": ["CVE-2025-1094"],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [{"package": {"name": "postgresql-16", "ecosystem": "Debian:12"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "16.7-0+deb12u1"}]}]}],
    },
    "DEBIAN-CVE-2099-0001": {  # unfixed
        "id": "DEBIAN-CVE-2099-0001", "upstream": ["CVE-2099-0001"],
        "affected": [{"package": {"name": "bash", "ecosystem": "Debian:12"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}],
    },
    "DEBIAN-CVE-2000-0001": {  # already fixed: must not match
        "id": "DEBIAN-CVE-2000-0001",
        "affected": [{"package": {"name": "bash", "ecosystem": "Debian:12"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.0-1"}]}]}],
    },
}


class FakeOSV:
    """Returns every vuln for the package; local range evaluation must filter."""

    async def query_ids(self, queries):
        return [[vid for vid, v in VULNS.items()
                 if any(a["package"]["name"] == q["package"]["name"] for a in v["affected"])] for q in queries]

    async def get_vuln(self, vid):
        return VULNS[vid]

    async def close(self):
        pass


class FakeTransport:
    async def run(self, cmd, binary=False, timeout=300):
        return HOST_OUTPUT

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        pass


@pytest.fixture
def scanned(monkeypatch):
    monkeypatch.setattr(scanner, "transport_for", lambda h: FakeTransport())

    async def fake_repo_versions(facts, t):
        return {"postgresql-16": "16.7-0+deb12u1", "libpq5": "16.7-0+deb12u1", "bash": "5.2.15-2+b7"}, []

    monkeypatch.setattr(scanner, "collect_repo_versions", fake_repo_versions)
    sent = []

    async def fake_send(ch, title, body, severity="MEDIUM"):
        sent.append((ch["url"], title, body))
        return True, ""

    monkeypatch.setattr(notify, "send_to_channel", fake_send)
    db.x("INSERT INTO hosts(name,address,groups) VALUES ('system_a','10.0.0.11','db,prod')")
    cid = db.x("INSERT INTO channels(name,url) VALUES ('ntfy','ntfy://ntfy.sh/test')")
    db.x("INSERT INTO subscriptions(name,channel_id,host_pattern,package_pattern,min_severity) "
         "VALUES ('pg', ?, 'group:prod', 'postgres*', 'MEDIUM')", (cid,))
    res = asyncio.run(scanner.scan_host(1, client=FakeOSV()))
    return res, sent


def test_scan_correlates(scanned):
    res, sent = scanned
    assert res["packages"] == 3 and res["error"] is None
    f = {r["vuln_id"]: r for r in db.q("SELECT * FROM findings WHERE status='open'")}
    assert set(f) == {"CVE-2025-1094", "CVE-2099-0001"}
    pg = f["CVE-2025-1094"]
    assert pg["package"] == "postgresql-16" and pg["binaries"] == "libpq5,postgresql-16"
    assert pg["fixed_version"] == "16.7-0+deb12u1" and pg["fix_in_repo"] == 1
    assert pg["severity"] == "HIGH" and pg["cvss_score"] == 8.1
    assert set(pg["osv_ids"].split(",")) == {"DSA-5850-1", "DEBIAN-CVE-2025-1094"}
    assert f["CVE-2099-0001"]["fixed_version"] is None


def test_alert_sent_once(scanned):
    _, sent = scanned
    assert len(sent) == 1
    url, title, body = sent[0]
    assert "CVE-2025-1094  postgresql-16 16.6-1~deb12u1" in body
    assert "is in your repos: patch it, or approve it for mitigation" in body
    assert "/findings/" in body and "Approve for mitigation:" in body
    assert "CVE-2025-1094" in title and "system_a" in title
    assert asyncio.run(notify.dispatch()) == 0  # dedup


def test_resolved_after_upgrade(scanned):
    global HOST_OUTPUT
    old = HOST_OUTPUT
    HOST_OUTPUT = old.replace("16.6-1~deb12u1", "16.7-0+deb12u1")
    try:
        asyncio.run(scanner.scan_host(1, client=FakeOSV()))
    finally:
        HOST_OUTPUT = old
    st = {r["vuln_id"]: r["status"] for r in db.q("SELECT * FROM findings")}
    assert st == {"CVE-2025-1094": "resolved", "CVE-2099-0001": "open"}


def test_sbom(scanned):
    s = build_sbom(1)
    assert s["bomFormat"] == "CycloneDX" and s["specVersion"] == "1.5"
    purls = [c["purl"] for c in s["components"]]
    assert "pkg:deb/debian/libpq5@16.6-1~deb12u1?arch=amd64&distro=debian-12" in purls
    v = {x["id"]: x for x in s["vulnerabilities"]}
    assert len(v["CVE-2025-1094"]["affects"]) == 2


def test_web_pages(scanned):
    from diysca.web import app
    with TestClient(app) as c:
        for url in ["/", "/systems", "/systems/1", "/packages?name=postgres", "/findings", "/findings?fix=repo&severity=HIGH",
                    "/findings/1", "/alerts", "/healthz"]:
            r = c.get(url)
            assert r.status_code == 200, url
        assert "CVE-2025-1094" in c.get("/findings?package=postgres").text
        assert "CVE-2025-1094" not in c.get("/findings?package=bash").text
        assert len(c.get("/api/findings?group=prod").json()) == 2
        assert json.loads(c.get("/systems/1/sbom.json").text)["metadata"]["component"]["name"] == "system_a"
        r = c.post("/filters", data={"name": "pg prod", "page": "findings", "query": "package=postgres"}, follow_redirects=False)
        assert r.status_code == 303
        assert "pg prod" in c.get("/findings").text


def test_subscription_matching():
    host = {"name": "system_a", "address": "10.0.0.11", "groups": "db,prod"}
    f = {"package": "postgresql-16", "binaries": "libpq5,postgresql-16", "severity": "HIGH", "kev": 0, "fix_in_repo": 1}
    base = {"enabled": 1, "host_pattern": "*", "package_pattern": "*", "min_severity": "LOW", "only_kev": 0, "only_fixable": 0}
    assert notify.matches(base, f, host)
    assert notify.matches({**base, "package_pattern": "libpq*"}, f, host)
    assert not notify.matches({**base, "package_pattern": "openssl"}, f, host)
    assert not notify.matches({**base, "host_pattern": "*,!system_*"}, f, host)
    assert notify.matches({**base, "host_pattern": "group:db"}, f, host)
    assert not notify.matches({**base, "host_pattern": "group:web"}, f, host)
    assert not notify.matches({**base, "min_severity": "CRITICAL"}, f, host)
    assert not notify.matches({**base, "only_kev": 1}, f, host)


def test_evaluate_ranges():
    aff = {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "1.5"}, {"introduced": "2.0"}, {"last_affected": "2.2"}]}]}
    assert evaluate(aff, "1.2", "deb") == (True, "1.5")
    assert evaluate(aff, "1.6", "deb") == (False, None)
    assert evaluate(aff, "2.1", "deb")[0] is True
    assert evaluate(aff, "2.3", "deb")[0] is False
    assert evaluate({"versions": ["3.0"]}, "3.0", "deb")[0] is True


def test_cvss_and_ecosystems():
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N") == 6.4
    assert vuln_severity({"severity": [{"type": "Ubuntu", "score": "high"}]})[1] == "HIGH"
    assert osv_ecosystem("ubuntu", "24.04") == "Ubuntu:24.04:LTS"
    assert osv_ecosystem("ubuntu", "24.10") == "Ubuntu:24.10"
    assert osv_ecosystem("alpine", "3.20.3") == "Alpine:v3.20"
    assert osv_ecosystem("rocky", "9.4") == "Rocky Linux:9"
    assert osv_ecosystem("debian", "12") == "Debian:12"
