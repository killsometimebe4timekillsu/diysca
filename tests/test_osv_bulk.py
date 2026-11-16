"""OSV bulk mode: the maintained per-ecosystem exports, shared across releases, and a warning for stale data."""
import asyncio
import io
import json
import zipfile
from datetime import UTC, datetime, timedelta

import httpx

from diysca.core import db
from diysca.core.config import settings
from diysca.scanning import feeds


def _rec(vid, release, pkg="openssl", fixed="3.0.15-1", modified=None):
    return {"id": vid, "modified": modified or datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "affected": [{"package": {"ecosystem": f"Debian:{release}", "name": pkg},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]}


def _zip(recs) -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for r in recs:
            z.writestr(r["id"] + ".json", json.dumps(r))
    return b.getvalue()


def _events():
    return [r["message"] for r in db.q("SELECT message FROM events")]


def test_ecosystem_export_is_used_and_filtered_by_release(monkeypatch, tmp_path):
    seen = []

    def handler(req: httpx.Request):
        seen.append(req.url.path)
        if req.url.path == "/Debian/all.zip":
            return httpx.Response(200, content=_zip([_rec("DSA-1", 12), _rec("DSA-2", 13), _rec("DSA-3", 13, "curl")]),
                                  headers={"etag": '"v1"'})
        return httpx.Response(200, content=_zip([_rec("OLD-1", 12, modified="2024-10-04T14:58:33Z")]))
    monkeypatch.setattr(settings, "data_dir", str(tmp_path))
    c = feeds.BulkOSVClient("https://osv.example")
    c.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    async def go():
        n13 = await c.ensure("Debian:13")
        n12 = await c.ensure("Debian:12")
        return n13, n12
    n13, n12 = asyncio.run(go())
    assert seen == ["/Debian/all.zip"]  # one download for both releases, never the frozen Debian:12/all.zip
    assert (n13, n12) == (2, 1)
    assert {r["id"] for r in db.q("SELECT id FROM osv_bulk WHERE ecosystem='Debian:13'")} == {"DSA-2", "DSA-3"}
    assert not any("out of date" in e for e in _events())


def test_stale_export_is_reported(monkeypatch, tmp_path):
    old = (datetime.now(UTC) - timedelta(days=400)).isoformat().replace("+00:00", "Z")
    mirror = tmp_path / "mirror" / "Debian"
    mirror.mkdir(parents=True)
    (mirror / "all.zip").write_bytes(_zip([_rec("DSA-9", 12, modified=old)]))
    monkeypatch.setattr(settings, "data_dir", str(tmp_path / "data"))
    c = feeds.BulkOSVClient(f"file://{tmp_path / 'mirror'}")
    asyncio.run(c.ensure("Debian:12"))
    assert any("out of date" in e and "Debian:12" in e for e in _events())


def test_file_mirror_with_only_per_release_zips_still_works(monkeypatch, tmp_path):
    (tmp_path / "mirror" / "Debian:12").mkdir(parents=True)
    (tmp_path / "mirror" / "Debian:12" / "all.zip").write_bytes(_zip([_rec("DSA-5", 12)]))
    monkeypatch.setattr(settings, "data_dir", str(tmp_path / "data"))
    c = feeds.BulkOSVClient(f"file://{tmp_path / 'mirror'}")
    assert asyncio.run(c.ensure("Debian:12")) == 1


def test_unchanged_export_is_not_loaded_again(monkeypatch, tmp_path):
    calls = []

    def handler(req):
        calls.append(req.headers.get("if-none-match"))
        if req.headers.get("if-none-match") == '"v1"':
            return httpx.Response(304)
        return httpx.Response(200, content=_zip([_rec("DSA-1", 12)]), headers={"etag": '"v1"'})
    monkeypatch.setattr(settings, "data_dir", str(tmp_path))
    c = feeds.BulkOSVClient("https://osv.example")
    c.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    asyncio.run(c.ensure("Debian:12"))
    loads = len([e for e in _events() if "loaded" in e])
    asyncio.run(c.ensure("Debian:12", force=True))
    assert calls == [None, '"v1"']
    assert asyncio.run(c.query_ids([{"package": {"ecosystem": "Debian:12", "name": "openssl"}, "version": "3.0.11-1"}])) == [["DSA-1"]]
    assert len([e for e in _events() if "loaded" in e]) == loads + 1  # forced: loaded again


# ------------------------------------------------------------------ Ubuntu Pro (ESM)
class _Client:
    """OSV stand-in: records per ecosystem, matched by package name."""

    def __init__(self, recs):
        self.recs = recs

    async def query_ids(self, queries):
        return [[r["id"] for r in self.recs if any(a["package"] == q["package"] for a in r["affected"])]
                for q in queries]

    async def get_vuln(self, vid):
        return next(r for r in self.recs if r["id"] == vid)


def _u(vid, eco, pkg, fixed=None, cves=()):
    ev = [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else [])
    return {"id": vid, "upstream": list(cves), "affected": [{"package": {"ecosystem": eco, "name": pkg},
                                                             "ranges": [{"type": "ECOSYSTEM", "events": ev}]}]}


def test_universe_packages_fixed_only_in_ubuntu_pro_are_found(monkeypatch):
    from diysca.scanning.collectors import HostFacts, Package
    from diysca.scanning.correlate import PRO_NOTE, correlate
    facts = HostFacts(os_id="ubuntu", os_version="24.04", packages=[
        Package("imagemagick", "8:6.9.12.98+dfsg1-5.2build2", source_name="imagemagick"),
        Package("python3-pil", "10.2.0-1ubuntu1.3", source_name="pillow")])
    client = _Client([
        _u("UBUNTU-CVE-2026-28693", "Ubuntu:Pro:24.04:LTS", "imagemagick", "8:6.9.12.98+dfsg1-5.2ubuntu0.1~esm10",
           ["CVE-2026-28693"]),
        # the standard archive already speaks to this one: the Pro record must not add it again
        _u("UBUNTU-CVE-2026-1", "Ubuntu:24.04:LTS", "pillow", "10.2.0-1ubuntu1.5", ["CVE-2026-1"]),
        _u("UBUNTU-CVE-2026-1-pro", "Ubuntu:Pro:24.04:LTS", "pillow", "10.2.0-1ubuntu1.9", ["CVE-2026-1"])])
    got = {(c.package, c.vuln_id): c for c in asyncio.run(correlate(facts, "Ubuntu:24.04:LTS", client, {}))}
    im = got[("imagemagick", "CVE-2026-28693")]
    assert im.fixed_version.endswith("~esm10") and not im.fix_in_repo and im.summary.startswith(PRO_NOTE)
    assert got[("pillow", "CVE-2026-1")].fixed_version == "10.2.0-1ubuntu1.5"
    monkeypatch.setattr(settings, "ubuntu_pro_advisories", False)
    assert ("imagemagick", "CVE-2026-28693") not in {
        (c.package, c.vuln_id) for c in asyncio.run(correlate(facts, "Ubuntu:24.04:LTS", client, {}))}


def test_ubuntu_notice_names_only_cves_that_apply():
    from diysca.scanning.collectors import HostFacts, Package
    from diysca.scanning.correlate import correlate
    facts = HostFacts(os_id="ubuntu", os_version="24.04",
                      packages=[Package("python3-pil", "10.2.0-1ubuntu1.3", source_name="pillow")])
    eco = "Ubuntu:24.04:LTS"
    client = _Client([
        _u("UBUNTU-CVE-2026-42308", eco, "pillow", "10.2.0-1ubuntu1.2", ["CVE-2026-42308"]),  # fixed earlier
        _u("UBUNTU-CVE-2026-112396", eco, "pillow", "10.2.0-1ubuntu1.5", ["CVE-2026-112396"]),
        _u("USN-9064-1", eco, "pillow", "10.2.0-1ubuntu1.5", ["CVE-2026-42308", "CVE-2026-112396"]),
        _u("USN-9999-1", eco, "pillow", "10.2.0-1ubuntu1.6", ["CVE-2026-42308"])])  # only CVEs that don't apply
    got = {c.vuln_id: c for c in asyncio.run(correlate(facts, eco, client, {}))}
    assert set(got) == {"CVE-2026-112396", "USN-9999-1"}
    assert got["CVE-2026-112396"].osv_ids == ["UBUNTU-CVE-2026-112396", "USN-9064-1"]
