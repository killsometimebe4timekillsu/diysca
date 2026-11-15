"""Settings import/export and reprovisioning from an SBOM."""
import asyncio
import json

import yaml
from fastapi.testclient import TestClient

from diysca.core import db, settings_io
from diysca.mitigation import reprovision
from diysca.scanning import scanner, sources

from . import test_pipeline as tp


def _scan(monkeypatch):
    monkeypatch.setattr(scanner, "transport_for", lambda h: tp.FakeTransport())

    async def fake_repo_versions(facts, t):
        return {"postgresql-16": "16.7-0+deb12u1", "libpq5": "16.7-0+deb12u1", "bash": "5.2.15-2+b7"}, []
    monkeypatch.setattr(scanner, "collect_repo_versions", fake_repo_versions)
    db.x("INSERT INTO hosts(name,address,groups) VALUES ('system_a','10.0.0.11','db')")
    asyncio.run(scanner.scan_host(1, client=tp.FakeOSV(), send_alerts=False))
    db.x("INSERT INTO repos(host_id,kind,url,suite,components,enabled) VALUES (1,'apt','http://mirror.local/debian','bookworm','main',1)")
    db.x("INSERT INTO packages(host_id,name,version,type,ecosystem,location) VALUES "
         "(1,'requests','2.31.0','lang','PyPI','/opt/app/venv/lib/python3.12/site-packages'),"
         "(1,'express','4.18.2','lang','npm','/srv/shop/package-lock.json')")
    db.x("INSERT INTO hosts(name,kind,parent_id,container_runtime,image) VALUES ('system_a/web','container',1,'podman','docker.io/library/nginx:1.27')")


def test_reprovision_from_host(monkeypatch):
    _scan(monkeypatch)
    text, summary = reprovision.for_host(1)
    assert summary == {"system": "system_a", "packages": 3, "bumped": 2, "lang": 1, "manual": 1, "images": 1, "repos": 1}
    play = yaml.safe_load(text.split("\n---\n", 1)[1])[0]
    names = [t["name"] for t in play["tasks"]]
    assert names[0].startswith("Target must run") and "Repository http://mirror.local/debian" in names
    apt = next(t for t in play["tasks"] if "allow_downgrade" in t.get("ansible.builtin.apt", {}))["ansible.builtin.apt"]
    assert "postgresql-16=16.7-0+deb12u1" in apt["name"] and "bash=5.2.15-2+b7" in apt["name"]
    pip = next(t for t in play["tasks"] if "ansible.builtin.pip" in t)["ansible.builtin.pip"]
    assert pip["virtualenv"] == "/opt/app/venv" and pip["name"] == ["requests==2.31.0"]
    assert any("pull" in str(t) and "nginx:1.27" in str(t) for t in play["tasks"])
    assert "npm express 4.18.2" in text
    exact, s2 = reprovision.for_host(1, mode="exact", target="newbox")
    assert s2["bumped"] == 0 and "postgresql-16=16.6-1~deb12u1" in exact and "hosts: newbox" in exact


def test_reprovision_foreign_sbom():
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": {"name": "box", "version": "9.4"}},
            "components": [{"type": "library", "purl": "pkg:rpm/rocky/openssl-libs@1:3.0.7-27.el9?arch=x86_64&distro=rocky-9.4"},
                           {"type": "library", "purl": "pkg:rpm/rocky/gpg-pubkey@350d275d-6279464b"},
                           {"type": "library", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"}]}
    text, s = reprovision.build(sbom)
    assert s["packages"] == 1 and "openssl-libs-3.0.7-27.el9.x86_64" in text and "ansible.builtin.dnf" in text
    assert "distribution_major_version'] == '9'" in text and "log4j-core" in text
    import pytest
    with pytest.raises(ValueError):
        reprovision.build({"bomFormat": "SPDX"})


def test_settings_roundtrip():
    sources.save("vendor", "osv", {"url": "https://x.example/a.zip", "headers": {"Authorization": "Bearer s3cret"}})
    db.x("INSERT INTO channels(name,url) VALUES ('ntfy','ntfys://user:pw@ntfy.example/topic')")
    db.x("INSERT INTO subscriptions(name,channel_id,package_pattern,min_severity) VALUES ('pg',1,'postgres*','HIGH')")
    db.x("INSERT INTO saved_filters(name,page,query) VALUES ('kev','findings','kev=1')")
    masked = settings_io.export_yaml()
    assert "s3cret" not in masked and "pw@" not in masked and "Bearer" not in masked
    assert "s3cret" in settings_io.export_yaml(include_secrets=True)
    data = yaml.safe_load(masked)
    data["subscriptions"][0]["min_severity"] = "critical"
    data["channels"].append({"name": "mail", "url": "mailtos://a:b@smtp.example?to=x@example.net"})
    res = settings_io.import_bundle(data, dry_run=True)
    assert res["added"] == 1 and res["errors"] == [] and db.q1("SELECT COUNT(*) n FROM channels")["n"] == 1
    settings_io.import_bundle(data)
    assert db.q1("SELECT url FROM channels WHERE name='ntfy'")["url"] == "ntfys://user:pw@ntfy.example/topic"
    assert sources.get("vendor")["cfg"]["headers"]["Authorization"] == "Bearer s3cret"
    assert db.q1("SELECT min_severity FROM subscriptions")["min_severity"] == "CRITICAL"
    bad = settings_io.import_bundle({"subscriptions": [{"name": "x", "channel": "nope"}]})
    assert bad["errors"] and db.q1("SELECT COUNT(*) n FROM subscriptions")["n"] == 1
    res = settings_io.import_bundle({"channels": [{"name": "mail", "url": "json://h/x"}]}, replace=True)
    assert res["removed"] == 1 and [r["name"] for r in db.q("SELECT name FROM channels")] == ["mail"]
    assert db.q1("SELECT COUNT(*) n FROM subscriptions")["n"] == 0  # cascade with its channel
    assert settings_io.parse("- name: a\n  type: epss\n") == {"sources": [{"name": "a", "type": "epss"}]}


def test_settings_pages(monkeypatch):
    _scan(monkeypatch)
    from diysca.web import app
    with TestClient(app) as c:
        for url in ["/settings", "/settings/sources", "/settings/notifications", "/settings/repos", "/settings/backup",
                    "/alerts", "/sources", "/settings/export.yml?parts=channels", "/systems/1/reprovision.yml"]:
            assert c.get(url).status_code == 200, url
        r = c.post("/settings/import", data={"text": "channels:\n  - name: n\n    url: ntfy://h/t\n", "dry_run": "1"})
        assert "Preview" in r.text and db.q1("SELECT COUNT(*) n FROM channels")["n"] == 0
        r = c.post("/settings/import", files={"file": ("s.yml", b"channels:\n  - name: n\n    url: ntfy://h/t\n")})
        assert "Imported" in r.text and db.q1("SELECT COUNT(*) n FROM channels")["n"] == 1
        sb = c.get("/systems/1/sbom.json").content
        r = c.post("/reprovision", files={"file": ("a.cdx.json", sb)}, data={"mode": "exact"})
        assert r.status_code == 200 and "reprovision system_a" in r.text
        r = c.post("/reprovision", files={"file": ("x.json", json.dumps({"a": 1}).encode())})
        assert "Not a CycloneDX SBOM" in r.text
