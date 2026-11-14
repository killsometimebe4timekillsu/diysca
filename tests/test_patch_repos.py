import asyncio
import json

import httpx
import yaml

from diysca.core import db
from diysca.core.config import settings
from diysca.mitigation import repomgr
from diysca.mitigation.patch import build_playbook


def _setup():
    h = db.x("INSERT INTO hosts(name,address,pkg_type,os_id) VALUES ('system_a','10.0.0.11','deb','debian')")
    db.x("""INSERT INTO packages(host_id,name,version,source_name,type,repo_version,ecosystem)
            VALUES (?,'libpq5','16.6-1','postgresql-16','deb','16.7-1',''),
                   (?,'postgresql-16','16.6-1','postgresql-16','deb','16.7-1','')""", (h, h))
    db.x("INSERT INTO repos(host_id,kind,url,suite) VALUES (?,'apt','http://aptly.local/debian','bookworm')", (h,))
    f1 = db.x("""INSERT INTO findings(host_id,package,version,ecosystem,binaries,vuln_id,fixed_version,repo_version,fix_in_repo,severity,status)
                 VALUES (?,'postgresql-16','16.6-1','','libpq5,postgresql-16','CVE-2025-1094','16.7-1','16.7-1',1,'HIGH','open')""", (h,))
    f2 = db.x("""INSERT INTO findings(host_id,package,version,ecosystem,binaries,vuln_id,fixed_version,repo_version,fix_in_repo,severity,status)
                 VALUES (?,'openssl','3.0.15-1','','libssl3','CVE-2099-1','3.0.16-1','3.0.15-1',0,'MEDIUM','open')""", (h,))
    f3 = db.x("""INSERT INTO findings(host_id,package,version,ecosystem,location,vuln_id,fixed_version,fix_in_repo,severity,status)
                 VALUES (?,'requests','2.20.0','PyPI','/srv/app/venv','CVE-2023-32681','2.31.0',0,'MEDIUM','open')""", (h,))
    return [f1, f2, f3]


def test_playbook():
    ids = _setup()
    text, summary = build_playbook(ids)
    assert summary == {"hosts": 1, "packages": 2, "manual": 2}
    assert "Fix released but not yet in your repos" in text and "openssl 3.0.15-1 -> 3.0.16-1" in text
    assert "PyPI requests 2.20.0 -> 2.31.0" in text
    plays = yaml.safe_load(text.split("\n---\n", 1)[1])
    assert plays[0]["hosts"] == "system_a"
    apt = plays[0]["tasks"][0]["ansible.builtin.apt"]
    assert apt["name"] == ["libpq5=16.7-1", "postgresql-16=16.7-1"] and apt["only_upgrade"] is True


def _mock(handler):
    calls = []

    def h(req: httpx.Request):
        calls.append((req.method, req.url.path, json.loads(req.content) if req.content else None))
        return handler(req)
    return httpx.MockTransport(h), calls


def test_aptly(monkeypatch):
    _setup()
    monkeypatch.setattr(settings, "repo_managers", [{"name": "aptly", "type": "aptly", "url": "http://aptly.local:8080",
                                                     "match": ["http://aptly.local/debian"],
                                                     "mirrors": [{"name": "bookworm-main", "component": "main"}],
                                                     "publish": {"prefix": "debian", "distribution": "bookworm"}}])
    assert [p["vuln_id"] for p in repomgr.pending_for(repomgr.get_manager("aptly"))] == ["CVE-2099-1"]
    t, calls = _mock(lambda r: httpx.Response(200, json={}))
    res = asyncio.run(repomgr.run("aptly", dry_run=False, transport=t))
    assert res.ok, res.steps
    assert [(m, p) for m, p, _ in calls] == [("PUT", "/api/mirrors/bookworm-main"),
                                             ("POST", "/api/mirrors/bookworm-main/snapshots"),
                                             ("PUT", "/api/publish/debian/bookworm")]
    assert calls[2][2]["Snapshots"][0]["Name"].startswith("bookworm-main-diysca-")
    t, calls = _mock(lambda r: httpx.Response(200, json={}))
    res = asyncio.run(repomgr.run("aptly", dry_run=True, transport=t))
    assert res.ok and [m for m, _, _ in calls] == ["GET"]


def test_pulp(monkeypatch):
    monkeypatch.setattr(settings, "repo_managers", [{"name": "pulp", "type": "pulp", "url": "https://pulp.local", "poll_seconds": 0,
                                                     "repositories": [{"type": "rpm", "name": "baseos", "distribution": "baseos"}]}])
    R = "/pulp/api/v3/repositories/rpm/rpm/1/"

    def handler(req):
        p = req.url.path
        if p == "/pulp/api/v3/repositories/rpm/rpm/":
            return httpx.Response(200, json={"results": [{"pulp_href": R, "remote": "/pulp/api/v3/remotes/rpm/rpm/9/"}]})
        if p == R + "sync/":
            return httpx.Response(202, json={"task": "/pulp/api/v3/tasks/1/"})
        if p == "/pulp/api/v3/tasks/1/":
            return httpx.Response(200, json={"state": "completed", "created_resources": [R + "versions/5/"]})
        if p == R:
            return httpx.Response(200, json={"latest_version_href": R + "versions/5/"})
        if p == "/pulp/api/v3/publications/rpm/rpm/":
            return httpx.Response(202, json={"task": "/pulp/api/v3/tasks/2/"})
        if p == "/pulp/api/v3/tasks/2/":
            return httpx.Response(200, json={"state": "completed", "created_resources": ["/pulp/api/v3/publications/rpm/rpm/7/"]})
        if p == "/pulp/api/v3/distributions/rpm/rpm/":
            return httpx.Response(200, json={"results": [{"pulp_href": "/pulp/api/v3/distributions/rpm/rpm/3/"}]})
        if p == "/pulp/api/v3/distributions/rpm/rpm/3/":
            return httpx.Response(202, json={"task": "/pulp/api/v3/tasks/3/"})
        if p == "/pulp/api/v3/tasks/3/":
            return httpx.Response(200, json={"state": "completed"})
        return httpx.Response(404, json={})
    t, calls = _mock(handler)
    res = asyncio.run(repomgr.run("pulp", dry_run=False, transport=t))
    assert res.ok, [(s.action, s.detail, s.info) for s in res.steps]
    assert ("PATCH", "/pulp/api/v3/distributions/rpm/rpm/3/", {"publication": "/pulp/api/v3/publications/rpm/rpm/7/"}) in calls
    assert ("POST", "/pulp/api/v3/publications/rpm/rpm/", {"repository_version": R + "versions/5/"}) in calls


def test_foreman(monkeypatch):
    monkeypatch.setattr(settings, "repo_managers", [{"name": "sat", "type": "foreman", "url": "https://foreman.local",
                                                     "username": "admin", "password_env": "FM_PW", "poll_seconds": 0,
                                                     "organization": "ACME", "repositories": ["BaseOS"],
                                                     "content_view": "CV-Base", "promote_to": ["Test", "Prod"]}])
    monkeypatch.setenv("FM_PW", "secret")

    def handler(req):
        p = req.url.path
        assert req.headers["authorization"].startswith("Basic ")
        if p == "/katello/api/organizations":
            return httpx.Response(200, json={"results": [{"id": 1, "name": "ACME"}]})
        if p == "/katello/api/repositories":
            return httpx.Response(200, json={"results": [{"id": 11, "name": "BaseOS"}]})
        if p == "/katello/api/repositories/11/sync":
            return httpx.Response(202, json={"id": "t1"})
        if p == "/katello/api/content_views":
            return httpx.Response(200, json={"results": [{"id": 5, "name": "CV-Base"}]})
        if p == "/katello/api/content_views/5/publish":
            return httpx.Response(202, json={"id": "t2"})
        if p == "/katello/api/content_views/5":
            return httpx.Response(200, json={"versions": [{"id": 50, "version": "3.0"}, {"id": 51, "version": "4.0"}]})
        if p == "/katello/api/organizations/1/environments":
            return httpx.Response(200, json={"results": [{"id": 2, "name": "Test"}, {"id": 3, "name": "Prod"}]})
        if p == "/katello/api/content_view_versions/51/promote":
            return httpx.Response(202, json={"id": "t3"})
        if p.startswith("/foreman_tasks/api/tasks/"):
            return httpx.Response(200, json={"state": "stopped", "result": "success"})
        return httpx.Response(404, json={})
    t, calls = _mock(handler)
    res = asyncio.run(repomgr.run("sat", dry_run=False, stages=["Test"], transport=t))
    assert res.ok, [(s.action, s.detail) for s in res.steps]
    assert ("POST", "/katello/api/content_view_versions/51/promote", {"environment_ids": [2], "force": False}) in calls
    assert not any(c[1].endswith("/promote") and c[2]["environment_ids"] == [3] for c in calls)
