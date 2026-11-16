"""Findings of the stability, usability and security review of 0.2.3 (2026-11-16)."""
import asyncio

import pytest
import yaml
from fastapi.testclient import TestClient

from diysca.core import config, db, scope
from diysca.core.config import settings
from diysca.mitigation import mitigate, patch, pbsafe
from diysca.scanning import scanner
from diysca.scanning import transport as tp

from .test_mitigation_mcp import _open_ids
from .test_settings_reprovision import _scan


def _client(monkeypatch):
    monkeypatch.setattr(settings, "allow_no_login", True)
    from diysca.web import app
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------- wrong-system risks
@pytest.mark.parametrize("name", ["all", "ALL", "ungrouped", "web*", "a,b", "a:b", "!web1", "&db", "web 1", "", "-x",
                                  "~regex", "web[1:3]", "x" * 300])
def test_odd_system_names_are_not_play_targets(name):
    assert not pbsafe.host_ok(name)


@pytest.mark.parametrize("name", ["web1", "db-01.example.org", "10.0.0.11", "system_a", "WEB1"])
def test_normal_system_names_are_play_targets(name):
    assert pbsafe.host_ok(name)


def test_playbook_skips_a_system_named_like_a_pattern(monkeypatch):
    _scan(monkeypatch)
    db.x("UPDATE hosts SET name='all' WHERE id=1")
    text, summary = patch.build_playbook(_open_ids())
    plays = yaml.safe_load(text) or []
    assert not any(p.get("hosts") == "all" for p in plays)
    assert summary["hosts"] == 0 and summary["manual"] >= 1 and "can't be used as an Ansible host" in text


def test_host_filter_matches_whole_names(monkeypatch):
    _scan(monkeypatch)
    from diysca.ui import finding_count
    n = finding_count({"host": "system_a"})
    assert n > 0
    assert finding_count({"host": "system"}) == 0          # not a substring match any more
    assert finding_count({"host": "system_"}) == 0         # _ is not a wildcard
    assert finding_count({"host": "system%"}) == 0         # % is not a wildcard
    assert finding_count({"host": "system*"}) == n and finding_count({"host": "*_a"}) == n
    assert finding_count({"host": "10.0.0.11"}) == n and finding_count({"host": "10.0.0.1"}) == 0
    assert finding_count({"host": "system_a", "package": "postgres"}) > 0   # other fields still match parts


def test_provider_inventory_does_not_take_over_a_system(monkeypatch):
    db.x("INSERT INTO hosts(name,address,source) VALUES ('web1','10.0.0.5','/etc/ansible/hosts')")
    db.x("INSERT INTO hosts(name,address) VALUES ('manual1','10.0.0.6')")
    from diysca.scanning.inventory import InvHost
    cloud = [InvHost(name="web1", vars={"ansible_host": "203.0.113.9"}), InvHost(name="manual1", vars={"ansible_host": "203.0.113.10"}),
             InvHost(name="new1", vars={"ansible_host": "10.0.0.7"})]
    monkeypatch.setattr(scanner, "_sources", lambda paths, providers: [("provider:aws", "aws", lambda: cloud)])
    scanner.import_inventories()
    got = {r["name"]: r["address"] for r in db.q("SELECT name, address FROM hosts")}
    assert got == {"web1": "10.0.0.5", "manual1": "10.0.0.6", "new1": "10.0.0.7"}


# ---------------------------------------------------------------- scopes and sessions
def test_mitigation_is_limited_to_the_users_systems(monkeypatch):
    _scan(monkeypatch)
    db.x("INSERT INTO hosts(name,address) VALUES ('other','10.0.0.12')")
    other = db.q1("SELECT id FROM hosts WHERE name='other'")["id"]
    ids = _open_ids()
    db.x("UPDATE findings SET host_id=? WHERE id=?", (other, ids[-1]))
    m = mitigate.approve(ids, "alice")
    tok = scope.set_ids(frozenset({1}))
    try:
        seen = mitigate.get(m["id"])
        assert {f["host_id"] for f in seen["findings"]} == {1} and "partial" in seen
        assert seen["hosts"] == ["system_a"] and "other" not in seen["playbook"]
        for act in (lambda: mitigate.claim(m["id"], "bob"), lambda: mitigate.report(m["id"], "done", "bob"),
                    lambda: mitigate.cancel(m["id"], "bob")):
            with pytest.raises(mitigate.MitigationError, match="outside your scope"):
                act()
    finally:
        scope.reset(tok)
    assert mitigate.get(m["id"])["status"] == "approved"
    tok = scope.set_ids(frozenset({1, other}))
    try:
        assert mitigate.claim(m["id"], "bob")["status"] == "claimed"
    finally:
        scope.reset(tok)


def test_role_follows_the_bindings_on_every_request(monkeypatch):
    from diysca.auth import rbac, session

    class Req:
        def __init__(self, v):
            self.cookies = {session.COOKIE: v}
    cookie = session.sign({"t": "login", "u": "alice", "r": "admin", "g": ["ops"]}, 600)
    monkeypatch.setattr(settings, "rbac", {"bindings": [{"group": "ops", "role": "admin"}]})
    assert rbac.user_from_cookie(Req(cookie)).role == "admin"
    monkeypatch.setattr(settings, "rbac", {"bindings": [{"group": "ops", "role": "viewer", "hosts": "web*"}]})
    u = rbac.user_from_cookie(Req(cookie))
    assert u.role == "viewer" and u.hosts == ["web*"]
    monkeypatch.setattr(settings, "rbac", {"bindings": []})
    assert rbac.user_from_cookie(Req(cookie)) is None
    monkeypatch.setattr(settings, "rbac", {"bindings": [{"group": "ops*", "role": "admin"}]})
    assert rbac.bound_groups(["ops-eu", "staff"] + [f"g{i}" for i in range(500)]) == ["ops-eu"]


def test_odd_session_cookies_are_just_invalid():
    from diysca.auth import session
    good = session.sign({"t": "login", "u": "a"}, 600)
    assert session.verify(good)["u"] == "a"
    for bad in ("", "x", "é.é", good[:-2] + "éé", good + "\udcff", "a.b.c.d", None):
        assert session.verify(bad) is None


# ---------------------------------------------------------------- stability
def test_healthz_says_when_the_database_is_down(monkeypatch):
    c = _client(monkeypatch)
    assert c.get("/healthz").json()["ok"] is True

    def down(*a, **k):
        raise OSError("connection refused")
    monkeypatch.setattr(db, "q1", down)
    r = c.get("/healthz")
    assert r.status_code == 503 and r.json()["ok"] is False and "refused" not in r.text


def test_one_system_is_not_scanned_twice_at_once(monkeypatch):
    db.x("INSERT INTO hosts(name,address) VALUES ('web1','10.0.0.5')")
    running, peak = 0, 0

    async def slow(host_id, *a, **kw):
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        await asyncio.sleep(0.02)
        running -= 1
        return {"host": "web1"}
    monkeypatch.setattr(scanner, "_scan_host", slow)

    async def go():
        await asyncio.gather(scanner.scan_host(1), scanner.scan_host(1), scanner.scan_host(1))
    asyncio.run(go())
    assert peak == 1


def test_local_command_is_killed_on_timeout():
    async def go():
        t = tp.LocalTransport()
        with pytest.raises(Exception, match="timed out"):
            await t.run("sleep 31 & sleep 30; true", timeout=0.2)   # a child of the shell, as dash runs it
    asyncio.run(asyncio.wait_for(go(), 5))


def test_bad_bodies_get_a_422_not_a_500(monkeypatch):
    c = _client(monkeypatch)
    _scan(monkeypatch)
    for body in ([1, 2], "x", {"finding_ids": "all"}, {"finding_ids": ["1; DROP"]}, {"finding_ids": [{"id": 1}]}):
        r = c.post("/api/mitigations", json=body)
        assert r.status_code == 422, (body, r.text)
    assert c.post("/api/mitigations", content=b"{not json", headers={"content-type": "application/json"}).status_code == 422
    m = mitigate.approve(_open_ids()[:1], "alice")
    assert c.post(f"/api/mitigations/{m['id']}/report", json=["done"]).status_code == 422


# ---------------------------------------------------------------- usability
def test_error_pages_for_browsers_and_json_for_clients(monkeypatch):
    c = _client(monkeypatch)
    r = c.get("/systems/999999", headers={"accept": "text/html"})
    assert r.status_code == 404 and "<html" in r.text.lower() and "Not found" in r.text
    r = c.get("/api/hosts/999999/repos")
    assert r.status_code == 404 and r.headers["content-type"].startswith("application/json")


def test_findings_page_says_when_the_list_is_cut(monkeypatch):
    from diysca import ui
    _scan(monkeypatch)
    total = ui.finding_count({})
    assert total > 1
    monkeypatch.setattr(ui, "FINDINGS_LIMIT", 1)
    sql, p = ui.finding_query({}, limit=1)
    assert len(db.q(sql, p)) == 1
    # approving by filter is never cut
    from diysca.mitigation.routes import _ids_from_filter
    assert len(_ids_from_filter("")) == total


def test_config_mistakes_are_named(tmp_path, monkeypatch):
    bad = tmp_path / "bad.yml"
    bad.write_text("listen: [unclosed\n")
    with pytest.raises(config.ConfigError, match="bad.yml"):
        config.load_settings(str(bad), explicit=True)
    with pytest.raises(config.ConfigError, match="does not exist"):
        config.load_settings(str(tmp_path / "missing.yml"), explicit=True)
    config.load_settings(str(tmp_path / "missing.yml"))   # $DIYSCA_CONFIG may point at nothing
    typo = tmp_path / "typo.yml"
    typo.write_text("databse_url: postgresql://x\n")
    config.load_settings(str(typo), explicit=True)
    assert any("databse_url" in w and "database_url" in w for w in config.warnings)
