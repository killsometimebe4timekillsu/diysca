"""OIDC login, roles and host scopes, the audit log, the patch log and disabled modules."""
import base64
import json
import time
from urllib.parse import parse_qs, urlparse

import httpx
from fastapi.testclient import TestClient

from diysca.auth import oidc, rbac
from diysca.core import db, scope
from diysca.core.config import settings
from diysca.mitigation import mitigate, patchlog

from .test_settings_reprovision import _scan

ISS = "https://sso.example.org/realms/acme"


def _jwt(claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{enc({'alg': 'RS256'})}.{enc(claims)}.sig"


def _provider(monkeypatch, claims):
    state = {}

    def handler(req: httpx.Request):
        if req.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json={"issuer": ISS, "authorization_endpoint": ISS + "/auth",
                                             "token_endpoint": ISS + "/token", "end_session_endpoint": ISS + "/logout"})
        if req.url.path.endswith("/token"):
            form = parse_qs(req.content.decode())
            assert form["code"] == ["c0de"] and form["code_verifier"]
            return httpx.Response(200, json={"id_token": _jwt({"iss": ISS, "aud": "diysca", "exp": time.time() + 300,
                                                               "nonce": state["nonce"], **claims}),
                                             "access_token": "at"})
        return httpx.Response(404)
    t = httpx.MockTransport(handler)
    monkeypatch.setattr(oidc, "_client", lambda: httpx.Client(transport=t))
    oidc._discovery.clear()
    monkeypatch.setattr(settings, "oidc", {"issuer": ISS, "client_id": "diysca", "client_secret": "s",
                                           "groups_claim": "groups"})
    monkeypatch.setattr(settings, "rbac", {"default_role": "", "bindings": [
        {"group": "secops", "role": "admin"},
        {"group": "dba", "role": "approver", "hosts": "group:db"},
        {"email": "*@ops.example.org", "role": "operator"}]})
    return state


def _login(c, state):
    r = c.get("/findings", follow_redirects=False, headers={"Accept": "text/html"})
    assert r.status_code == 303 and r.headers["location"].startswith("/login?next=%2Ffindings")
    r = c.get(r.headers["location"], follow_redirects=False)
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["code_challenge_method"] == ["S256"] and q["client_id"] == ["diysca"]
    state["nonce"] = q["nonce"][0]
    return c.get("/auth/callback", params={"code": "c0de", "state": q["state"][0]}, follow_redirects=False)


def test_oidc_roles(monkeypatch):
    _scan(monkeypatch)
    state = _provider(monkeypatch, {"preferred_username": "dana", "email": "dana@example.org", "groups": ["/dba"]})
    from diysca.web import app
    c = TestClient(app)
    r = _login(c, state)
    assert r.status_code == 303 and r.headers["location"] == "/findings"
    me = c.get("/api/me").json()
    assert me["name"] == "dana" and me["role"] == "approver" and me["hosts"] == ["group:db"]
    assert c.get("/settings/sources").status_code == 403  # admin only
    assert c.get("/findings").status_code == 200
    actions = [r["action"] for r in db.q("SELECT action FROM audit_log")]
    assert "login" in actions


def test_oidc_denied_and_bad_nonce(monkeypatch):
    state = _provider(monkeypatch, {"preferred_username": "eve", "groups": ["guests"]})
    from diysca.web import app
    c = TestClient(app)
    r = _login(c, state)
    assert "/login?error=" in r.headers["location"] and "no+access" in r.headers["location"]
    state2 = _provider(monkeypatch, {"preferred_username": "x", "groups": ["secops"]})
    r = c.get("/login", follow_redirects=False)
    q = parse_qs(urlparse(r.headers["location"]).query)
    state2["nonce"] = "wrong"
    r = c.get("/auth/callback", params={"code": "c0de", "state": q["state"][0]}, follow_redirects=False)
    assert "nonce" in r.headers["location"]
    r = c.get("/auth/callback", params={"code": "c0de", "state": "forged"}, follow_redirects=False)
    assert "state" in r.headers["location"]


def test_role_for_and_policy(monkeypatch):
    monkeypatch.setattr(settings, "rbac", {"default_role": "viewer", "bindings": [
        {"group": "dba", "role": "approver", "hosts": "group:db"}, {"group": "ops", "role": "approver"},
        {"user": "root*", "role": "admin"}]})
    assert rbac.role_for("a", "", ["dba"]) == ("approver", ["group:db"])
    assert rbac.role_for("a", "", ["dba", "ops"]) == ("approver", [])  # an unscoped binding wins
    assert rbac.role_for("rooty", "", []) == ("admin", [])
    assert rbac.role_for("nobody", "", []) == ("viewer", [])
    assert rbac.required_role("POST", "/api/mitigations") == "approver"
    assert rbac.required_role("POST", "/api/mitigations/3/claim") == "operator"
    assert rbac.required_role("POST", "/settings/channels") == "admin"
    assert rbac.required_role("GET", "/findings") == "viewer"


def test_token_scope_and_roles(monkeypatch):
    _scan(monkeypatch)
    from diysca.web import app
    hosts = [r["name"] for r in db.q("SELECT name FROM hosts ORDER BY name")]
    monkeypatch.setattr(settings, "api_tokens", {
        "view": {"token": "v1", "role": "viewer"},
        "one": {"token": "o1", "role": "operator", "hosts": hosts[0]}})
    c = TestClient(app)
    v = {"Authorization": "Bearer v1"}
    assert c.get("/api/findings", headers=v).status_code == 200
    assert c.post("/api/scan", headers=v).status_code == 403
    o = {"Authorization": "Bearer o1"}
    rows = c.get("/api/findings", headers=o).json()
    rows = rows.get("findings", rows) if isinstance(rows, dict) else rows
    assert rows and {r.get("host") or r.get("host_name") or r.get("name") for r in rows} == {hosts[0]}
    assert c.post("/api/mitigations", json={"filter": ""}, headers=o).status_code == 403


def test_scope_clause():
    db.x("INSERT INTO hosts(name, address, groups) VALUES ('a','a','db'),('b','b','web')")
    ids = scope.hosts_for(["group:db"])
    assert [r["name"] for r in db.q("SELECT name FROM hosts WHERE id IN (%s)" % ",".join(map(str, ids)))] == ["a"]
    assert scope.hosts_for([]) is None


def test_patch_log(monkeypatch):
    _scan(monkeypatch)
    from diysca.web import app
    c = TestClient(app)
    ids = [r["id"] for r in db.q("SELECT id FROM findings WHERE status='open'")]
    r = c.post("/patch/playbook", data={"ids": [str(i) for i in ids]})
    assert r.status_code == 200
    monkeypatch.setattr(mitigate, "_notify", lambda *a: None)
    m = mitigate.approve(ids, "alice", "window tonight")
    mitigate.claim(m["id"], "runner:ci")
    mitigate.report(m["id"], "done", "runner:ci", "PLAY RECAP ok=3")
    d = patchlog.query({"range": "24h"})
    kinds = [e["kind"] for e in d["rows"]]
    assert "playbook" in kinds and "mitigation" in kinds
    e = next(e for e in d["rows"] if e["kind"] == "mitigation")
    assert e["approver"] == "alice" and e["executor"] == "runner:ci" and e["status"] == "done"
    assert e["hosts"] and e["cves"] and "PLAY RECAP" in e["detail"]
    csv_text = c.get("/patchlog.csv?range=24h").text
    assert csv_text.splitlines()[0].startswith("id,at,kind,status") and "alice" in csv_text
    j = c.get("/api/patchlog", params={"range": "24h", "kind": "mitigation"}).json()
    assert [x["kind"] for x in j["entries"]] == ["mitigation"]
    assert "Patch log" in c.get("/patchlog").text


def test_modules_disabled(monkeypatch):
    from diysca import mcp
    from diysca.core import modules
    monkeypatch.setattr(settings, "modules", ["alerting"])
    try:
        modules.load(force=True)
        assert not modules.enabled("mitigation") and not modules.enabled("auth") and modules.enabled("scanning")
        names = {t["name"] for t in mcp.tool_list(mcp.Context(actor="x", is_token=True))}
        assert "search_findings" in names and "approve_findings" not in names and "patch_log" not in names
        assert "Mitigations" not in str(modules.tabs("findings"))
    finally:
        monkeypatch.setattr(settings, "modules", [])
        modules.load(force=True)
