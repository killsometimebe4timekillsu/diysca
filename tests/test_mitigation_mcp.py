"""Approving findings for mitigation, hand-off, API tokens and the MCP server."""
import asyncio
import json

from fastapi.testclient import TestClient

from diysca import mcp
from diysca.alerting import notify
from diysca.core import db, settings_io
from diysca.core.config import settings
from diysca.mitigation import mitigate

from .test_settings_reprovision import _scan


def _open_ids():
    return [r["id"] for r in db.q("SELECT id FROM findings WHERE status='open' ORDER BY id")]


def test_lifecycle(monkeypatch):
    _scan(monkeypatch)
    ids = _open_ids()
    assert ids
    m = mitigate.approve(ids, "alice", "CHG-1")
    assert m["status"] == "approved" and m["approved_by"] == "alice" and "postgresql-16=16.7-0+deb12u1" in m["playbook"]
    assert m["summary"]["findings"] == len(ids) and m["hosts"] == ["system_a"]
    assert db.q1("SELECT mitigation_id FROM findings WHERE id=?", (ids[0],))["mitigation_id"] == m["id"]
    assert [x["id"] for x in mitigate.list_("approved")] == [m["id"]]
    mitigate.claim(m["id"], "token:ci")
    try:
        mitigate.claim(m["id"], "token:other")
        raise AssertionError("second claim must fail")
    except mitigate.MitigationError:
        pass
    mitigate.report(m["id"], "running", "token:ci", "ansible started")
    done, rescan = mitigate.report(m["id"], "done", "token:ci", "ok=3 changed=1")
    assert done["status"] == "done" and rescan == [1]
    full = mitigate.get(m["id"])
    assert full["finished_at"] and full["verified"].endswith("/" + str(len(full["findings"])))
    assert "ok=3 changed=1" in mitigate.get(m["id"])["log"]
    assert db.q1("SELECT COUNT(*) n FROM patch_runs WHERE kind='mitigation'")["n"] == 1


def test_cancel_and_reapprove(monkeypatch):
    _scan(monkeypatch)
    ids = _open_ids()
    m = mitigate.approve(ids[:1], "bob")
    mitigate.cancel(m["id"], "bob", "wrong host")
    assert db.q1("SELECT mitigation_id FROM findings WHERE id=?", (ids[0],))["mitigation_id"] is None
    m2 = mitigate.approve(ids[:1], "bob")
    assert m2["id"] != m["id"]


def test_handoff_webhook_and_github(monkeypatch):
    _scan(monkeypatch)
    sent = []

    class FakeResp:
        status_code = 204
        text = ""

    class FakeClient:
        def __init__(self, **kw): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def post(self, url, **kw):
            sent.append((url, kw))
            return FakeResp()

    monkeypatch.setattr(mitigate.httpx, "Client", FakeClient)
    mitigate.save_handoff("hook", "webhook", "https://hooks.example/diysca", "s3cret", auto=True)
    mitigate.save_handoff("gh", "github", "https://github.com/acme/infra", "ghp_x")
    assert mitigate.handoffs()[0]["url"] == "https://api.github.com/repos/acme/infra/dispatches"
    m = mitigate.approve(_open_ids(), "alice")  # auto target
    url, kw = sent[0]
    body = json.loads(kw["content"])
    assert url == "https://hooks.example/diysca" and kw["headers"]["Authorization"] == "Bearer s3cret"
    assert body["mitigation"]["id"] == m["id"] and body["playbook"] and body["links"]["report"].endswith("/report")
    mitigate.deliver(m["id"], "gh")
    url, kw = sent[1]
    assert url.endswith("/repos/acme/infra/dispatches") and kw["json"]["event_type"] == "diysca-mitigation"
    assert len(kw["json"]["client_payload"]) <= 10
    assert "HTTP 204" in mitigate.get(m["id"])["handoff_result"]
    out = settings_io.export_bundle()
    assert {h["name"]: h["token"] for h in out["handoffs"]} == {"gh": "***", "hook": "***"}
    res = settings_io.import_bundle({"handoffs": out["handoffs"]})
    assert res["errors"] == [] and db.q1("SELECT token FROM handoffs WHERE name='hook'")["token"] == "s3cret"


def test_api_tokens_and_approval_gate(monkeypatch):
    _scan(monkeypatch)
    from diysca.web import app
    monkeypatch.setattr(settings, "api_tokens", {"ci": "tok123"})
    c = TestClient(app)
    assert c.get("/api/mitigations").status_code == 401
    assert c.get("/api/mitigations", headers={"Authorization": "Bearer nope"}).status_code == 401
    h = {"Authorization": "Bearer tok123"}
    assert c.get("/findings", headers=h).status_code == 401  # tokens don't open the UI
    r = c.post("/api/mitigations", json={"filter": "host=system_a"}, headers=h)
    assert r.status_code == 403
    m = mitigate.approve(_open_ids(), "alice")
    r = c.post(f"/api/mitigations/{m['id']}/claim", headers=h)
    assert r.status_code == 200 and r.json()["claimed_by"] == "token:ci"
    assert c.post(f"/api/mitigations/{m['id']}/claim", headers=h).status_code == 409
    assert "postgresql-16" in c.get(f"/api/mitigations/{m['id']}/playbook.yml", headers=h).text
    monkeypatch.setattr(mitigate, "_notify", lambda *a: None)
    r = c.post(f"/api/mitigations/{m['id']}/report", json={"status": "failed", "log": "unreachable"}, headers=h)
    assert r.status_code == 200 and r.json()["status"] == "failed"
    monkeypatch.setattr(settings, "agents_can_approve", True)
    r = c.post("/api/mitigations", json={"filter": "host=system_a", "note": "auto"}, headers=h)
    assert r.status_code == 201 and r.json()["approved_by"] == "token:ci"
    spec = c.get("/openapi.json").json()
    assert "/api/mitigations/{mid}/report" in spec["paths"] and "/findings" not in spec["paths"]


def test_ui_approve(monkeypatch):
    _scan(monkeypatch)
    from diysca.web import app
    c = TestClient(app)
    assert "Approve for mitigation" in c.get("/findings").text
    r = c.post("/mitigations", data={"ids": [str(i) for i in _open_ids()], "note": "go"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/mitigations/")
    page = c.get(r.headers["location"]).text
    assert "approved" in page and "go" in page
    assert "#1 approved" in c.get("/findings").text
    assert c.get("/mitigations").status_code == 200 and c.get("/settings/handoff").status_code == 200
    assert c.get("/findings?approval=unapproved").text.count('name="ids"') == 0


def test_mcp(monkeypatch):
    _scan(monkeypatch)
    ctx = mcp.Context(actor="token:agent", is_token=True)
    run = lambda msg: asyncio.run(mcp.handle(msg, ctx))
    init = run({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}})
    assert init["result"]["protocolVersion"] == "2025-06-18" and init["result"]["capabilities"]["tools"]
    assert run({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    names = {t["name"] for t in run({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]}
    assert {"search_findings", "claim_mitigation", "report_mitigation"} <= names and "approve_findings" not in names

    def tool(name, **args):
        r = run({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": name, "arguments": args}})
        res = r["result"]
        return res["isError"], (json.loads(res["content"][0]["text"]) if not res["isError"] else res["content"][0]["text"])

    err, data = tool("search_findings", severity="HIGH", limit=5)
    assert not err and data["findings"][0]["host_name"] == "system_a"
    assert run({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "approve_findings"}})["error"]
    m = mitigate.approve(_open_ids(), "alice")
    assert tool("list_mitigations", status="approved")[1][0]["id"] == m["id"]
    err, data = tool("claim_mitigation", id=m["id"])
    assert not err and data["claimed_by"] == "token:agent"
    err, data = tool("claim_mitigation", id=m["id"])
    assert err and "claimed" in data
    monkeypatch.setattr(mitigate, "_notify", lambda *a: None)
    err, data = tool("report_mitigation", id=m["id"], status="failed", log="no route to host")
    assert not err and data["status"] == "failed"
    assert run({"jsonrpc": "2.0", "id": 9, "method": "nope"})["error"]["code"] == -32601
    from diysca.web import app
    c = TestClient(app)
    r = c.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert r.status_code == 200 and r.json()["result"]["tools"]
    assert c.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"}).status_code == 202


def test_alert_text():
    f = {"id": 7, "severity": "HIGH", "vuln_id": "CVE-2025-1", "package": "openssl", "version": "3.0.11", "cvss_score": 8.1,
         "epss": 0.42, "kev": 1, "summary": "bad thing", "ecosystem": "", "fixed_version": "3.0.15", "fix_in_repo": 0,
         "repo_version": None, "location": None}
    body = notify.alert_body([f], {"name": "web1"}, "https://diysca.example")
    assert "HIGH  CVE-2025-1  openssl 3.0.11  (CVSS 8.1, EPSS 42%, KNOWN EXPLOITED)" in body
    assert "isn't in your repos yet" in body and "https://diysca.example/findings/7" in body
