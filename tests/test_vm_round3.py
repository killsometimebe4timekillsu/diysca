"""Findings from the third run against the test VMs (2026-11-15): mitigation bookkeeping and messages."""
import sys

import pytest
from fastapi.testclient import TestClient

from diysca.core import db
from diysca.core.config import settings
from diysca.mitigation import mitigate, patchlog

from .test_mitigation_mcp import _open_ids
from .test_settings_reprovision import _scan


def test_findings_are_not_approved_twice(monkeypatch):
    _scan(monkeypatch)
    ids = _open_ids()
    assert len(ids) >= 2
    first = mitigate.approve(ids[:1], "alice")
    with pytest.raises(mitigate.MitigationError, match=f"already in open mitigation #{first['id']}"):
        mitigate.approve(ids[:1], "bob")
    # a wider selection takes only what is still free
    second = mitigate.approve(ids, "bob")
    assert {f["id"] for f in second["findings"]} == set(ids[1:])
    # once the first one is finished or cancelled, its findings can be approved again
    mitigate.cancel(first["id"], "alice")
    assert {f["id"] for f in mitigate.approve(ids[:1], "alice")["findings"]} == set(ids[:1])


def test_cancel_without_claim_has_no_executor(monkeypatch):
    _scan(monkeypatch)
    m = mitigate.approve(_open_ids()[:1], "alice")
    mitigate.cancel(m["id"], "token:approverbot")
    e = patchlog.query({"range": "24h"})["rows"][0]
    assert e["status"] == "cancelled" and e["actor"] == "token:approverbot" and not e["executor"]


def test_patch_log_says_what_a_done_run_covered(monkeypatch):
    _scan(monkeypatch)
    m = mitigate.approve(_open_ids(), "alice")
    mitigate.report(m["id"], "done", "runner:ci")
    e = patchlog.query({"range": "24h"})["rows"][0]
    s = m["summary"]
    assert f"({s['playbook_packages']} packages, {s['manual_items']} manual items)" in e["summary"]
    assert e["executor"] == "runner:ci"


def test_empty_filter_message(monkeypatch, capsys):
    monkeypatch.setattr(settings, "allow_no_login", True)
    _scan(monkeypatch)
    from diysca.web import app
    r = TestClient(app).post("/api/mitigations", json={"filter": "host=nosuchhost&fix=repo"})
    assert r.status_code == 422 and "no open findings match the filter 'host=nosuchhost&fix=repo'" in r.text
    assert "select at least one finding" in TestClient(app).post("/api/mitigations", json={}).text

    from diysca import cli
    monkeypatch.setattr(sys, "argv", ["diysca", "playbook", "--host", "system_a", "--filter", "cve=CVE-0000-0"])
    cli.main()
    err = capsys.readouterr().err
    assert "no open findings match the filter 'cve=CVE-0000-0' on system_a" in err and "open findings in total" in err


def test_report_names_the_rescanned_systems_and_counts_all_cves(monkeypatch):
    monkeypatch.setattr(settings, "allow_no_login", True)
    _scan(monkeypatch)
    from diysca.scanning import scanner
    from diysca.web import app

    async def no_scan(**kw):
        return []
    monkeypatch.setattr(scanner, "scan_all", no_scan)
    m = mitigate.approve(_open_ids(), "alice")
    assert m["summary"]["cves_total"] == len({f["vuln_id"] for f in m["findings"]}) >= len(m["summary"]["cves"]) > 0
    assert "<this file> --check --diff" in m["playbook"] and "diysca-patch.yml" not in m["playbook"]
    r = TestClient(app).post(f"/api/mitigations/{m['id']}/report", json={"status": "done"})
    assert r.status_code == 200 and r.json()["rescan_hosts"] == ["system_a"]
