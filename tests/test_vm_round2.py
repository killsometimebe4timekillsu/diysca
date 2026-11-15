"""Fixes from the second VM test round: open-UI warning, scheduler start delay, mitigation fields, CLI pipes."""
import asyncio
import subprocess
import sys
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from diysca.core import db
from diysca.core.config import settings
from diysca.scanning import scanner



def test_banner_when_no_login(monkeypatch):
    monkeypatch.setattr(settings, "web_user", "")
    monkeypatch.setattr(settings, "web_password", "")
    from diysca.web import app
    assert "No login configured" in TestClient(app).get("/").text
    monkeypatch.setattr(settings, "web_user", "admin")
    monkeypatch.setattr(settings, "web_password", "pw")
    r = TestClient(app).get("/", auth=("admin", "pw"))
    assert r.status_code == 200 and "No login configured" not in r.text


def test_first_scan_waits_for_interval(monkeypatch):
    monkeypatch.setattr(settings, "scan_interval_hours", 12)
    assert scanner._first_scan_delay() == 10  # never scanned
    recent = (datetime.now(timezone.utc) - timedelta(hours=2)).replace(microsecond=0).isoformat()
    db.x("INSERT INTO hosts(name,address,last_scan) VALUES ('h1','10.0.0.1',?)", (recent,))
    assert 9.9 * 3600 < scanner._first_scan_delay() <= 10 * 3600


def test_findings_pipe_to_head_does_not_crash():
    code = ("import sys; sys.argv=['diysca','--version'];"
            "from diysca import cli\n"
            "def boom(*a, **k): raise BrokenPipeError\n"
            "cli._main = boom\ncli.main()")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert r.returncode == 0 and "Traceback" not in r.stderr
