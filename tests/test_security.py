"""Regression tests for the security review: data from scanned systems must stay data, the web UI must not
read arbitrary files, and browsers on other sites must not be able to change anything."""
import asyncio
import os
import subprocess
import zipfile

import pytest
from fastapi.testclient import TestClient

from diysca.core import db, security
from diysca.core.config import settings
from diysca.mitigation import pbsafe, reprovision
from diysca.mitigation.patch import build_playbook
from diysca.scanning import repos
from diysca.scanning.langpkgs import lang_script, parse_lang_output
from diysca.ui import csv_cell, download_name

EVIL = "{{ lookup('pipe', 'id') }}"


# ------------------------------------------------------------------ playbooks
def _host_with_package(name: str, repo_version: str = "2.0-1", pkg_type: str = "deb"):
    h = db.x("INSERT INTO hosts(name,address,pkg_type,os_id) VALUES ('web1','10.0.0.1',?,'debian')", (pkg_type,))
    db.x("""INSERT INTO packages(host_id,name,version,source_name,type,repo_version,ecosystem)
            VALUES (?,?,'1.0-1','openssl',?,?,'')""", (h, name, pkg_type, repo_version))
    return db.x("""INSERT INTO findings(host_id,package,version,ecosystem,binaries,vuln_id,fixed_version,repo_version,
                                        fix_in_repo,severity,status)
                   VALUES (?,'openssl','1.0-1','',?,'CVE-2099-1','2.0-1',?,1,'HIGH','open')""", (h, name, repo_version))


@pytest.mark.parametrize("name,version,pkg_type", [
    ("{{ 7 * 7 }}", "2.0-1", "deb"),               # Jinja: would be evaluated on the Ansible control node
    ("libssl3", EVIL, "deb"),
    ("http://evil.example/x.rpm#", "2.0-1", "rpm"),  # dnf installs URLs and paths given as a name
    ("/tmp/evil.rpm", "2.0-1", "rpm"),
    ("-oDPkg::Pre-Invoke::=id", "2.0-1", "deb"),   # option for the package manager
    ("lib ssl", "2.0-1", "deb"),
])
def test_playbook_never_installs_odd_package_names(name, version, pkg_type):
    fid = _host_with_package(name, version, pkg_type)
    text, summary = build_playbook([fid])
    assert summary["hosts"] == 0 and "Skipped: unexpected characters" in text
    body = text.split("\n---\n", 1)[1]
    assert name not in body and version not in body


def test_playbook_marks_jinja_in_other_strings_unsafe():
    fid = _host_with_package("libssl3")
    db.x("UPDATE findings SET vuln_id=? WHERE id=?", (EVIL, fid))   # ends up in the play name
    body = build_playbook([fid])[0].split("\n---\n", 1)[1]
    assert "!unsafe" in body and "libssl3=2.0-1" in body
    for line in body.splitlines():
        if "lookup" in line:
            assert "!unsafe" in line


def test_playbook_comment_cannot_be_left():
    h = db.x("INSERT INTO hosts(name,address,pkg_type,os_id) VALUES ('web1','10.0.0.1','deb','debian')")
    fid = db.x("""INSERT INTO findings(host_id,package,version,ecosystem,location,vuln_id,fixed_version,fix_in_repo,
                                       severity,status)
                  VALUES (?,?,'1.0','npm','/srv/app','CVE-2099-2','2.0',0,'HIGH','open')""",
               (h, "left-pad\n- hosts: all\n  tasks: [{shell: id}]\n#"))
    head = build_playbook([fid])[0].split("\n---\n", 1)[0]
    assert all(line.startswith("#") for line in head.splitlines())


def _sbom(os_version="12", pkg="bash", ver="5.2-1", image="docker.io/library/nginx:1.27", runtime="podman",
          pip_name="requests"):
    return {"bomFormat": "CycloneDX",
            "metadata": {"component": {"name": "web1", "properties": [
                {"name": "diysca:os_id", "value": "debian"}, {"name": "diysca:os_version", "value": os_version},
                {"name": "diysca:pkg_type", "value": "deb"}]}},
            "components": [
                {"type": "library", "purl": f"pkg:deb/debian/{pkg}@{ver}", "bom-ref": "a"},
                {"type": "library", "purl": f"pkg:pypi/{pip_name}@2.31.0",
                 "properties": [{"name": "diysca:location", "value": "/opt/app/lib/python3.12/site-packages"}]},
                {"type": "container", "name": image,
                 "properties": [{"name": "diysca:container_runtime", "value": runtime}]}]}


def test_reprovision_condition_takes_no_expression():
    import yaml
    text, _ = reprovision.build(_sbom(os_version="12' or lookup('pipe','id') or '"))
    play = yaml.safe_load(text.split("\n---\n", 1)[1])[0]
    conditions = [c for t in play["tasks"] for c in t.get("ansible.builtin.assert", {}).get("that", [])]
    assert conditions == ["ansible_facts['distribution'] == 'Debian'"]  # the version check is dropped, not injected
    text, _ = reprovision.build(_sbom())
    assert "distribution_major_version'] == '12'" in text


def test_reprovision_skips_odd_packages_images_and_pip_options():
    text, summary = reprovision.build(_sbom(pkg="bash", ver="5.2-1", image="x; rm -rf /", runtime="sh",
                                             pip_name="--index-url=http:evil"))
    body = text.split("\n---\n", 1)[1]
    assert "bash=5.2-1" in body and "rm -rf" not in body and "index-url" not in body and summary["packages"] == 1
    assert "Skipped, unexpected characters" in text


def test_pbsafe_helpers():
    assert pbsafe.pin_ok("deb", "libc6:i386", "2.36-9+deb12u4") and pbsafe.pin_ok("rpm", "kernel-core", "0:5.14.0-1.el9")
    assert not pbsafe.pin_ok("deb", "Bad", "1") and not pbsafe.pin_ok("rpm", "a b", "1") and not pbsafe.pin_ok("apk", "x", "")
    assert pbsafe.word("12") == "12" and pbsafe.word("12'x") == ""
    assert "\n" not in pbsafe.comment("a\nb c\x85d")


# ------------------------------------------------------------------ scan script
def test_lang_scan_does_not_run_file_names(tmp_path):
    """A jar whose path is a sed program: the old script passed it to sed, which ran it as the scan user."""
    root = tmp_path / "root"
    evil_dir = root / "a|;1e touch PWNED #"
    evil_dir.mkdir(parents=True)
    with zipfile.ZipFile(evil_dir / "x.jar", "w") as z:
        z.writestr("META-INF/maven/g/a/pom.properties", "groupId=org.x\nartifactId=lib\nversion=1.2.3\n")
    r = subprocess.run(["/bin/sh", "-c", lang_script([str(root), str(tmp_path / "missing dir")])],
                       capture_output=True, text=True, cwd=tmp_path)
    assert not (tmp_path / "PWNED").exists()
    if r.stdout.count("P\t"):  # unzip is installed: the package is still found
        assert [(p.name, p.version) for p in parse_lang_output(r.stdout)] == [("org.x:lib", "1.2.3")]


def test_lang_script_has_no_temp_files_or_unquoted_roots():
    s = lang_script(["/opt", "/srv/my app"])
    assert "/tmp/" not in s and "$ROOTS" not in s and 'find "$@"' in s and "sed \"" not in s


# ------------------------------------------------------------------ web
def _client():
    from diysca.web import app
    return TestClient(app)


def test_inventory_import_only_reads_configured_paths(tmp_path, monkeypatch):
    key = tmp_path / "id_ed25519"
    key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nc2VjcmV0\n-----END OPENSSH PRIVATE KEY-----\n")
    inv = tmp_path / "inv"
    inv.mkdir()
    (inv / "hosts.ini").write_text("[web]\nweb1 ansible_host=10.0.0.1\n")
    monkeypatch.setattr(settings, "use_ansible_inventory_cli", False)
    c = _client()
    assert c.post("/inventory/import", data={"path": str(key)}).status_code == 400
    assert db.q1("SELECT COUNT(*) n FROM hosts")["n"] == 0
    assert c.post("/inventory/import", data={"path": str(inv / ".." / "id_ed25519")}).status_code == 400
    monkeypatch.setattr(settings, "inventory_dirs", [str(inv)])
    assert c.post("/inventory/import", data={"path": str(inv / "hosts.ini")}, follow_redirects=False).status_code == 303
    assert [r["name"] for r in db.q("SELECT name FROM hosts")] == ["web1"]


def test_cross_site_changes_are_blocked(monkeypatch):
    monkeypatch.setattr(settings, "base_url", "https://diysca.example.org")
    monkeypatch.setattr(settings, "api_tokens", {"ci": {"token": "t1", "role": "admin"}})
    c = _client()
    form = {"name": "x", "address": "10.9.9.9"}
    assert c.post("/systems", data=form, headers={"Origin": "https://evil.example"}).status_code == 403
    assert c.post("/systems", data=form, headers={"Referer": "https://evil.example/page"}).status_code == 403
    assert c.post("/systems", data=form, headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert c.post("/systems", data=form, headers={"Origin": "null"}).status_code == 403
    assert db.q1("SELECT COUNT(*) n FROM hosts")["n"] == 0
    ok = {"follow_redirects": False}
    assert c.post("/systems", data=form, headers={"Origin": "https://diysca.example.org"}, **ok).status_code == 303
    assert c.post("/systems", data=form, headers={"Origin": "http://testserver"}, **ok).status_code == 303
    assert c.post("/systems", data=form, **ok).status_code == 303  # curl, scripts: no Origin at all
    assert c.post("/api/scan?wait=false&hosts=nope", headers={"Origin": "https://evil.example",
                                                             "Authorization": "Bearer t1"}).status_code == 404
    r = c.get("/systems", headers={"Origin": "https://evil.example"})
    assert r.status_code == 200 and r.headers["x-frame-options"] == "DENY" and r.headers["x-content-type-options"] == "nosniff"


def test_redirect_targets_stay_on_this_site(monkeypatch):
    for bad in ("//evil.example", "https://evil.example", "/\\evil.example", "javascript:alert(1)", "", None, "/a\nb"):
        assert security.safe_next(bad) == "/"
    assert security.safe_next("/findings?severity=HIGH") == "/findings?severity=HIGH"
    c = _client()
    fid = _host_with_package("libssl3")
    r = c.post(f"/findings/{fid}/status", data={"status": "ignored", "back": "//evil.example"}, follow_redirects=False)
    assert r.headers["location"] == "/findings"
    monkeypatch.setattr(settings, "web_user", "admin")
    monkeypatch.setattr(settings, "web_password", "pw")
    assert "javascript:" not in c.get("/login?next=javascript:alert(1)").text


def test_basic_auth_takes_non_ascii(monkeypatch):
    monkeypatch.setattr(settings, "web_user", "admin")
    monkeypatch.setattr(settings, "web_password", "pässwört")
    c = _client()
    assert c.get("/systems", headers={"Authorization": "Basic " + __import__("base64").b64encode(
        "admin:wröng".encode()).decode()}).status_code == 401
    assert c.get("/api/hosts", headers={"Authorization": "Bearer tökén".encode()}).status_code == 401


def test_scoped_token_cannot_reach_other_systems(monkeypatch):
    f1 = _host_with_package("libssl3")
    h2 = db.x("INSERT INTO hosts(name,address,pkg_type,os_id) VALUES ('db1','10.0.0.2','deb','debian')")
    db.x("""INSERT INTO packages(host_id,name,version,source_name,type,repo_version,ecosystem)
            VALUES (?,'libpq5','1.0-1','postgresql','deb','2.0-1','')""", (h2,))
    f2 = db.x("""INSERT INTO findings(host_id,package,version,ecosystem,binaries,vuln_id,fixed_version,repo_version,
                                      fix_in_repo,severity,status)
                 VALUES (?,'postgresql','1.0-1','','libpq5','CVE-2099-3','2.0-1','2.0-1',1,'HIGH','open')""", (h2,))
    from diysca.mitigation import mitigate
    mid = mitigate.approve([f2], "admin")["id"]
    monkeypatch.setattr(settings, "api_tokens", {"web": {"token": "w1", "role": "operator", "hosts": "web1"}})
    c = _client()
    h = {"Authorization": "Bearer w1"}
    assert c.get(f"/api/mitigations/{mid}/playbook.yml", headers=h).status_code == 404
    assert c.get(f"/api/hosts/{h2}/sbom", headers=h).status_code == 404

    def tool(name, args):
        r = c.post("/mcp", headers=h, json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                            "params": {"name": name, "arguments": args}}).json()["result"]
        return r["content"][0]["text"]
    assert "no system" in tool("get_sbom", {"host": "db1"})
    assert "no system" in tool("start_scan", {"host": "db1"})
    pb = tool("generate_playbook", {"finding_ids": [f1, f2]})
    assert "libssl3=2.0-1" in pb and "libpq5" not in pb


# ------------------------------------------------------------------ repo fetches
def test_repo_fetch_refuses_metadata_and_loopback():
    assert repos._forbidden_address("169.254.169.254") and repos._forbidden_address("127.0.0.1")
    assert repos._forbidden_address("::1") and repos._forbidden_address("10.1.2.3") is None

    async def run():
        f = repos.Fetcher()
        try:
            with pytest.raises(repos.FetchError, match="refusing to fetch"):
                await f.get("http://169.254.169.254/latest/meta-data/")
        finally:
            await f.close()
    asyncio.run(run())


def test_decompression_is_bounded(monkeypatch):
    import gzip
    monkeypatch.setattr(repos, "MAX_INDEX", 1000)
    with pytest.raises(repos.FetchError):
        repos._decompress("Packages.gz", gzip.compress(b"a" * 100_000))
    with pytest.raises(repos.FetchError):
        repos._decompress("Packages.xz", __import__("lzma").compress(b"a" * 100_000))
    assert repos._decompress("Packages.gz", gzip.compress(b"abc") + gzip.compress(b"def")) == b"abcdef"


# ------------------------------------------------------------------ exports
def test_csv_cells_and_download_names():
    assert csv_cell("=HYPERLINK(\"http://evil\")") == "'=HYPERLINK(\"http://evil\")"
    assert csv_cell("-2+3") == "'-2+3" and csv_cell("web1") == "web1" and csv_cell(None) == "" and csv_cell(3) == 3
    assert download_name('a"\r\nX-Evil: 1') == "a___X-Evil__1"


def test_login_cookie_and_flow_cookie_are_not_interchangeable(monkeypatch):
    from diysca.auth import rbac, session

    class Req:
        def __init__(self, v):
            self.cookies = {session.COOKIE: v}
    flow = session.sign({"t": "flow", "u": "mallory", "r": "admin", "state": "s"}, 600)
    assert rbac.user_from_cookie(Req(flow)) is None
    assert rbac.user_from_cookie(Req(session.sign({"u": "old", "r": "admin"}, 600))) is None
    assert rbac.user_from_cookie(Req(session.sign({"t": "login", "u": "alice", "r": "viewer"}, 600))).name == "alice"
    assert os.stat(settings.data_dir).st_mode  # data dir exists
