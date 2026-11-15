"""Scanning selected systems, inventory providers and Windows inventory."""
import base64
import json
from urllib.parse import parse_qs

import httpx
from fastapi.testclient import TestClient

from diysca import mcp
from diysca.core import db
from diysca.core.config import settings
from diysca.scanning import providers, scanner, windows
from diysca.scanning.providers import aws, libvirt


def _hosts():
    for name, groups, enabled in (("web1", "prod,web", 1), ("web2", "test,web", 1), ("db1", "prod,db", 1),
                                  ("old", "prod", 0)):
        db.x("INSERT INTO hosts(name, address, groups, enabled) VALUES (?,?,?,?)", (name, name, groups, enabled))
    return {r["name"]: r["id"] for r in db.q("SELECT id, name FROM hosts")}


def _names(ids):
    return sorted(r["name"] for r in db.q("SELECT name FROM hosts") if r["name"] in
                  {x["name"] for x in db.q("SELECT name, id FROM hosts") if x["id"] in ids})


def test_select_hosts():
    ids = _hosts()
    assert _names(scanner.select_hosts()) == ["db1", "web1", "web2"]  # enabled only
    assert _names(scanner.select_hosts("web*")) == ["web1", "web2"]
    assert _names(scanner.select_hosts("group:prod")) == ["db1", "web1"]
    assert _names(scanner.select_hosts("group:web,!web2")) == ["web1"]
    assert _names(scanner.select_hosts("!web*")) == ["db1"]
    assert _names(scanner.select_hosts(["old", "db1"])) == ["db1", "old"]  # exact name picks a disabled one
    assert _names(scanner.select_hosts(None, [ids["web2"]])) == ["web2"]
    assert scanner.select_hosts("nothing*") == []


def _record(monkeypatch):
    seen = []

    async def fake(client=None, host_ids=None):
        seen.append(sorted(host_ids))
        return [{"host": i} for i in host_ids]
    monkeypatch.setattr(scanner, "scan_all", fake)
    return seen


def test_scan_selected_ui_api_mcp(monkeypatch):
    ids = _hosts()
    seen = _record(monkeypatch)
    from diysca.web import app
    c = TestClient(app)
    page = c.get("/systems").text
    assert "Scan selected" in page and 'class="hsel"' in page
    r = c.post("/scan", data={"selected": "1", "host_id": [str(ids["web1"]), str(ids["db1"])]}, follow_redirects=False)
    assert r.status_code == 303
    assert c.post("/api/scan", params={"hosts": "group:web"}).json() == [{"host": i} for i in sorted([ids["web1"], ids["web2"]])]
    assert c.post("/api/scan", params={"id": [ids["old"]]}).status_code == 200
    assert c.post("/api/scan", params={"hosts": "zzz*"}).status_code == 404
    r = c.post("/api/scan", params={"hosts": "db*", "wait": "false"})
    assert r.status_code == 202 and r.json() == {"started": ["db1"]}
    import asyncio
    ctx = mcp.Context(actor="token:agent", is_token=True)
    asyncio.run(mcp.call("start_scan", {"hosts": "web1"}, ctx))
    assert sorted([ids["web1"], ids["db1"]]) in seen and [ids["old"]] in seen and [ids["web1"]] in seen


def test_scan_respects_scope(monkeypatch):
    ids = _hosts()
    seen = _record(monkeypatch)
    monkeypatch.setattr(settings, "api_tokens", {"ci": {"token": "t1", "role": "operator", "hosts": "group:db"}})
    from diysca.web import app
    c = TestClient(app)
    h = {"Authorization": "Bearer t1"}
    assert c.post("/api/scan", params={"hosts": "*"}, headers=h).status_code == 200
    assert c.post("/api/scan", params={"hosts": "web*"}, headers=h).status_code == 404
    assert seen == [[ids["db1"]]]


def _mock(routes):
    def handler(req: httpx.Request):
        for (method, path), resp in routes.items():
            if req.method == method and req.url.path == path:
                return resp(req) if callable(resp) else httpx.Response(200, json=resp)
        return httpx.Response(404, json={})
    return httpx.MockTransport(handler)


def test_proxmox():
    t = _mock({
        ("GET", "/api2/json/cluster/resources"): {"data": [
            {"type": "qemu", "vmid": 100, "node": "pve1", "name": "web1", "status": "running", "tags": "prod;web"},
            {"type": "qemu", "vmid": 101, "node": "pve1", "name": "win1", "status": "running"},
            {"type": "lxc", "vmid": 200, "node": "pve2", "name": "ct1", "status": "running"},
            {"type": "qemu", "vmid": 102, "node": "pve1", "name": "off", "status": "stopped"}]},
        ("GET", "/api2/json/nodes/pve1/qemu/100/agent/network-get-interfaces"): {"data": {"result": [
            {"name": "lo", "ip-addresses": [{"ip-address": "127.0.0.1", "ip-address-type": "ipv4"}]},
            {"name": "eth0", "ip-addresses": [{"ip-address": "10.0.0.5", "ip-address-type": "ipv4"}]}]}},
        ("GET", "/api2/json/nodes/pve1/qemu/100/config"): {"data": {"ostype": "l26"}},
        ("GET", "/api2/json/nodes/pve1/qemu/101/config"): {"data": {"ostype": "win11"}},
        ("GET", "/api2/json/nodes/pve2/lxc/200/interfaces"): {"data": [{"name": "eth0", "inet": "10.0.1.9/24"}]},
        ("GET", "/api2/json/cluster/status"): {"data": [{"type": "node", "name": "pve1", "ip": "10.0.0.1", "online": 1}]},
    })
    hs = {h.name: h for h in providers.discover({"type": "proxmox", "name": "lab", "url": "https://pve:8006",
                                                 "token_id": "a@pve!b", "token_secret": "x", "nodes": True,
                                                 "user": "root"}, transport=t)}
    assert sorted(hs) == ["ct1", "pve1", "web1", "win1"]
    assert hs["web1"].address == "10.0.0.5" and hs["web1"].user == "root"
    assert {"proxmox", "lab", "prod", "web", "pve_pve1"} <= hs["web1"].groups
    assert "windows" in hs["win1"].groups and hs["win1"].address == "win1"
    assert hs["ct1"].address == "10.0.1.9" and "lxc" in hs["ct1"].groups


def test_vsphere_openstack_kubernetes():
    vs = _mock({("POST", "/api/session"): "sess", ("DELETE", "/api/session"): {},
                ("GET", "/api/vcenter/vm"): [{"vm": "vm-1", "name": "app1"}, {"vm": "vm-2", "name": "dc1"}],
                ("GET", "/api/vcenter/vm/vm-1/guest/identity"): {"ip_address": "10.1.0.1", "family": "LINUX"},
                ("GET", "/api/vcenter/vm/vm-2/guest/identity"): {"ip_address": "10.1.0.2", "family": "WINDOWS"}})
    hs = {h.name: h for h in providers.discover({"type": "vsphere", "url": "https://vc", "username": "u",
                                                 "password": "p"}, transport=vs)}
    assert hs["app1"].address == "10.1.0.1" and "windows" in hs["dc1"].groups

    def token(req):
        body = json.loads(req.content)
        assert body["auth"]["identity"]["methods"] == ["application_credential"]
        return httpx.Response(201, headers={"X-Subject-Token": "tok"}, json={"token": {"catalog": [
            {"type": "compute", "endpoints": [{"interface": "public", "region": "R1", "url": "https://nova/v2.1"}]}]}})
    osx = _mock({("POST", "/v3/auth/tokens"): token,
                 ("GET", "/v2.1/servers/detail"): {"servers": [
                     {"id": "s1", "name": "api1", "status": "ACTIVE", "metadata": {"groups": "api,prod"},
                      "addresses": {"net": [{"version": 4, "addr": "192.168.0.4", "OS-EXT-IPS:type": "fixed"},
                                            {"version": 4, "addr": "203.0.113.4", "OS-EXT-IPS:type": "floating"}]}},
                     {"id": "s2", "name": "down", "status": "SHUTOFF", "addresses": {}}]}})
    hs = providers.discover({"type": "openstack", "auth_url": "https://keystone:5000", "region": "R1",
                             "application_credential_id": "id", "application_credential_secret": "s"}, transport=osx)
    assert [(h.name, h.address) for h in hs] == [("api1", "203.0.113.4")] and "api" in hs[0].groups

    k8s = _mock({("GET", "/api/v1/nodes"): {"items": [
        {"metadata": {"name": "worker-1", "labels": {"node-role.kubernetes.io/worker": "",
                                                     "topology.kubernetes.io/zone": "eu-1a"}},
         "status": {"conditions": [{"type": "Ready", "status": "True"}],
                    "addresses": [{"type": "InternalIP", "address": "10.2.0.1"}],
                    "nodeInfo": {"operatingSystem": "linux", "osImage": "Red Hat Enterprise Linux CoreOS"}}},
        {"metadata": {"name": "nr"}, "status": {"conditions": [{"type": "Ready", "status": "False"}]}}]}})
    hs = providers.discover({"type": "openshift", "name": "ocp", "url": "https://api:6443", "token": "t",
                             "user": "core"}, transport=k8s)
    assert [h.name for h in hs] == ["worker-1"]
    assert {"openshift", "ocp", "role_worker", "zone_eu-1a"} <= hs[0].groups and hs[0].user == "core"


def test_libvirt_and_filters():
    out = {"list": "vm1\nvm2\nwin\n", "dumpxml win": "<domain><metadata><libosinfo:os id='http://microsoft.com/win/11'/>"
           "</metadata><os>", "dumpxml": "<domain><os>"}

    def run(args):
        if args[2] == "list":
            return out["list"]
        if args[2] == "domifaddr":
            if args[3] == "vm1" and args[5] == "lease":
                return " vnet0  52:54:00:aa  ipv4  192.168.122.10/24\n"
            if args[3] == "vm2" and args[5] == "agent":
                return " eth0  52:54:00:bb  ipv4  192.168.122.11/24\n"
            return ""
        return out.get(f"dumpxml {args[3]}", out["dumpxml"])
    hs = {h.name: h for h in libvirt.discover({"type": "libvirt", "uri": "qemu+ssh://root@kvm1/system",
                                               "hypervisor": True}, run=run)}
    assert hs["vm1"].address == "192.168.122.10" and hs["vm2"].address == "192.168.122.11"
    assert "windows" in hs["win"].groups and "kvm1" in hs and "kvm_kvm1" in hs["vm1"].groups
    import diysca.scanning.providers.libvirt as lv
    orig = lv.discover
    try:
        lv.discover = lambda cfg, transport=None: orig(cfg, run=run)
        assert [h.name for h in providers.discover({"type": "kvm", "uri": "qemu:///system", "include": "vm*",
                                                    "exclude": "vm2"})] == ["vm1"]
    finally:
        lv.discover = orig


def test_aws_sigv4_and_parse():
    import datetime
    # AWS's published SigV4 test vector values are for other services; check the shape and determinism here
    now = datetime.datetime(2024, 1, 2, 3, 4, 5, tzinfo=datetime.UTC)
    h1 = aws.signed_headers("GET", "ec2.eu-central-1.amazonaws.com", "eu-central-1", "Action=DescribeInstances",
                            "AKID", "SECRET", now=now)
    assert h1["x-amz-date"] == "20240102T030405Z"
    assert h1["authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKID/20240102/eu-central-1/ec2/aws4_request")
    assert h1 == aws.signed_headers("GET", "ec2.eu-central-1.amazonaws.com", "eu-central-1",
                                    "Action=DescribeInstances", "AKID", "SECRET", now=now)
    xml = """<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><reservationSet><item>
      <instancesSet><item><instanceId>i-1</instanceId><privateIpAddress>172.31.0.5</privateIpAddress>
      <placement><availabilityZone>eu-central-1a</availabilityZone></placement>
      <tagSet><item><key>Name</key><value>api</value></item><item><key>env</key><value>prod</value></item></tagSet>
      </item><item><instanceId>i-2</instanceId><privateIpAddress>172.31.0.6</privateIpAddress><platform>windows</platform>
      </item></instancesSet></item></reservationSet></DescribeInstancesResponse>"""
    seen = {}

    def handler(req):
        seen.update(dict(req.url.params))
        assert req.headers["authorization"].startswith("AWS4-HMAC-SHA256")
        return httpx.Response(200, text=xml)
    hs = providers.discover({"type": "aws", "regions": "eu-central-1", "access_key_id": "A",
                             "secret_access_key": "S"}, transport=httpx.MockTransport(handler))
    assert seen["Filter.1.Name"] == "instance-state-name" and seen["Filter.1.Value.1"] == "running"
    assert [(h.name, h.address) for h in hs] == [("api", "172.31.0.5"), ("i-2", "172.31.0.6")]
    assert "tag_env_prod" in hs[0].groups and "windows" in hs[1].groups


def test_import_providers(monkeypatch):
    t = _mock({("GET", "/api/v1/nodes"): {"items": [
        {"metadata": {"name": "n1", "labels": {}}, "status": {"conditions": [{"type": "Ready", "status": "True"}],
                                                              "addresses": [{"type": "InternalIP", "address": "10.9.0.1"}]}}]}})
    real = providers.discover
    monkeypatch.setattr(providers, "discover", lambda cfg, transport=None: real(cfg, transport=t))
    monkeypatch.setattr(settings, "inventory_providers", [{"type": "kubernetes", "name": "k", "url": "https://k", "token": "x"},
                                                          {"type": "nope"}])
    assert scanner.import_inventories() == 1
    h = db.q1("SELECT * FROM hosts WHERE name='n1'")
    assert h["address"] == "10.9.0.1" and h["source"] == "provider:k" and "kubernetes" in h["groups"]
    assert scanner.inventory_status["provider:k"]["ok"] and not scanner.inventory_status["provider:nope"]["ok"]
    from diysca.web import app
    page = TestClient(app).get("/settings/inventory").text
    assert "provider:k" in page or "kubernetes" in page


def test_windows_parse():
    out = json.dumps({"caption": "Microsoft Windows Server 2022 Standard", "version": "10.0.20348", "build": "20348",
                      "ubr": 2340, "display": "21H2", "arch": "64-bit", "host": "DC1", "kb": ["KB5034129", "KB5033118"],
                      "apps": [{"n": "7-Zip 23.01", "v": "23.01", "p": "Igor Pavlov"},
                               {"n": "7-Zip 23.01", "v": "23.01", "p": "Igor Pavlov"}]})
    f = windows.parse("#< CLIXML\r\n" + out)
    assert f.os_id == "windows" and f.kernel == "20348.2340" and "Windows Server 2022 Standard" in f.os_pretty
    assert [p.type for p in f.packages] == ["kb", "kb", "win"]
    assert windows.script().startswith("powershell -NoProfile")
    assert windows.is_windows({"groups": "windows,prod", "os_id": None, "connection": "ssh"})
    assert not windows.is_windows({"groups": "prod", "os_id": "debian", "connection": "ssh"})


def test_hetzner():
    def handler(req):
        assert req.headers["authorization"] == "Bearer ht" and req.url.params["status"] == "running"
        page = int(req.url.params["page"])
        srv = {1: [{"id": 1, "name": "fsn-web", "labels": {"env": "prod"}, "image": {"os_flavor": "debian"},
                    "public_net": {"ipv4": {"ip": "49.12.0.1"}}, "private_net": [{"network": 7, "ip": "10.0.0.2"}],
                    "datacenter": {"location": {"name": "fsn1"}}}],
               2: [{"id": 2, "name": "hel-db", "public_net": {"ipv4": None}, "private_net": [{"network": 7, "ip": "10.0.0.3"}]}]}
        return httpx.Response(200, json={"servers": srv[page], "meta": {"pagination": {"next_page": 2 if page == 1 else None}}})
    hs = providers.discover({"type": "hcloud", "name": "hc", "token": "ht"}, transport=httpx.MockTransport(handler))
    assert [(h.name, h.address) for h in hs] == [("fsn-web", "49.12.0.1"), ("hel-db", "10.0.0.3")]
    assert {"hetzner", "hc", "label_env_prod", "location_fsn1", "debian"} <= hs[0].groups
    hs = providers.discover({"type": "hetzner", "token": "ht", "address": "private"}, transport=httpx.MockTransport(handler))
    assert hs[0].address == "10.0.0.2"


def test_azure():
    calls = []

    def handler(req):
        calls.append(req.url.path)
        if req.url.host == "login.microsoftonline.com":
            assert b"client_credentials" in req.content and "/tenant1/" in req.url.path
            return httpx.Response(200, json={"access_token": "az"})
        assert req.headers["authorization"] == "Bearer az"
        body = json.loads(req.content)
        assert body["subscriptions"] == ["sub1"] and "virtualmachines" in body["query"]
        if "$skipToken" not in body["options"]:
            return httpx.Response(200, json={"$skipToken": "next", "data": [
                {"id": "/vm/1", "name": "app", "resourceGroup": "RG-Prod", "location": "westeurope", "tags": {"env": "prod"},
                 "osType": "Linux", "power": "PowerState/running", "privateIp": "", "publicIp": ""},
                {"id": "/vm/1", "name": "app", "resourceGroup": "RG-Prod", "location": "westeurope", "tags": {},
                 "osType": "Linux", "power": "PowerState/running", "privateIp": "10.1.0.4", "publicIp": "20.1.1.1"}]})
        return httpx.Response(200, json={"data": [
            {"id": "/vm/2", "name": "dc", "resourceGroup": "rg-prod", "location": "westeurope", "osType": "Windows",
             "power": "PowerState/running", "privateIp": "10.1.0.5"},
            {"id": "/vm/3", "name": "off", "resourceGroup": "rg-prod", "power": "PowerState/deallocated", "privateIp": "10.1.0.6"}]})
    hs = providers.discover({"type": "azure", "tenant_id": "tenant1", "client_id": "c", "client_secret": "s",
                             "subscriptions": ["sub1"]}, transport=httpx.MockTransport(handler))
    assert [(h.name, h.address) for h in hs] == [("app", "10.1.0.4"), ("dc", "10.1.0.5")]
    assert {"azure", "rg_rg-prod", "region_westeurope", "tag_env_prod"} <= hs[0].groups and "windows" in hs[1].groups


def test_gcp_service_account():
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from diysca.scanning.providers import gcp
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    sa = {"type": "service_account", "client_email": "scan@p.iam.gserviceaccount.com", "private_key": pem,
          "private_key_id": "k1", "token_uri": "https://oauth2.googleapis.com/token"}

    def handler(req):
        if req.url.host == "oauth2.googleapis.com":
            assertion = parse_qs(req.content.decode())["assertion"][0]
            head, claims, sig = assertion.split(".")
            pad = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
            key.public_key().verify(pad(sig), f"{head}.{claims}".encode(), padding.PKCS1v15(), hashes.SHA256())
            assert json.loads(pad(claims))["iss"] == sa["client_email"]
            return httpx.Response(200, json={"access_token": "g"})
        assert req.headers["authorization"] == "Bearer g" and 'status = "RUNNING"' in req.url.params["filter"]
        return httpx.Response(200, json={"items": {
            "zones/europe-west3-a": {"instances": [
                {"id": "1", "name": "web", "zone": ".../zones/europe-west3-a", "labels": {"env": "prod"},
                 "tags": {"items": ["http"]}, "networkInterfaces": [{"networkIP": "10.2.0.2",
                                                                     "accessConfigs": [{"natIP": "34.1.1.1"}]}],
                 "disks": [{"licenses": [".../debian-cloud/global/licenses/debian-12"]}]},
                {"id": "2", "name": "win", "zone": ".../zones/europe-west3-a",
                 "networkInterfaces": [{"networkIP": "10.2.0.3"}],
                 "disks": [{"licenses": [".../windows-cloud/global/licenses/windows-server-2022"]}]}]},
            "zones/us-east1-b": {"warning": {"code": "NO_RESULTS_ON_PAGE"}}}})
    hs = providers.discover({"type": "gcp", "projects": "p1", "credentials": sa}, transport=httpx.MockTransport(handler))
    assert [(h.name, h.address) for h in hs] == [("web", "10.2.0.2"), ("win", "10.2.0.3")]
    assert {"gcp", "project_p1", "zone_europe-west3-a", "label_env_prod", "tag_http"} <= hs[0].groups
    assert "windows" in hs[1].groups


def test_nvd_is_time_boxed_and_prioritised(monkeypatch):
    import asyncio
    from diysca.scanning import feeds
    ids = _hosts()
    for hid, cve, sev in ((ids["db1"], "CVE-2024-0001", "HIGH"), (ids["web1"], "CVE-2024-0002", "UNKNOWN"),
                          (ids["web1"], "CVE-2024-0003", "LOW"), (ids["db1"], "CVE-2024-0004", None)):
        db.x("""INSERT INTO findings(host_id, vuln_id, cve, package, version, severity, status, first_seen, last_seen)
                VALUES (?,?,?,?,?,?,'open',?,?)""", (hid, cve, cve, "p", "1", sev, db.now(), db.now()))
    assert feeds.nvd_pending([ids["web1"]]) == ["CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004", "CVE-2024-0001"]
    assert feeds.nvd_pending()[:2] == ["CVE-2024-0002", "CVE-2024-0004"]
    calls = []

    class FakeClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, url, params=None):
            calls.append(params["cveId"])
            return httpx.Response(429 if len(calls) > 2 else 200, json={"vulnerabilities": [{"cve": {
                "descriptions": [{"lang": "en", "value": "x"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}}}]})
    monkeypatch.setattr(feeds.httpx, "AsyncClient", FakeClient)
    monkeypatch.setattr(settings, "nvd_enabled", True)
    sleeps = []

    async def fake_sleep(s):
        sleeps.append(s)
    monkeypatch.setattr(feeds.asyncio, "sleep", fake_sleep)
    n = asyncio.run(feeds.nvd_enrich(host_ids=[ids["web1"]]))
    assert n == 2 and calls == ["CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004"]  # stops at the 429
    assert 30 not in sleeps
    assert db.q1("SELECT severity FROM findings WHERE cve='CVE-2024-0002'")["severity"] == "CRITICAL"
    calls.clear()
    assert asyncio.run(feeds.nvd_enrich(budget=0)) == 1 and len(calls) == 1  # budget 0: one request, then stop


def test_nvd_stops_on_5xx_and_logs(monkeypatch):
    import asyncio
    from diysca.scanning import feeds
    ids = _hosts()
    for i in range(5):
        db.x("""INSERT INTO findings(host_id, vuln_id, cve, package, version, severity, status, first_seen, last_seen)
                VALUES (?,?,?,?,?,?,'open',?,?)""", (ids["db1"], f"CVE-2024-100{i}", f"CVE-2024-100{i}", "p", "1",
                                                     None, db.now(), db.now()))
    calls = []

    class Down:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, url, params=None):
            calls.append(params["cveId"])
            return httpx.Response(503, text="down")

    async def no_sleep(s):
        pass
    monkeypatch.setattr(feeds.httpx, "AsyncClient", Down)
    monkeypatch.setattr(feeds.asyncio, "sleep", no_sleep)
    monkeypatch.setattr(settings, "nvd_enabled", True)
    assert asyncio.run(feeds.nvd_enrich()) == 0 and len(calls) == 2
    msg = db.q1("SELECT message FROM events WHERE kind='feed' ORDER BY id DESC")["message"]
    assert "0 CVEs enriched, 5 still pending, stopped: NVD unavailable (HTTP 503)" in msg and "API key" in msg
