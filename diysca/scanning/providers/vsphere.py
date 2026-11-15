"""VMware vSphere / vCenter: virtual machines, through the vSphere Automation REST API (vCenter 7.0U2+).

    - type: vsphere
      url: https://vcenter.example.org
      username: diysca-ro@vsphere.local   # a read-only role is enough
      password_env: VC_PASSWORD

The IP address and the guest OS family come from VMware Tools. VMs without Tools are added by name.
"""
from __future__ import annotations

from diysca.scanning.providers import ProviderError, check, host, http, secret


def discover(cfg: dict, transport=None):
    url = str(cfg.get("url", "")).rstrip("/")
    if not url or not cfg.get("username"):
        raise ProviderError("vsphere needs url, username and password / password_env")
    out = []
    with http(cfg, transport, base_url=url) as c:
        r = check(c.post("/api/session", auth=(str(cfg["username"]), secret(cfg, "password"))), "vsphere login")
        c.headers["vmware-api-session-id"] = r.json()
        try:
            params = {"power_states": "POWERED_ON"} if cfg.get("running_only", True) else {}
            for vm in check(c.get("/api/vcenter/vm", params=params), "vsphere list VMs").json():
                ident = {}
                g = c.get(f"/api/vcenter/vm/{vm['vm']}/guest/identity")
                if g.status_code == 200:
                    ident = g.json()
                platform = "windows" if ident.get("family") == "WINDOWS" else ""
                name = vm.get("name") or vm["vm"]
                if cfg.get("address") == "name" and ident.get("host_name"):
                    name = ident["host_name"]
                out.append(host(cfg, name, ident.get("ip_address"), [str(ident.get("family", "")).lower()],
                                platform, vsphere_moid=vm["vm"]))
        finally:
            c.delete("/api/session")
    return out
