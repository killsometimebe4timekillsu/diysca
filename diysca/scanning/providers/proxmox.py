"""Proxmox VE: QEMU VMs and LXC containers of a cluster (and optionally the PVE nodes themselves).

    - type: proxmox
      url: https://pve1.example.org:8006
      token_id: "diysca@pve!scan"        # API token, role PVEAuditor is enough (plus VM.Monitor for guest agent IPs)
      token_secret_env: PVE_TOKEN
      nodes: true                        # also the PVE nodes (Debian, scannable like any host)

IP addresses come from the QEMU guest agent (VMs) and from the container interfaces (LXC). VMs without the
agent are added by name, so DNS has to resolve them (or set address: name).
"""
from __future__ import annotations

from diysca.scanning.providers import ProviderError, check, host, http, secret


def _ipv4(ifaces) -> str | None:
    for i in ifaces or []:
        if i.get("name") in ("lo", "lo0") or "Loopback" in str(i.get("name", "")):
            continue
        for a in i.get("ip-addresses") or []:
            ip = a.get("ip-address", "")
            if a.get("ip-address-type") == "ipv4" and not ip.startswith(("127.", "169.254.")):
                return ip
        ip = (i.get("inet") or "").split("/")[0]  # LXC interfaces
        if ip and not ip.startswith("127."):
            return ip
    return None


def discover(cfg: dict, transport=None):
    url = str(cfg.get("url", "")).rstrip("/")
    if not url or not cfg.get("token_id"):
        raise ProviderError("proxmox needs url and token_id (+ token_secret / token_secret_env)")
    auth = {"Authorization": f"PVEAPIToken={cfg['token_id']}={secret(cfg, 'token_secret')}"}
    out = []
    with http(cfg, transport, base_url=url + "/api2/json", headers=auth) as c:
        res = check(c.get("/cluster/resources", params={"type": "vm"}), "proxmox cluster/resources").json()["data"]
        for vm in res:
            if vm.get("template"):
                continue
            if cfg.get("running_only", True) and vm.get("status") != "running":
                continue
            kind = vm.get("type")  # qemu | lxc
            path = f"/nodes/{vm['node']}/{kind}/{vm['vmid']}"
            ip, platform = None, ""
            try:
                if kind == "qemu":
                    r = c.get(path + "/agent/network-get-interfaces")
                    if r.status_code == 200:
                        ip = _ipv4(r.json()["data"].get("result"))
                    conf = c.get(path + "/config")
                    if conf.status_code == 200 and str(conf.json()["data"].get("ostype", "")).startswith("win"):
                        platform = "windows"
                else:
                    r = c.get(path + "/interfaces")
                    if r.status_code == 200:
                        ip = _ipv4(r.json()["data"])
            except (KeyError, ValueError):
                pass
            tags = [t for t in str(vm.get("tags") or "").replace(",", ";").split(";") if t]
            out.append(host(cfg, vm.get("name") or f"vm{vm['vmid']}", ip,
                            [f"pve_{vm['node']}", "lxc" if kind == "lxc" else "vm", *tags], platform,
                            proxmox_vmid=vm["vmid"], proxmox_node=vm["node"]))
        if cfg.get("nodes"):
            for n in check(c.get("/cluster/status"), "proxmox cluster/status").json()["data"]:
                if n.get("type") == "node" and n.get("online", 1):
                    out.append(host(cfg, n["name"], n.get("ip"), ["pve_nodes"]))
    return out
