"""Hetzner Cloud: servers of a project (Hetzner Cloud API).

    - type: hetzner
      token_env: HCLOUD_TOKEN          # a read-only API token of the project
      address: public                  # public (default) | private | name
      network: ""                      # with address: private, the private network to use (name or id)
      label_selector: "env=prod"       # optional, Hetzner label selector syntax

Labels become groups (label_<key>_<value>), plus the location (location_fsn1).
"""
from __future__ import annotations

from diysca.scanning.providers import ProviderError, check, host, http, secret

API = "https://api.hetzner.cloud/v1"


def discover(cfg: dict, transport=None):
    token = secret(cfg, "token")
    if not token:
        raise ProviderError("hetzner needs token (or token_env / token_file)")
    out, page = [], 1
    with http(cfg, transport, headers={"Authorization": f"Bearer {token}"}) as c:
        while page:
            params = {"page": page, "per_page": 50}
            if cfg.get("label_selector"):
                params["label_selector"] = cfg["label_selector"]
            if cfg.get("running_only", True):
                params["status"] = "running"
            d = check(c.get(str(cfg.get("api_url") or API).rstrip("/") + "/servers", params=params),
                      "hetzner servers").json()
            for s in d.get("servers", []):
                pub = ((s.get("public_net") or {}).get("ipv4") or {}).get("ip")
                privs = s.get("private_net") or []
                want = str(cfg.get("network") or "")
                priv = next((p.get("ip") for p in privs if not want or str(p.get("network")) == want), None)
                ip = priv if cfg.get("address") == "private" else pub or priv
                loc = (((s.get("datacenter") or {}).get("location")) or {}).get("name", "")
                flavor = ((s.get("image") or {}).get("os_flavor")) or ""
                groups = [f"location_{loc}" if loc else "", flavor] + \
                    [f"label_{k}_{v}" if v else f"label_{k}" for k, v in (s.get("labels") or {}).items()]
                out.append(host(cfg, s["name"], ip, groups, hcloud_id=s.get("id")))
            page = ((d.get("meta") or {}).get("pagination") or {}).get("next_page")
    return out
