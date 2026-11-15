"""OpenStack: Nova servers of a project, through Keystone v3 and the compute API.

    - type: openstack
      auth_url: https://keystone.example.org:5000/v3
      application_credential_id: 3f2c...           # preferred: a read-only application credential
      application_credential_secret_env: OS_APP_SECRET
      # or password auth:
      # username: diysca, password_env: OS_PASSWORD, project_name: prod,
      # user_domain_name: Default, project_domain_name: Default
      region: RegionOne
      interface: public                             # endpoint interface: public | internal | admin
      network: ""                                   # prefer addresses on this network

Address: the floating IP if there is one, else the first fixed IPv4. Server metadata "groups" (comma
separated, like the Ansible openstack plugin) becomes groups.
"""
from __future__ import annotations

from diysca.scanning.providers import ProviderError, check, host, http, secret


def _auth_body(cfg: dict) -> dict:
    if cfg.get("application_credential_id"):
        return {"auth": {"identity": {"methods": ["application_credential"], "application_credential": {
            "id": cfg["application_credential_id"], "secret": secret(cfg, "application_credential_secret")}}}}
    if not cfg.get("username"):
        raise ProviderError("openstack needs application_credential_id or username / password")
    body = {"auth": {"identity": {"methods": ["password"], "password": {"user": {
        "name": cfg["username"], "password": secret(cfg, "password"),
        "domain": {"name": cfg.get("user_domain_name", "Default")}}}}}}
    if cfg.get("project_id"):
        body["auth"]["scope"] = {"project": {"id": cfg["project_id"]}}
    elif cfg.get("project_name"):
        body["auth"]["scope"] = {"project": {"name": cfg["project_name"],
                                             "domain": {"name": cfg.get("project_domain_name", "Default")}}}
    return body


def _endpoint(catalog: list, cfg: dict) -> str:
    want_if, region = cfg.get("interface", "public"), cfg.get("region")
    for svc in catalog:
        if svc.get("type") != "compute":
            continue
        for ep in svc.get("endpoints", []):
            if ep.get("interface") == want_if and (not region or region in (ep.get("region"), ep.get("region_id"))):
                return ep["url"].rstrip("/")
    raise ProviderError(f"openstack: no compute endpoint ({want_if}, region {region or 'any'}) in the catalog")


def _address(server: dict, network: str = "") -> str | None:
    nets = server.get("addresses") or {}
    order = ([network] if network in nets else []) + [n for n in nets if n != network]
    fixed = None
    for n in order:
        for a in nets[n]:
            if a.get("version") != 4:
                continue
            if a.get("OS-EXT-IPS:type") == "floating":
                return a["addr"]
            fixed = fixed or a.get("addr")
    return fixed or server.get("accessIPv4") or None


def discover(cfg: dict, transport=None):
    auth_url = str(cfg.get("auth_url", "")).rstrip("/")
    if not auth_url:
        raise ProviderError("openstack needs auth_url (Keystone v3)")
    if not auth_url.endswith("/v3"):
        auth_url += "/v3"
    out = []
    with http(cfg, transport) as c:
        r = check(c.post(auth_url + "/auth/tokens", json=_auth_body(cfg)), "openstack login")
        token = r.headers.get("X-Subject-Token")
        nova = cfg.get("compute_url") or _endpoint(r.json()["token"].get("catalog", []), cfg)
        url, params = nova + "/servers/detail", {"limit": 500}
        while url:
            page = check(c.get(url, params=params, headers={"X-Auth-Token": token}), "openstack servers").json()
            for s in page.get("servers", []):
                if cfg.get("running_only", True) and s.get("status") != "ACTIVE":
                    continue
                md = s.get("metadata") or {}
                groups = [g for g in str(md.get("groups", "")).split(",") if g]
                platform = "windows" if "windows" in str(md.get("os_type", md.get("os_distro", ""))).lower() else ""
                out.append(host(cfg, s["name"], _address(s, cfg.get("network", "")),
                                [f"az_{s.get('OS-EXT-AZ:availability_zone', '')}" if s.get("OS-EXT-AZ:availability_zone") else "",
                                 *groups], platform, openstack_id=s["id"]))
            nxt = [link["href"] for link in page.get("servers_links", []) if link.get("rel") == "next"]
            url, params = (nxt[0], None) if nxt else (None, None)
    return out
