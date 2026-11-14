"""Microsoft Azure: virtual machines of one or more subscriptions, through Azure Resource Graph.

    - type: azure
      tenant_id: 00000000-0000-0000-0000-000000000000
      client_id: 11111111-1111-1111-1111-111111111111     # an app registration (service principal) ...
      client_secret_env: AZURE_CLIENT_SECRET
      # ... or managed_identity: true when diysca runs on an Azure VM / AKS / Container Apps
      subscriptions: []                                    # default: every subscription the identity can read
      address: private                                     # private (default) | public | name
      resource_groups: []                                  # optional filter

Role: Reader on the subscriptions (Resource Graph needs nothing else). One query returns every VM with its
NIC addresses and public IPs, across subscriptions. Tags become groups (tag_<key>_<value>), plus the
resource group (rg_<name>) and the region.
"""
from __future__ import annotations

from diysca.scanning.providers import ProviderError, check, host, http, secret, split

ARM = "https://management.azure.com"
LOGIN = "https://login.microsoftonline.com"
IMDS = "http://169.254.169.254/metadata/identity/oauth2/token"

QUERY = """Resources
| where type =~ 'microsoft.compute/virtualmachines'
| extend power = tostring(properties.extended.instanceView.powerState.code),
         osType = tostring(properties.storageProfile.osDisk.osType),
         computerName = tostring(properties.osProfile.computerName)
| mv-expand nic = properties.networkProfile.networkInterfaces
| extend nicId = tolower(tostring(nic.id))
| join kind=leftouter (Resources
    | where type =~ 'microsoft.network/networkinterfaces'
    | mv-expand ipc = properties.ipConfigurations
    | project nicId = tolower(id), privateIp = tostring(ipc.properties.privateIPAddress),
              pipId = tolower(tostring(ipc.properties.publicIPAddress.id))) on nicId
| join kind=leftouter (Resources
    | where type =~ 'microsoft.network/publicipaddresses'
    | project pipId = tolower(id), publicIp = tostring(properties.ipAddress)) on pipId
| project id, name, computerName, resourceGroup, subscriptionId, location, tags, osType, power, privateIp, publicIp"""


def token(cfg: dict, c) -> str:
    if cfg.get("managed_identity"):
        params = {"api-version": "2018-02-01", "resource": ARM + "/"}
        if cfg.get("client_id"):
            params["client_id"] = cfg["client_id"]  # user-assigned identity
        r = check(c.get(IMDS, params=params, headers={"Metadata": "true"}), "azure managed identity")
        return r.json()["access_token"]
    if not (cfg.get("tenant_id") and cfg.get("client_id")):
        raise ProviderError("azure needs tenant_id, client_id and client_secret (or managed_identity: true)")
    r = check(c.post(f"{cfg.get('login_url') or LOGIN}/{cfg['tenant_id']}/oauth2/v2.0/token",
                     data={"grant_type": "client_credentials", "client_id": cfg["client_id"],
                           "client_secret": secret(cfg, "client_secret"), "scope": ARM + "/.default"}),
              "azure login")
    return r.json()["access_token"]


def discover(cfg: dict, transport=None):
    out, seen = [], {}
    rgs = {g.lower() for g in split(cfg.get("resource_groups"))}
    with http(cfg, transport) as c:
        hdr = {"Authorization": f"Bearer {token(cfg, c)}"}
        body: dict = {"query": QUERY, "options": {"resultFormat": "objectArray", "$top": 1000}}
        if split(cfg.get("subscriptions")):
            body["subscriptions"] = split(cfg.get("subscriptions"))
        while True:
            d = check(c.post(ARM + "/providers/Microsoft.ResourceGraph/resources",
                             params={"api-version": "2022-10-01"}, json=body, headers=hdr), "azure resource graph").json()
            for vm in d.get("data", []):
                if rgs and str(vm.get("resourceGroup", "")).lower() not in rgs:
                    continue
                if cfg.get("running_only", True) and vm.get("power") and vm["power"] != "PowerState/running":
                    continue
                want = cfg.get("address", "private")
                ip = (vm.get("publicIp") or None) if want == "public" else (vm.get("privateIp") or None)
                if vm["id"] in seen:  # one row per NIC / IP configuration: the first one with an address wins
                    prev = seen[vm["id"]]
                    if ip and prev.vars.get("ansible_host") == prev.name and want != "name":
                        prev.vars["ansible_host"] = ip
                    continue
                name = vm.get("name")
                if want == "name":
                    name, ip = vm.get("computerName") or name, None
                tags = vm.get("tags") or {}
                groups = [f"rg_{vm.get('resourceGroup', '')}", f"region_{vm.get('location', '')}"] + \
                    [f"tag_{k}_{v}" if v else f"tag_{k}" for k, v in tags.items()]
                h = host(cfg, name, ip, groups, "windows" if vm.get("osType") == "Windows" else "",
                         azure_id=vm["id"], azure_subscription=vm.get("subscriptionId"))
                seen[vm["id"]] = h
                out.append(h)
            skip = d.get("$skipToken")
            if not skip:
                break
            body["options"]["$skipToken"] = skip
    return out
