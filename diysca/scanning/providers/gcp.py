"""Google Cloud: Compute Engine instances of one or more projects.

    - type: gcp
      projects: [my-project]
      credentials_file: /etc/diysca/gcp-sa.json   # a service account key with roles/compute.viewer ...
      # ... or leave it out when diysca runs on GCE / GKE: the metadata server's service account is used
      address: private                             # private (default) | public | name
      filter: "labels.env=prod"                    # optional, Compute API filter syntax

Labels become groups (label_<key>_<value>), plus the zone and the network tags (tag_<tag>).
"""
from __future__ import annotations

import base64
import json
import time

from diysca.scanning.providers import ProviderError, check, host, http, split

COMPUTE = "https://compute.googleapis.com/compute/v1"
METADATA = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
SCOPE = "https://www.googleapis.com/auth/compute.readonly"


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def service_account_jwt(sa: dict, now: float | None = None) -> str:
    """RS256-signed assertion for the OAuth2 JWT bearer grant (cryptography comes with asyncssh)."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    now = int(now or time.time())
    head = _b64(json.dumps({"alg": "RS256", "typ": "JWT", "kid": sa.get("private_key_id", "")}).encode())
    claims = _b64(json.dumps({"iss": sa["client_email"], "scope": SCOPE, "aud": sa.get("token_uri"),
                              "iat": now, "exp": now + 3600}).encode())
    key = serialization.load_pem_private_key(sa["private_key"].encode(), password=None)
    sig = key.sign(f"{head}.{claims}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{head}.{claims}.{_b64(sig)}"


def token(cfg: dict, c) -> str:
    if cfg.get("credentials_file") or cfg.get("credentials"):
        sa = cfg.get("credentials")
        if not sa:
            import os
            with open(os.path.expanduser(str(cfg["credentials_file"]))) as fh:
                sa = json.load(fh)
        if isinstance(sa, str):
            sa = json.loads(sa)
        if sa.get("type") != "service_account":
            raise ProviderError("gcp: credentials must be a service account key (type: service_account)")
        sa.setdefault("token_uri", "https://oauth2.googleapis.com/token")
        r = check(c.post(sa["token_uri"], data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                                "assertion": service_account_jwt(sa)}), "gcp login")
        return r.json()["access_token"]
    r = c.get(METADATA, headers={"Metadata-Flavor": "Google"})
    if r.status_code != 200:
        raise ProviderError("gcp needs credentials_file, or must run on GCE / GKE with a service account")
    return r.json()["access_token"]


def discover(cfg: dict, transport=None):
    projects = split(cfg.get("projects") or cfg.get("project"))
    if not projects:
        raise ProviderError("gcp needs projects")
    out = []
    with http(cfg, transport) as c:
        hdr = {"Authorization": f"Bearer {token(cfg, c)}"}
        for proj in projects:
            params = {"maxResults": 500}
            filt = [f"({cfg['filter']})"] if cfg.get("filter") else []
            if cfg.get("running_only", True):
                filt.append('(status = "RUNNING")')
            if filt:
                params["filter"] = " AND ".join(filt)
            while True:
                d = check(c.get(f"{COMPUTE}/projects/{proj}/aggregated/instances", params=params, headers=hdr),
                          f"gcp {proj} instances").json()
                for scoped in (d.get("items") or {}).values():
                    for vm in scoped.get("instances", []):
                        nic = (vm.get("networkInterfaces") or [{}])[0]
                        priv = nic.get("networkIP")
                        pub = next((a.get("natIP") for a in nic.get("accessConfigs", []) if a.get("natIP")), None)
                        want = cfg.get("address", "private")
                        ip = pub if want == "public" else priv
                        zone = str(vm.get("zone", "")).rsplit("/", 1)[-1]
                        name = vm["name"]
                        if want == "name":
                            name, ip = f"{vm['name']}.{zone}.c.{proj}.internal", None
                        licenses = " ".join(lic for disk in vm.get("disks", []) for lic in disk.get("licenses", []))
                        platform = "windows" if "windows-cloud" in licenses else ""
                        groups = [f"project_{proj}", f"zone_{zone}"] + \
                            [f"label_{k}_{v}" if v else f"label_{k}" for k, v in (vm.get("labels") or {}).items()] + \
                            [f"tag_{t}" for t in (vm.get("tags") or {}).get("items", [])]
                        out.append(host(cfg, name, ip, groups, platform, gcp_id=vm.get("id"), gcp_project=proj))
                if not d.get("nextPageToken"):
                    break
                params["pageToken"] = d["nextPageToken"]
    return out
