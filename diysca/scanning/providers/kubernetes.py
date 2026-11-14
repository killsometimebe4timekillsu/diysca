"""Kubernetes and OpenShift: the cluster nodes, so diysca scans their OS and the containers running on them.

    - type: kubernetes          # or openshift
      url: https://k8s-api.example.org:6443
      token_env: K8S_TOKEN      # a service account token with get/list on nodes
      ca_file: /etc/diysca/k8s-ca.pem
      # or: kubeconfig: ~/.kube/config  (context: prod)

Every node becomes a system (InternalIP, or ExternalIP with address: external). With scan_containers on,
diysca finds the running containers on each node through crictl (containerd / CRI-O) and scans one per
image, which is how running pods get checked. The SSH user needs to run crictl: container_sudo: true.

OpenShift nodes run RHCOS: the rpm database is read like on RHEL. OpenShift usually allows SSH only as
"core" with a key from the install config: user: core.
"""
from __future__ import annotations

import base64
import os
import tempfile

import yaml

from diysca.scanning.providers import ProviderError, check, host, http, secret


def _from_kubeconfig(cfg: dict) -> dict:
    path = os.path.expanduser(str(cfg["kubeconfig"]))
    with open(path) as fh:
        kc = yaml.safe_load(fh)
    ctx_name = cfg.get("context") or kc.get("current-context")
    ctx = next((c["context"] for c in kc.get("contexts", []) if c["name"] == ctx_name), None)
    if not ctx:
        raise ProviderError(f"kubeconfig: context {ctx_name!r} not found")
    cl = next(c["cluster"] for c in kc["clusters"] if c["name"] == ctx["cluster"])
    us = next((u["user"] for u in kc.get("users", []) if u["name"] == ctx.get("user")), {})
    out = {"url": cl["server"], "token": us.get("token", "")}
    if cl.get("certificate-authority"):
        out["ca_file"] = cl["certificate-authority"]
    elif cl.get("certificate-authority-data"):
        f = tempfile.NamedTemporaryFile("wb", suffix=".pem", delete=False)
        f.write(base64.b64decode(cl["certificate-authority-data"]))
        f.close()
        out["ca_file"] = f.name
    if cl.get("insecure-skip-tls-verify"):
        out["verify_tls"] = False
    if not out["token"]:
        raise ProviderError("kubeconfig: only token users are supported (use a service account token)")
    return out


def discover(cfg: dict, transport=None):
    if cfg.get("kubeconfig"):
        cfg = {**cfg, **_from_kubeconfig(cfg)}
    url = str(cfg.get("url", "")).rstrip("/")
    if not url:
        raise ProviderError(f"{cfg.get('type')} needs url + token (or kubeconfig)")
    if cfg.get("ca_file") and cfg.get("verify_tls", True) is True:
        cfg = {**cfg, "verify_tls": cfg["ca_file"]}
    want = "ExternalIP" if cfg.get("address") == "external" else "InternalIP"
    out = []
    with http(cfg, transport, headers={"Authorization": f"Bearer {secret(cfg, 'token')}"}) as c:
        nodes = check(c.get(url + "/api/v1/nodes"), f"{cfg.get('type')} list nodes").json().get("items", [])
    for n in nodes:
        md, st = n.get("metadata", {}), n.get("status", {})
        ready = any(x.get("type") == "Ready" and x.get("status") == "True" for x in st.get("conditions", []))
        if cfg.get("running_only", True) and not ready:
            continue
        addrs = {a["type"]: a["address"] for a in st.get("addresses", [])}
        labels = md.get("labels", {})
        roles = [k.split("/", 1)[1] for k in labels if k.startswith("node-role.kubernetes.io/")]
        info = st.get("nodeInfo", {})
        platform = "windows" if info.get("operatingSystem") == "windows" else ""
        name = md.get("name")
        groups = [f"role_{r}" for r in roles]
        if labels.get("topology.kubernetes.io/zone"):
            groups.append(f"zone_{labels['topology.kubernetes.io/zone']}")
        out.append(host(cfg, name, addrs.get(want) or addrs.get("InternalIP"), groups, platform,
                        k8s_os_image=info.get("osImage")))
    return out
