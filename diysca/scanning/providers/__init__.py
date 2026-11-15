"""Inventory providers: read systems straight from hypervisors, clouds and clusters.

Configured under ``inventory_providers`` (Settings -> Inventory shows what each one found):

    inventory_providers:
      - {type: proxmox, name: pve, url: https://pve1:8006, token_id: "diysca@pve!scan", token_secret_env: PVE_TOKEN}
      - {type: vsphere, name: vc, url: https://vcenter.example.org, username: ro@vsphere.local, password_env: VC_PW}
      - {type: libvirt, name: kvm1, uri: "qemu+ssh://root@kvm1/system"}
      - {type: openstack, name: os, auth_url: https://keystone:5000/v3, application_credential_id: ...,
         application_credential_secret_env: OS_SECRET}
      - {type: kubernetes, name: prod, url: https://k8s-api:6443, token_env: K8S_TOKEN, ca_file: /etc/diysca/k8s-ca.pem}
      - {type: openshift, name: ocp, url: https://api.ocp.example.org:6443, token_env: OCP_TOKEN}
      - {type: aws, name: aws-eu, regions: [eu-central-1], access_key_id_env: AWS_ACCESS_KEY_ID,
         secret_access_key_env: AWS_SECRET_ACCESS_KEY}
      - {type: azure, name: az, tenant_id: ..., client_id: ..., client_secret_env: AZURE_CLIENT_SECRET}
      - {type: gcp, name: gcp, projects: [my-project], credentials_file: /etc/diysca/gcp-sa.json}
      - {type: hetzner, name: hcloud, token_env: HCLOUD_TOKEN}

Options every provider takes:

    user, port, key_file   SSH login diysca uses for the systems found (default: the scanner's defaults)
    address                which address to scan: "ip" (default) or "name" (the DNS name / VM name)
    groups                 extra groups for every system found (always added: the provider type and name)
    include, exclude       name patterns, comma separated ("web-*,db-*")
    running_only           skip stopped VMs (default true)
    verify_tls             true, false or a CA bundle path (default true)

Other clouds (DigitalOcean, OVH, Scaleway, ...): point ``inventories`` at an Ansible inventory plugin config;
diysca reads those through ``ansible-inventory``.
"""
from __future__ import annotations

import importlib
import os
from typing import Callable

import httpx

from diysca.core.config import settings
from diysca.scanning.inventory import InvHost

TYPES = {"proxmox": "proxmox", "vsphere": "vsphere", "libvirt": "libvirt", "kvm": "libvirt",
         "openstack": "openstack", "kubernetes": "kubernetes", "k8s": "kubernetes", "openshift": "kubernetes",
         "aws": "aws", "ec2": "aws", "azure": "azure", "gcp": "gcp", "gce": "gcp", "google": "gcp",
         "hetzner": "hetzner", "hcloud": "hetzner"}


class ProviderError(Exception):
    pass


def split(v) -> list[str]:
    """"a, b" or [a, b] -> [a, b]; empty -> []."""
    items = v if isinstance(v, (list, tuple, set)) else str(v or "").split(",")
    return [str(x).strip() for x in items if str(x).strip()]


def secret(cfg: dict, key: str, default: str = "") -> str:
    """cfg[key], or the environment variable named by cfg[key + "_env"], or a file named by cfg[key + "_file"]."""
    if cfg.get(key + "_env"):
        return os.environ.get(str(cfg[key + "_env"]), default)
    if cfg.get(key + "_file"):
        with open(os.path.expanduser(str(cfg[key + "_file"]))) as fh:
            return fh.read().strip()
    return str(cfg.get(key) or default)


def http(cfg: dict, transport=None, **kw) -> httpx.Client:
    verify = cfg.get("verify_tls", True)
    if verify is True and settings.http_proxy_ca:
        verify = settings.http_proxy_ca
    if transport is not None:
        return httpx.Client(transport=transport, **kw)
    return httpx.Client(timeout=settings.http_timeout, verify=verify, **kw)


def check(r: httpx.Response, what: str) -> httpx.Response:
    if r.status_code >= 400:
        raise ProviderError(f"{what}: HTTP {r.status_code} {r.text[:200]}")
    return r


def label(cfg: dict) -> str:
    return str(cfg.get("name") or cfg.get("type"))


def host(cfg: dict, name: str, ip: str | None, groups: list[str], platform: str = "", **vars_) -> InvHost:
    """An InvHost for a system a provider found, with the provider-wide options applied."""
    addr = name if cfg.get("address") == "name" or not ip else ip
    v = {"ansible_host": addr, **{k: x for k, x in vars_.items() if x not in (None, "")}}
    if cfg.get("user"):
        v["ansible_user"] = cfg["user"]
    if cfg.get("port"):
        v["ansible_port"] = int(cfg["port"])
    if cfg.get("key_file"):
        v["ansible_ssh_private_key_file"] = cfg["key_file"]
    t = str(cfg.get("type") or "").lower()
    g = {t, TYPES.get(t, t), label(cfg), *split(cfg.get("groups") or []), *[x for x in groups if x]}
    if platform == "windows":
        g.add("windows")
    return InvHost(name=name, vars=v, groups={_group(x) for x in g})


def _group(s: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in s.lower())


def _wanted(cfg: dict, h: InvHost) -> bool:
    from fnmatch import fnmatch
    inc, exc = split(cfg.get("include") or []), split(cfg.get("exclude") or [])
    if inc and not any(fnmatch(h.name, p) for p in inc):
        return False
    return not any(fnmatch(h.name, p) for p in exc)


def provider(cfg: dict) -> Callable[..., list[InvHost]]:
    t = TYPES.get(str(cfg.get("type", "")).lower())
    if not t:
        raise ProviderError(f"unknown inventory provider type {cfg.get('type')!r} (known: {', '.join(sorted(TYPES))})")
    return importlib.import_module(f"diysca.scanning.providers.{t}").discover


def discover(cfg: dict, transport=None) -> list[InvHost]:
    hosts = provider(cfg)(cfg, transport=transport)
    seen, out = set(), []
    for h in hosts:
        if h.name in seen or not _wanted(cfg, h):
            continue
        seen.add(h.name)
        out.append(h)
    return out


def source(cfg: dict) -> str:
    return f"provider:{label(cfg)}"
