"""KVM / libvirt: domains of one or more libvirt hosts, read with virsh (local or qemu+ssh://).

    - type: libvirt
      uri: "qemu+ssh://root@kvm1.example.org/system"   # or a list: uris: [...]
      hypervisor: true                                  # also scan the KVM host itself

Addresses: virsh domifaddr (DHCP lease, then the guest agent, then ARP). Needs the libvirt client
(virsh) where diysca runs, and for qemu+ssh an SSH key that the libvirt host accepts.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from urllib.parse import urlparse

from diysca.scanning.providers import ProviderError, host, split

Runner = "callable(args: list[str]) -> str"


def _virsh(args: list[str]) -> str:
    exe = shutil.which("virsh")
    if not exe:
        raise ProviderError("libvirt provider: virsh is not installed (package libvirt-clients / libvirt-client)")
    r = subprocess.run([exe, *args], capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise ProviderError(f"virsh {' '.join(args[:3])}: {r.stderr.strip()[:200]}")
    return r.stdout


_ADDR = re.compile(r"\s(ipv4)\s+(\d+\.\d+\.\d+\.\d+)/\d+")


def discover(cfg: dict, transport=None, run=None):
    run = run or _virsh
    uris = split(cfg.get("uris") or cfg.get("uri") or "qemu:///system")
    out = []
    for uri in uris:
        kvm = urlparse(uri).hostname or "localhost"
        flag = [] if cfg.get("running_only", True) is False else ["--state-running"]
        names = [n.strip() for n in run(["-c", uri, "list", "--name", *(flag or ["--all"])]).splitlines() if n.strip()]
        for name in names:
            ip = None
            for src in ("lease", "agent", "arp"):
                try:
                    m = _ADDR.search(run(["-c", uri, "domifaddr", "--domain", name, "--source", src]))
                except ProviderError:
                    continue
                if m and not m.group(2).startswith("127."):
                    ip = m.group(2)
                    break
            platform = ""
            try:
                if "microsoft.com/win" in run(["-c", uri, "dumpxml", "--domain", name]):  # libosinfo id in the domain metadata
                    platform = "windows"
            except ProviderError:
                pass
            out.append(host(cfg, name, ip, [f"kvm_{kvm}"], platform, libvirt_uri=uri))
        if cfg.get("hypervisor") and kvm != "localhost":
            out.append(host(cfg, kvm, None, ["kvm_hypervisors"]))
    return out
