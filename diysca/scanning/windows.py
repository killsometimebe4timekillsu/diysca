"""Windows hosts: inventory over OpenSSH (built into Windows Server 2019+ and Windows 10/11).

What diysca collects: the OS (edition, version, build.UBR), installed updates (KBs) and installed programs
(from the Uninstall registry keys, the "Apps & features" list).

What it does not do yet: match those against Microsoft's security update guide (MSRC). OSV has no
Windows feed, so a Windows host shows its inventory and a note, and has no findings. Programs that are
also in OSV (language runtimes, some open source tools) are not matched either.

A host counts as Windows when it is in the "windows" group (providers put Windows VMs there, so can an
Ansible inventory), or when an earlier scan found Windows. ansible_connection=winrm / psrp hosts are
reached over SSH on port 22 instead: enable OpenSSH Server on them.
"""
from __future__ import annotations

import json

from diysca.scanning.collectors import HostFacts, Package

NOTE = ("Windows: inventory collected (build, updates, programs). CVE matching against Microsoft's security "
        "updates (MSRC) isn't built yet, so this system has no findings.")

_PS = r"""$ErrorActionPreference='SilentlyContinue'
$o=Get-CimInstance Win32_OperatingSystem
$cv=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$kb=@(Get-HotFix | ForEach-Object { $_.HotFixID })
$apps=@(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' |
  Where-Object { $_.DisplayName -and -not $_.SystemComponent } |
  ForEach-Object { @{n=$_.DisplayName; v=[string]$_.DisplayVersion; p=[string]$_.Publisher} })
@{caption=$o.Caption; version=$o.Version; build=$o.BuildNumber; ubr=$cv.UBR; display=$cv.DisplayVersion;
  arch=$o.OSArchitecture; host=$env:COMPUTERNAME; kb=$kb; apps=$apps} | ConvertTo-Json -Depth 4 -Compress"""


def script() -> str:
    import base64
    enc = base64.b64encode(_PS.encode("utf-16-le")).decode()
    return f"powershell -NoProfile -NonInteractive -EncodedCommand {enc}"


def is_windows(h) -> bool:
    groups = {g.strip().lower() for g in (h["groups"] or "").split(",")}
    return "windows" in groups or (h["os_id"] or "") == "windows" or \
        (h["connection"] or "") in ("winrm", "psrp")


def parse(output: str) -> HostFacts:
    start = output.find("{")
    if start < 0:
        raise RuntimeError("no answer from PowerShell (is this a Windows host with OpenSSH Server?)")
    d = json.loads(output[start:])
    build = f"{d.get('build') or ''}.{d.get('ubr')}" if d.get("ubr") is not None else str(d.get("build") or "")
    caption = str(d.get("caption") or "Windows").replace("Microsoft ", "")
    pkgs = [Package(name=str(k), version="installed", type="kb") for k in d.get("kb") or [] if k]
    apps = d.get("apps") or []
    if isinstance(apps, dict):
        apps = [apps]
    seen = set()
    for a in apps:
        key = (a.get("n"), a.get("v"))
        if key in seen:
            continue
        seen.add(key)
        pkgs.append(Package(name=str(a.get("n")), version=str(a.get("v") or ""), source_name=str(a.get("p") or ""),
                            type="win"))
    return HostFacts(os_id="windows", os_version=str(d.get("version") or ""),
                     os_pretty=f"{caption} {d.get('display') or ''} (build {build})".replace("  ", " "),
                     os_codename=str(d.get("display") or ""), hostname=str(d.get("host") or ""),
                     arch=str(d.get("arch") or ""), kernel=build, packages=pkgs)
