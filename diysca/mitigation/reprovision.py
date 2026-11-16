"""Reprovision a system from its SBOM.

Takes a CycloneDX SBOM (one from diysca, or any other tool that writes
package URLs) and turns it into an Ansible playbook that rebuilds the same
system on a fresh install of the same OS release:

1. checks that the target runs the same distribution and major version
2. adds the repositories the original system had (diysca SBOMs only)
3. installs the OS packages at the recorded versions
4. installs pip and gem packages at the recorded versions
5. pulls the container images that were running

Modes:
  exact  every package at the version in the SBOM
  fixed  the same, except packages with an open vulnerability whose fix is in
         the repos, which get the repo candidate version instead (default;
         needs a diysca SBOM, falls back to exact for others)

npm, Maven, Composer, Cargo and Go dependencies belong to an application's
own build and are listed as comments.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from urllib.parse import unquote

import yaml

from diysca import __version__
from diysca.core import db
from diysca.mitigation import pbsafe
from diysca.scanning.sbom import build_sbom


_Dumper = pbsafe.Dumper

SUSE = ("sles", "sled", "sles_sap", "opensuse-leap", "opensuse-tumbleweed", "suse", "opensuse")
FAMILY = {"debian": "Debian", "ubuntu": "Ubuntu", "rhel": "RedHat", "rocky": "Rocky", "almalinux": "AlmaLinux",
          "centos": "CentOS", "ol": "OracleLinux", "sles": "SLES", "sles_sap": "SLES_SAP", "opensuse-leap": "openSUSE Leap",
          "alpine": "Alpine"}


def parse_purl(p: str) -> dict | None:
    m = re.match(r"^pkg:([a-z0-9.+-]+)/(.+?)@([^?#]+)(?:\?([^#]*))?", p or "")
    if not m:
        return None
    t, path, ver, q = m.groups()
    parts = [unquote(x) for x in path.split("/")]
    quals = dict(kv.split("=", 1) for kv in (q or "").split("&") if "=" in kv)
    ns, name = (parts[:-1], parts[-1])
    return {"type": t, "namespace": "/".join(ns), "name": name, "version": unquote(ver), "qualifiers": quals}


def _props(obj) -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    for p in (obj or {}).get("properties") or []:
        out[p.get("name", "")].append(p.get("value", ""))
    return out


def read_sbom(sbom: dict) -> dict:
    """Normalise a CycloneDX document into what the playbook needs."""
    if sbom.get("bomFormat") != "CycloneDX":
        raise ValueError("Not a CycloneDX SBOM (bomFormat is missing or different).")
    meta = (sbom.get("metadata") or {}).get("component") or {}
    mp = _props(meta)
    os_pkgs, lang, manual, images, repos = [], [], [], [], []
    os_id = (mp.get("diysca:os_id") or [""])[0]
    os_version = (mp.get("diysca:os_version") or [meta.get("version") or ""])[0]
    pkg_type = (mp.get("diysca:pkg_type") or [""])[0]
    for r in mp.get("diysca:repo", []):
        try:
            repos.append(json.loads(r))
        except ValueError:
            pass
    candidates: dict[str, str] = {}
    for c in sbom.get("components") or []:
        cp = _props(c)
        if c.get("type") == "container":
            images.append({"image": c.get("name", ""), "name": (cp.get("diysca:container_name") or [""])[0],
                           "runtime": (cp.get("diysca:container_runtime") or ["podman"])[0] or "podman"})
            continue
        pu = parse_purl(c.get("purl") or "")
        if not pu:
            continue
        if pu["type"] in ("deb", "rpm", "apk"):
            if pu["name"] == "gpg-pubkey":  # rpm's pseudo-package for imported keys
                continue
            pkg_type = pkg_type or pu["type"]
            os_id = os_id or pu["namespace"]
            if not os_version and pu["qualifiers"].get("distro"):
                os_version = pu["qualifiers"]["distro"].split("-", 1)[-1]
            os_pkgs.append({"name": pu["name"], "version": pu["version"], "arch": pu["qualifiers"].get("arch", ""),
                            "ref": c.get("bom-ref", "")})
            if cp.get("diysca:repo_candidate_version"):
                candidates[c.get("bom-ref", "")] = cp["diysca:repo_candidate_version"][0]
        elif pu["type"] in ("pypi", "gem"):
            loc = (cp.get("diysca:location") or [""])[0]
            lang.append({"type": pu["type"], "name": pu["name"], "version": pu["version"], "location": loc})
        else:
            name = f"{pu['namespace']}/{pu['name']}" if pu["namespace"] else pu["name"]
            manual.append(f"{pu['type']} {name} {pu['version']} " + (cp.get("diysca:location") or [""])[0])
    # packages with an open vulnerability whose fix the repos offer
    fixable: dict[str, str] = {}
    for v in sbom.get("vulnerabilities") or []:
        if "available in configured repos" not in (v.get("recommendation") or ""):
            continue
        for a in v.get("affects") or []:
            if a.get("ref") in candidates:
                fixable[a["ref"]] = candidates[a["ref"]]
    return {"name": meta.get("name") or "system", "os_id": os_id, "os_version": os_version,
            "os_pretty": meta.get("description") or "", "pkg_type": pkg_type, "repos": repos, "os_pkgs": os_pkgs,
            "lang": lang, "manual": manual, "images": images, "fixable": fixable}


def _pin(pkg_type: str, name: str, version: str, arch: str = "") -> str:
    if pkg_type == "rpm":
        v = version.split(":", 1)[1] if ":" in version else version  # dnf/zypper want name-version-release
        return f"{name}-{v}" + (f".{arch}" if arch and arch not in ("noarch",) else "")
    if pkg_type == "deb":
        return f"{name}:{arch}={version}" if arch and arch not in ("all", "amd64", "arm64") else f"{name}={version}"
    return f"{name}={version}"


def _repo_tasks(info: dict) -> list[dict]:
    tasks = []
    for i, r in enumerate(info["repos"]):
        if not r.get("enabled", True):
            continue
        kind = (r.get("kind") or "").lower()
        if kind.startswith("apt") or kind == "deb":
            line = f"deb {r['url']} {r.get('suite', '')} {r.get('components', '')}".strip()
            tasks.append({"name": f"Repository {r['url']}", "ansible.builtin.apt_repository":
                          {"repo": line, "filename": f"diysca-{i}", "update_cache": False}})
        elif kind in ("yum", "dnf", "zypp", "zypper") and info["os_id"] in SUSE:
            tasks.append({"name": f"Repository {r.get('name') or r['url']}", "community.general.zypper_repository":
                          {"name": r.get("name") or f"diysca-{i}", "repo": r["url"], "auto_import_keys": True}})
        elif kind in ("yum", "dnf", "zypp"):
            tasks.append({"name": f"Repository {r.get('name') or r['url']}", "ansible.builtin.yum_repository":
                          {"name": re.sub(r"[^A-Za-z0-9_.-]", "_", r.get("name") or f"diysca-{i}"),
                           "description": r.get("name") or r["url"], "baseurl": r["url"], "gpgcheck": True}})
        elif kind == "apk":
            tasks.append({"name": f"Repository {r['url']}", "ansible.builtin.lineinfile":
                          {"path": "/etc/apk/repositories", "line": r["url"]}})
    return tasks


def _install_tasks(pkg_type: str, os_id: str, pins: list[str]) -> list[dict]:
    if pkg_type == "deb":
        return [{"name": "Refresh package lists", "ansible.builtin.apt": {"update_cache": True}},
                {"name": f"Install {len(pins)} packages at the recorded versions",
                 "ansible.builtin.apt": {"name": pins, "state": "present", "allow_downgrade": True}}]
    if pkg_type == "rpm" and os_id in SUSE:
        return [{"name": f"Install {len(pins)} packages at the recorded versions", "ansible.builtin.command":
                 {"argv": ["zypper", "--non-interactive", "install", "--oldpackage", "--no-recommends"] + pins},
                 "register": "diysca_zy", "changed_when": "'Nothing to do' not in diysca_zy.stdout"}]
    if pkg_type == "rpm":
        return [{"name": f"Install {len(pins)} packages at the recorded versions",
                 "ansible.builtin.dnf": {"name": pins, "state": "present", "allow_downgrade": True,
                                         "update_cache": True}}]
    return [{"name": f"Install {len(pins)} packages at the recorded versions",
             "ansible.builtin.command": {"argv": ["apk", "add", "--update-cache"] + pins}}]


_LANG_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,127}$")
_LANG_VER = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+!_\-]{0,63}$")
_LANG_PATH = re.compile(r"^(/[A-Za-z0-9._+@\-]+)*/?$")


def _lang_tasks(lang: list[dict]) -> list[dict]:
    tasks = []
    pip: dict[str, list[str]] = defaultdict(list)
    # names and versions become arguments of pip / gem, run as root: plain ones only (no options, URLs, paths)
    lang = [p for p in lang if _LANG_NAME.match(p["name"] or "") and _LANG_VER.match(p["version"] or "")
            and _LANG_PATH.match(p["location"] or "")]
    for p in lang:
        if p["type"] == "pypi":
            loc = p["location"]
            venv = loc.split("/lib/python")[0] if "/lib/python" in loc else ""
            if venv in ("/usr", "/usr/local", ""):
                venv = ""
            pip[venv].append(f"{p['name']}=={p['version']}")
    for venv, reqs in sorted(pip.items()):
        t = {"name": f"pip packages {'in ' + venv if venv else '(system)'}",
             "ansible.builtin.pip": {"name": sorted(reqs)}}
        if venv:
            t["ansible.builtin.pip"]["virtualenv"] = venv
            t["ansible.builtin.pip"]["virtualenv_command"] = "python3 -m venv"
        else:
            t["ansible.builtin.pip"]["executable"] = "pip3"
        tasks.append(t)
    for p in sorted((p for p in lang if p["type"] == "gem"), key=lambda p: p["name"]):
        tasks.append({"name": f"gem {p['name']} {p['version']}", "community.general.gem":
                      {"name": p["name"], "version": p["version"], "user_install": False, "state": "present"}})
    return tasks


def build(sbom: dict, mode: str = "fixed", target: str | None = None) -> tuple[str, dict]:
    info = read_sbom(sbom)
    if not info["os_pkgs"]:
        raise ValueError("The SBOM has no deb, rpm or apk packages to install.")
    pkg_type = info["pkg_type"] or info["os_pkgs"][0].get("type", "deb")
    if pkg_type not in ("deb", "rpm", "apk"):
        raise ValueError(f"Unknown package type '{pkg_type}' in the SBOM.")
    bumped = 0
    pins, odd = [], []
    for p in sorted(info["os_pkgs"], key=lambda p: p["name"]):
        ver = p["version"]
        if mode == "fixed" and p["ref"] in info["fixable"]:
            ver, bumped = info["fixable"][p["ref"]], bumped + 1
        arch = p["arch"] if pkg_type == "rpm" else ""
        # names, versions and architectures come from the scanned system: only plain ones become install arguments
        if not pbsafe.pin_ok(pkg_type, p["name"], ver) or (arch and not pbsafe.word(arch)):
            odd.append(f"{p['name']} {ver}")
            continue
        pins.append(_pin(pkg_type, p["name"], ver, arch))
    # the major version goes into a condition, which Ansible evaluates as an expression: plain tokens only
    major = pbsafe.word((info["os_version"] or "").split(".")[0])
    tasks: list[dict] = []
    if info["os_id"]:
        cond = [f"ansible_facts['distribution'] == '{FAMILY.get(info['os_id'], info['os_id'])}'"] if info["os_id"] in FAMILY else []
        if major:
            cond.append(f"ansible_facts['distribution_major_version'] == '{major}'")
        if cond:
            tasks.append({"name": f"Target must run {info['os_pretty'] or info['os_id'] + ' ' + info['os_version']}",
                          "ansible.builtin.assert": {"that": cond, "fail_msg": "The SBOM was taken on a different OS release."}})
    tasks += _repo_tasks(info)
    tasks += _install_tasks(pkg_type, info["os_id"], pins)
    tasks += _lang_tasks(info["lang"])
    runtimes = ("podman", "docker", "nerdctl", "crictl")
    for im in info["images"]:
        if im["runtime"] not in runtimes or not re.match(r"^[A-Za-z0-9][A-Za-z0-9._:/@\-]{0,254}$", im["image"] or ""):
            odd.append(f"container image {im['image']} ({im['runtime']})")
            continue
        tasks.append({"name": f"Pull image {im['image']}" + (f" (was running as {im['name']})" if im["name"] else ""),
                      "ansible.builtin.command": {"argv": [im["runtime"] if im["runtime"] != "crictl" else "crictl",
                                                           "pull", im["image"]]},
                      "changed_when": False})
    hosts = target or info["name"]
    if not target and not pbsafe.host_ok(hosts):  # the name comes from the SBOM: never let it act as a pattern
        odd.append(f"system name {info['name']} can't be used as an Ansible host: set `hosts:` yourself (--target)")
        hosts = "REPLACE_WITH_THE_TARGET_HOST"
    play = {"name": f"diysca: reprovision {info['name']} from its SBOM ({mode})", "hosts": hosts,
            "become": True, "gather_facts": True, "tasks": tasks}
    head = [f"# Generated by diysca {__version__} at {db.now()} from the SBOM of {pbsafe.comment(info['name'])}",
            "# Generated automatically by AI-written software, without warranty: review it before you run it.",
            f"# OS: {pbsafe.comment(info['os_pretty'] or info['os_id'] + ' ' + info['os_version'])}, {len(pins)} {pkg_type} packages, "
            f"{len(info['lang'])} pip/gem packages, {len(info['images'])} container images",
            f"# Mode: {mode}" + (f" ({bumped} vulnerable packages raised to the fixed version in your repos)"
                                 if mode == "fixed" else " (every package at the recorded version)"),
            "# Start from a minimal install of the same OS release. Dry run first:",
            "#   ansible-playbook -i <inventory> reprovision.yml --check --diff",
            "# Repository signing keys are not part of an SBOM: install them before running (or in a pre_task).",
            "#"]
    if not info["repos"]:
        head.append("# The SBOM lists no repositories: the target must already have repos that carry these versions.")
    if info["manual"]:
        head.append("# Application dependencies (rebuild or redeploy the application instead):")
        head += [f"#   - {pbsafe.comment(m)}" for m in info["manual"][:300]]
        if len(info["manual"]) > 300:
            head.append(f"#   ... and {len(info['manual']) - 300} more")
    if odd:
        head.append("# Skipped, unexpected characters in the name or version (check the system, it may be tampered with):")
        head += [f"#   - {pbsafe.comment(o)}" for o in odd[:100]]
    if info["images"]:
        head.append("# Container images are pulled only. Recreate the containers with your usual deployment.")
    summary = {"system": info["name"], "packages": len(pins), "bumped": bumped, "lang": len(info["lang"]),
               "manual": len(info["manual"]), "images": len(info["images"]), "repos": len(info["repos"])}
    body = yaml.dump([play], Dumper=_Dumper, sort_keys=False, width=140)
    return "\n".join(head) + "\n---\n" + body, summary


def for_host(host_id: int, mode: str = "fixed", target: str | None = None) -> tuple[str, dict]:
    return build(build_sbom(host_id), mode, target)
