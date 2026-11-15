"""Patching, part 1: an Ansible playbook that upgrades selected findings.

For every selected OS finding whose fix is already in the host's repos, the
binaries built from the affected source package are upgraded to exactly the
version the repos offer (the "repo candidate"), not to whatever is newest
when the playbook runs. Everything that a playbook can't fix safely is
listed as a comment at the top:

* fix released upstream but not yet in your repos -> update the repo first
  (see repomgr.py: aptly / Pulp / Foreman)
* no fix released yet
* language packages (pip, npm, ...) -> bump the dependency in the app
* container images -> rebuild/redeploy the image
"""
from __future__ import annotations

from collections import defaultdict

import yaml

from diysca import __version__
from diysca.core import db
from diysca.core.versions import max_version


def _pin(pkg_type: str, name: str, version: str) -> str:
    if pkg_type == "rpm":
        return f"{name}-{version}"  # dnf/yum NEVRA without arch; epoch stays as "E:V-R"
    return f"{name}={version}"      # apt, apk, zypper


class _Dumper(yaml.SafeDumper):
    pass


def _str_repr(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style='"' if "=" in data or ":" in data else None)


_Dumper.add_representer(str, _str_repr)


def _tasks_for(pkg_type: str, os_id: str, pins: list[str]) -> list[dict]:
    if pkg_type == "deb":
        upgrade = {"name": "Upgrade vulnerable packages to the repo candidate version",
                   "ansible.builtin.apt": {"name": pins, "state": "present", "only_upgrade": True,
                                           "update_cache": True, "cache_valid_time": 600}}
        reboot_check = {"name": "Check whether a reboot is required",
                        "ansible.builtin.stat": {"path": "/var/run/reboot-required"}, "register": "diysca_rr"}
        reboot_when = "diysca_reboot | bool and diysca_rr.stat.exists"
    elif pkg_type == "rpm" and os_id in ("sles", "sled", "sles_sap", "opensuse-leap", "opensuse-tumbleweed"):
        upgrade = {"name": "Upgrade vulnerable packages to the repo candidate version",
                   "ansible.builtin.command": {"argv": ["zypper", "--non-interactive", "install", "--no-recommends"] + pins},
                   "register": "diysca_up", "changed_when": "'Nothing to do' not in diysca_up.stdout"}
        reboot_check = {"name": "Check whether a reboot is required",
                        "ansible.builtin.command": {"argv": ["zypper", "needs-rebooting"]},
                        "register": "diysca_rr", "changed_when": False, "failed_when": False}
        reboot_when = "diysca_reboot | bool and diysca_rr.rc == 102"
    elif pkg_type == "rpm":
        upgrade = {"name": "Upgrade vulnerable packages to the repo candidate version",
                   "ansible.builtin.dnf": {"name": pins, "state": "present", "update_cache": True}}
        reboot_check = {"name": "Check whether a reboot is required",
                        "ansible.builtin.command": {"argv": ["needs-restarting", "-r"]},
                        "register": "diysca_rr", "changed_when": False, "failed_when": False}
        reboot_when = "diysca_reboot | bool and diysca_rr.rc == 1"
    else:  # apk
        upgrade = {"name": "Upgrade vulnerable packages to the repo candidate version",
                   "ansible.builtin.command": {"argv": ["apk", "add", "--update-cache", "--upgrade"] + pins}}
        return [upgrade]
    return [upgrade, reboot_check,
            {"name": "Reboot if needed (set -e diysca_reboot=true)", "ansible.builtin.reboot": {},
             "when": reboot_when}]


def build_playbook(finding_ids: list[int]) -> tuple[str, dict]:
    """Returns (playbook YAML, summary)."""
    if not finding_ids:
        return "# diysca: no findings selected\n", {"hosts": 0, "packages": 0, "manual": 0}
    marks = ",".join("?" * len(finding_ids))
    rows = db.q(f"""SELECT f.*, h.name host_name, h.kind host_kind, h.pkg_type, h.os_id, h.image, h.parent_id
                    FROM findings f JOIN hosts h ON h.id=f.host_id
                    WHERE f.id IN ({marks}) AND f.status='open' ORDER BY h.name, f.package""", finding_ids)
    per_host: dict[str, dict] = {}
    manual: dict[str, list[str]] = defaultdict(list)
    # One line per language package and location, with the version that fixes all of its selected CVEs.
    lang: dict[tuple, dict] = {}
    for f in rows:
        where = f["host_name"]
        if f["ecosystem"]:
            g = lang.setdefault((where, f["ecosystem"], f["package"], f["version"], f["location"] or "?"),
                                {"fixed": [], "cves": [], "unfixed": 0})
            g["cves"].append(f["vuln_id"])
            if f["fixed_version"]:
                g["fixed"].append(f["fixed_version"])
            else:
                g["unfixed"] += 1
            continue
        if f["host_kind"] == "container":
            manual["Container images (rebuild the image with updated packages and redeploy)"].append(
                f"{where} [{f['image']}]: {f['package']} {f['version']} -> {f['fixed_version'] or 'no fix yet'} ({f['vuln_id']})")
            continue
        if not f["fixed_version"]:
            manual["No fix released yet"].append(f"{where}: {f['package']} {f['version']} ({f['vuln_id']})")
            continue
        if not f["fix_in_repo"]:
            manual["Fix released but not yet in your repos (update/sync the repo first, see Patching > Repositories)"].append(
                f"{where}: {f['package']} {f['version']} -> {f['fixed_version']} ({f['vuln_id']}),"
                f" repos offer {f['repo_version'] or 'nothing newer'}")
            continue
        h = per_host.setdefault(f["host_name"], {"host_id": f["host_id"], "pkg_type": f["pkg_type"] or "deb",
                                                  "os_id": f["os_id"] or "", "cves": set(), "binaries": set()})
        h["cves"].add(f["vuln_id"])
        h["binaries"].update(b for b in (f["binaries"] or f["package"]).split(",") if b)

    for (where, eco, pkg, ver, loc), g in lang.items():
        target = max_version(eco, g["fixed"])
        to = f">= {target}" if target else "no fix yet"
        if target and g["unfixed"]:
            to += f" ({g['unfixed']} CVE(s) without a fix yet)"
        manual["Language packages (bump the dependency in the application and redeploy)"].append(
            f"{where}: {eco} {pkg} {ver} -> {to} ({', '.join(sorted(set(g['cves'])))}) in {loc}")

    plays = []
    n_pkgs = 0
    for host, h in per_host.items():
        pins = []
        for b in sorted(h["binaries"]):
            p = db.q1("SELECT version, repo_version FROM packages WHERE host_id=? AND name=? AND ecosystem=''",
                      (h["host_id"], b))
            if p and p["repo_version"] and p["repo_version"] != p["version"]:
                pins.append(_pin(h["pkg_type"], b, p["repo_version"]))
        if not pins:
            continue
        n_pkgs += len(pins)
        plays.append({
            "name": f"diysca: patch {host} ({len(h['cves'])} CVEs: {', '.join(sorted(h['cves'])[:8])}"
                    + (" ..." if len(h["cves"]) > 8 else "") + ")",
            "hosts": host,
            "become": True,
            "gather_facts": False,
            "vars": {"diysca_reboot": False},
            "tasks": _tasks_for(h["pkg_type"], h["os_id"], pins),
        })

    head = [f"# Generated by diysca {__version__} at {db.now()}",
            "# Generated automatically by AI-written software, without warranty: review it before you run it.",
            "# Run:  ansible-playbook -i <your inventory> diysca-patch.yml --check --diff   (dry run first)",
            "#       ansible-playbook -i <your inventory> diysca-patch.yml [-e diysca_reboot=true]",
            "# Packages are pinned to the exact version your repos offered at scan time.", "#"]
    for title, items in manual.items():
        head.append(f"# {title}:")
        head += [f"#   - {i}" for i in items[:200]]
        if len(items) > 200:
            head.append(f"#   ... and {len(items) - 200} more")
        head.append("#")
    body = yaml.dump(plays, Dumper=_Dumper, sort_keys=False, width=140) if plays else "[]\n"
    summary = {"hosts": len(plays), "packages": n_pkgs, "manual": sum(len(v) for v in manual.values())}
    return "\n".join(head) + "\n---\n" + body, summary
