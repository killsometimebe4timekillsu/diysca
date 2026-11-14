"""Read hosts from Ansible inventories.

If `ansible-inventory` is installed we use it (handles dynamic inventories,
vault, plugins). Otherwise a built-in parser handles static INI and YAML
inventories plus group_vars/ and host_vars/ next to the inventory file.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class InvHost:
    name: str
    vars: dict = field(default_factory=dict)
    groups: set[str] = field(default_factory=set)

    @property
    def address(self) -> str:
        return str(self.vars.get("ansible_host") or self.vars.get("ansible_ssh_host") or self.name)

    @property
    def user(self) -> str | None:
        u = self.vars.get("ansible_user") or self.vars.get("ansible_ssh_user")
        return str(u) if u else None

    @property
    def port(self) -> int:
        return int(self.vars.get("ansible_port") or self.vars.get("ansible_ssh_port") or 22)

    @property
    def key_file(self) -> str | None:
        k = self.vars.get("ansible_ssh_private_key_file") or self.vars.get("ansible_private_key_file")
        return os.path.expanduser(str(k)) if k else None

    @property
    def connection(self) -> str:
        if self.vars.get("ansible_connection"):
            return str(self.vars["ansible_connection"])
        return "local" if self.name in ("localhost", "127.0.0.1") else "ssh"


_RANGE = re.compile(r"\[([0-9a-z]+):([0-9a-z]+)(?::(\d+))?\]")


def expand_host_pattern(pattern: str) -> list[str]:
    m = _RANGE.search(pattern)
    if not m:
        return [pattern]
    start, end, step = m.group(1), m.group(2), int(m.group(3) or 1)
    pre, post = pattern[: m.start()], pattern[m.end():]
    out = []
    if start.isdigit() and end.isdigit():
        width = len(start) if start.startswith("0") else 0
        for i in range(int(start), int(end) + 1, step):
            out += expand_host_pattern(f"{pre}{str(i).zfill(width)}{post}")
    else:
        for c in range(ord(start), ord(end) + 1, step):
            out += expand_host_pattern(f"{pre}{chr(c)}{post}")
    return out


def _parse_value(v: str):
    try:
        return yaml.safe_load(v)
    except Exception:
        return v


class Inventory:
    def __init__(self):
        self.hosts: dict[str, InvHost] = {}
        self.group_vars: dict[str, dict] = {}
        self.children: dict[str, set[str]] = {}
        self.group_hosts: dict[str, set[str]] = {}

    def _host(self, name: str) -> InvHost:
        if name not in self.hosts:
            self.hosts[name] = InvHost(name)
        return self.hosts[name]

    def _add_to_group(self, group: str, host: str):
        self.group_hosts.setdefault(group, set()).add(host)

    # ------------------------------------------------------------- INI
    def load_ini(self, text: str):
        section, kind = "ungrouped", "hosts"
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line[0] in "#;":
                continue
            if line.startswith("[") and line.endswith("]"):
                name = line[1:-1]
                if ":" in name:
                    section, kind = name.split(":", 1)
                else:
                    section, kind = name, "hosts"
                self.group_hosts.setdefault(section, set())
                continue
            if kind == "children":
                self.children.setdefault(section, set()).add(line.split()[0])
            elif kind == "vars":
                if "=" in line:
                    k, v = line.split("=", 1)
                    self.group_vars.setdefault(section, {})[k.strip()] = _parse_value(v.strip())
            else:
                parts = shlex.split(line, comments=True)
                if not parts:
                    continue
                hvars = {}
                for p in parts[1:]:
                    if "=" in p:
                        k, v = p.split("=", 1)
                        hvars[k] = _parse_value(v)
                for hn in expand_host_pattern(parts[0]):
                    h = self._host(hn)
                    h.vars.update(hvars)
                    self._add_to_group(section, hn)

    # ------------------------------------------------------------ YAML
    def load_yaml(self, data: dict):
        def walk(gname: str, gdata: dict | None):
            self.group_hosts.setdefault(gname, set())
            gdata = gdata or {}
            for hpat, hvars in (gdata.get("hosts") or {}).items():
                for hn in expand_host_pattern(str(hpat)):
                    h = self._host(hn)
                    h.vars.update(hvars or {})
                    self._add_to_group(gname, hn)
            if gdata.get("vars"):
                self.group_vars.setdefault(gname, {}).update(gdata["vars"])
            for cname, cdata in (gdata.get("children") or {}).items():
                self.children.setdefault(gname, set()).add(cname)
                walk(cname, cdata)

        for gname, gdata in (data or {}).items():
            walk(gname, gdata)

    # ------------------------------------------------- group/host vars
    def load_vars_dirs(self, base: Path):
        for kind in ("group_vars", "host_vars"):
            d = base / kind
            if not d.is_dir():
                continue
            for p in d.iterdir():
                files = [p] if p.is_file() else sorted(p.glob("*.y*ml"))
                name = p.stem if p.is_file() else p.name
                for f in files:
                    if f.suffix not in (".yml", ".yaml", ""):
                        continue
                    try:
                        data = yaml.safe_load(f.read_text()) or {}
                    except Exception:
                        continue  # vault-encrypted or broken: ignore
                    if not isinstance(data, dict):
                        continue
                    if kind == "group_vars":
                        self.group_vars.setdefault(name, {}).update(data)
                    elif name in self.hosts:
                        self.hosts[name].vars.update(data)

    def resolve(self) -> list[InvHost]:
        """Apply group vars (parents first, so children override) and memberships."""
        parents: dict[str, set[str]] = {}
        for p, cs in self.children.items():
            for c in cs:
                parents.setdefault(c, set()).add(p)

        def ancestors(g, seen=None):
            seen = seen or set()
            for p in parents.get(g, ()):
                if p not in seen:
                    seen.add(p)
                    ancestors(p, seen)
            return seen

        def depth(g):
            return len(ancestors(g))

        for h in self.hosts.values():
            direct = {g for g, hs in self.group_hosts.items() if h.name in hs}
            allg = set(direct)
            for g in direct:
                allg |= ancestors(g)
            allg.add("all")
            h.groups = allg - {"all", "ungrouped"} if len(allg) > 1 else allg
            merged = {}
            for g in sorted(allg, key=lambda g: (g != "all", depth(g), g)):
                merged.update(self.group_vars.get(g, {}))
            merged.update(h.vars)
            h.vars = merged
        return list(self.hosts.values())


def _from_ansible_inventory(path: str) -> list[InvHost] | None:
    exe = shutil.which("ansible-inventory")
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "-i", path, "--list"], capture_output=True, text=True, timeout=120, check=True)
        data = json.loads(out.stdout)
    except Exception:
        return None
    hostvars = data.get("_meta", {}).get("hostvars", {})
    hosts: dict[str, InvHost] = {}
    for g, gd in data.items():
        if g == "_meta" or not isinstance(gd, dict):
            continue
        for hn in gd.get("hosts", []):
            h = hosts.setdefault(hn, InvHost(hn, dict(hostvars.get(hn, {}))))
            if g not in ("all", "ungrouped"):
                h.groups.add(g)
    # add parent groups
    parents = {}
    for g, gd in data.items():
        if isinstance(gd, dict):
            for c in gd.get("children", []):
                parents.setdefault(c, set()).add(g)
    for h in hosts.values():
        stack = list(h.groups)
        while stack:
            for p in parents.get(stack.pop(), ()):
                if p not in h.groups and p != "all":
                    h.groups.add(p)
                    stack.append(p)
    return list(hosts.values())


def load_inventory(path: str, use_ansible: bool = True) -> list[InvHost]:
    if use_ansible:
        res = _from_ansible_inventory(path)
        if res is not None:
            return res
    p = Path(path)
    inv = Inventory()
    files = sorted(f for f in p.iterdir() if f.is_file() and not f.name.startswith(".")) if p.is_dir() else [p]
    for f in files:
        text = f.read_text()
        if f.suffix in (".yml", ".yaml") or text.lstrip().startswith(("all:", "---")):
            inv.load_yaml(yaml.safe_load(text) or {})
        elif f.suffix in ("", ".ini", ".cfg", ".hosts", ".txt") or f.name in ("hosts", "inventory"):
            inv.load_ini(text)
    inv.load_vars_dirs(p if p.is_dir() else p.parent)
    return inv.resolve()
