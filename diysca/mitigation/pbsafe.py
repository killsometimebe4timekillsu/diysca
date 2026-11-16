"""Keep data from scanned systems from becoming code in generated playbooks.

Package names, versions, repo URLs, image names and OS facts come from the systems diysca scans. A system
that is compromised (or a container image somebody else built) controls them. Ansible templates every string
in a playbook that contains Jinja markers, on the control node, and `lookup('pipe', ...)` in a template runs
a command there. So a package called `{{ lookup('pipe', 'id') }}` would run `id` on whoever runs the playbook.

Three defences, used by patch.py and reprovision.py:

* `Dumper` writes every string with a Jinja marker as `!unsafe`, which tells Ansible not to template it.
* `pin_ok` only lets package names and versions with the characters real packages use into install tasks,
  so a "package" can't be a URL, a file path or an option for apt / dnf / zypper / apk either.
* `comment` strips line breaks, so a value can't leave the comment block at the top of a playbook.
"""
from __future__ import annotations

import re

import yaml

_JINJA = ("{{", "{%", "{#")
# line breaks as YAML and Python see them, and other control characters
_CTRL = re.compile(r"[\x00-\x1f\x7f\x85  ]+")

_NAME = {
    "deb": re.compile(r"^[a-z0-9][a-z0-9+.\-]{0,127}(:[a-z0-9\-]{1,20})?$"),
    "rpm": re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+\-]{0,127}$"),
    "apk": re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+\-]{0,127}$"),
}
_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+~^:_\-]{0,127}$")
_WORD = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._\-]{0,63}$")


class Dumper(yaml.SafeDumper):
    """SafeDumper that marks strings with Jinja markers as !unsafe and quotes the ones YAML could misread."""


def _str(dumper, data: str):
    if any(m in data for m in _JINJA):
        return dumper.represent_scalar("!unsafe", data, style='"')
    return dumper.represent_scalar("tag:yaml.org,2002:str", data,
                                   style='"' if any(c in data for c in "=:{}#*") else None)


Dumper.add_representer(str, _str)


def pin_ok(pkg_type: str, name: str, version: str) -> bool:
    """True when name and version look like a real package of that type (no URLs, paths, options, templates)."""
    rx = _NAME.get(pkg_type or "deb", _NAME["rpm"])
    return bool(name and version and rx.match(str(name)) and _VERSION.match(str(version)))


def word(value: str) -> str:
    """`value` if it is a plain token (letters, digits, . _ -), else "". For values used inside conditions."""
    return value if _WORD.match(str(value or "")) else ""


def comment(text) -> str:
    """One line for a `# ...` comment: control characters and line breaks become spaces."""
    return _CTRL.sub(" ", str(text))[:500]


_HOST = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._\-]{0,252}$")
_RESERVED_HOSTS = {"all", "ungrouped"}


def host_ok(name) -> bool:
    """True when a system name can stand alone in a play's `hosts:`. Ansible reads that line as a pattern: `all`,
    `web*`, `a,b`, `a:b`, `!x` or `&y` would run the play on other systems than the one that was approved. System
    names come from inventories and cloud metadata, so they are checked like everything else in a playbook."""
    name = str(name or "")
    return bool(_HOST.match(name)) and name.lower() not in _RESERVED_HOSTS

