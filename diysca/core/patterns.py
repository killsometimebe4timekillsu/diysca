"""Host patterns, shared by alert subscriptions and role scopes.

    "*"                     every system
    "web*,db1"              by name or address (globs), comma separated
    "group:prod"            by Ansible / provider group
    "group:prod,!test-*"    "!" excludes
"""
from __future__ import annotations

from fnmatch import fnmatch


def split(s: str | None) -> list[str]:
    return [p.strip() for p in (s or "*").split(",") if p.strip()] or ["*"]


def host_matches(pattern: str | None, host) -> bool:
    groups = [g for g in (host["groups"] or "").split(",") if g]
    ok = False
    for pat in split(pattern):
        neg = pat.startswith("!")
        pat = pat.lstrip("!")
        if pat.startswith("group:"):
            hit = any(fnmatch(g, pat[6:]) for g in groups)
        else:
            hit = fnmatch(host["name"], pat) or fnmatch(host["address"] or "", pat)
        if hit and neg:
            return False
        ok = ok or (hit and not neg)
    return ok
