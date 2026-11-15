"""Which systems the current request may see.

The auth module sets a scope per request from the user's role bindings (`hosts:` patterns). Queries add
`clause("h.id")`, which is empty when the user sees everything. Containers belong to their host's scope.
"""
from __future__ import annotations

from contextvars import ContextVar

from diysca.core import db, patterns

_allowed: ContextVar[frozenset[int] | None] = ContextVar("diysca_scope", default=None)


def hosts_for(pattern_list: list[str] | None) -> frozenset[int] | None:
    """None = everything. Otherwise the ids of hosts matching any of the patterns (and their containers)."""
    if not pattern_list or any(p.strip() in ("", "*") for p in pattern_list):
        return None
    rows = db.q("SELECT id, name, address, groups, parent_id FROM hosts")
    ids = {r["id"] for r in rows if any(patterns.host_matches(p, r) for p in pattern_list)}
    ids |= {r["id"] for r in rows if r["parent_id"] in ids}
    return frozenset(ids)


def set_ids(ids: frozenset[int] | None):
    return _allowed.set(ids)


def reset(token):
    _allowed.reset(token)


def current() -> frozenset[int] | None:
    return _allowed.get()


def clause(column: str) -> str:
    """' AND <column> IN (...)' for a limited scope, '' otherwise. Ids are ints, so they are inlined."""
    ids = _allowed.get()
    if ids is None:
        return ""
    return f" AND {column} IN ({','.join(str(i) for i in sorted(ids)) or 'NULL'})"


def allows(host_id: int | None) -> bool:
    ids = _allowed.get()
    return ids is None or host_id in ids
