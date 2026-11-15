"""Module registry.

diysca is split into modules. `core` (database, config, events, settings) and `scanning` are always on;
the others can be switched off in config.yml:

    modules: [alerting, mitigation, auth]      # default: all of them

Each module describes what it brings: web routes (pages and API), menu entries, tabs, settings tabs,
MCP tools, CLI commands and event handlers. The web app, the MCP server and the CLI are built from the
modules that are enabled.
"""
from __future__ import annotations

import importlib
from collections.abc import Callable
from dataclasses import dataclass, field

from diysca.core.config import settings

OPTIONAL = ("alerting", "mitigation", "auth")
ALWAYS = ("core", "scanning")


@dataclass
class Module:
    name: str
    title: str
    description: str
    routes: str | None = None                 # "diysca.x.routes" with a `router`
    nav: list[tuple] = field(default_factory=list)            # (key, href, label, svg path, order)
    tabs: dict[str, list[tuple]] = field(default_factory=dict)  # view group -> [(key, href, label, order)]
    settings_tabs: list[tuple] = field(default_factory=list)  # (key, href, label, order)
    mcp_tools: tuple[str, ...] = ()           # names of tools in diysca.mcp that belong to this module
    setup: Callable[[], None] | None = None   # subscribe to events, etc.
    openapi_tags: list[dict] = field(default_factory=list)
    requires: tuple[str, ...] = ()


_loaded: dict[str, Module] = {}


def configured() -> list[str]:
    want = settings.modules if settings.modules else list(OPTIONAL)
    unknown = [m for m in want if m not in OPTIONAL and m not in ALWAYS]
    if unknown:
        raise ValueError(f"unknown module(s) in config: {', '.join(unknown)}; known: {', '.join(OPTIONAL)}")
    return list(ALWAYS) + [m for m in OPTIONAL if m in want]


def load(force: bool = False) -> dict[str, Module]:
    """Import the enabled modules and run their setup once."""
    if _loaded and not force:
        return _loaded
    _loaded.clear()
    for name in configured():
        mod = importlib.import_module(f"diysca.{name}.module").MODULE
        missing = [r for r in mod.requires if r not in configured()]
        if missing:
            raise ValueError(f"module {name} needs {', '.join(missing)}")
        _loaded[name] = mod
    for mod in _loaded.values():
        if mod.setup:
            mod.setup()
    return _loaded


def enabled(name: str) -> bool:
    return name in (load() if not _loaded else _loaded)


def all_loaded() -> list[Module]:
    return list(load().values())


def nav() -> list[tuple]:
    items = [i for m in all_loaded() for i in m.nav]
    return [i[:4] for i in sorted(items, key=lambda i: i[4])]


def tabs(group: str) -> list[tuple]:
    items = [t for m in all_loaded() for t in m.tabs.get(group, [])]
    return [t[:3] for t in sorted(items, key=lambda t: t[3])]


def tab_group(page: str) -> str | None:
    for m in all_loaded():
        for group, items in m.tabs.items():
            if any(t[0] == page for t in items):
                return group
    return None


def settings_tabs() -> list[tuple]:
    items = [t for m in all_loaded() for t in m.settings_tabs]
    return [t[:3] for t in sorted(items, key=lambda t: t[3])]


def mcp_tools() -> set[str]:
    return {t for m in all_loaded() for t in m.mcp_tools}
