"""A tiny in-process event bus, so modules don't import each other.

    events.on("scan.finished", handler)     # handler(**data), sync or async
    await events.emit_async("scan.finished", host_id=1, new=3)
    events.emit("mitigation.status", mitigation_id=12, status="done")   # from sync code

Events used today:

    scan.finished       host_id, send_alerts, open_findings      (scanning -> alerting)
    mitigation.status   mitigation_id, status, detail, actor      (mitigation -> alerting)
    audit               actor, action, target, detail            (anyone -> auth, which keeps the audit log)

A handler that raises is logged and doesn't stop the others.
"""
from __future__ import annotations

import asyncio
import inspect
import logging
from collections import defaultdict
from collections.abc import Callable

log = logging.getLogger("diysca.events")
_handlers: dict[str, list[Callable]] = defaultdict(list)


def on(event: str, handler: Callable) -> Callable:
    if handler not in _handlers[event]:
        _handlers[event].append(handler)
    return handler


def off(event: str, handler: Callable):
    if handler in _handlers[event]:
        _handlers[event].remove(handler)


def clear():
    _handlers.clear()


async def emit_async(event: str, **data) -> list:
    out = []
    for h in list(_handlers.get(event, [])):
        try:
            r = h(**data)
            if inspect.isawaitable(r):
                r = await r
            out.append(r)
        except Exception:  # noqa: BLE001 - one broken handler must not break the emitter
            log.exception("handler %s for %s failed", getattr(h, "__name__", h), event)
    return out


def emit(event: str, **data) -> list:
    """Call from sync code. Async handlers run on the running loop if there is one, else to completion."""
    out = []
    for h in list(_handlers.get(event, [])):
        try:
            r = h(**data)
            if inspect.isawaitable(r):
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    r = asyncio.run(r)
                else:
                    r = loop.create_task(r)
            out.append(r)
        except Exception:  # noqa: BLE001
            log.exception("handler %s for %s failed", getattr(h, "__name__", h), event)
    return out


def audit(actor: str, action: str, target: str = "", detail: str = ""):
    """Record who did what. Kept by the auth module's audit log when it is enabled."""
    emit("audit", actor=actor, action=action, target=target, detail=detail)
