"""Bulk import / export of the settings kept in the database.

One YAML document, the same shape as config.yml where the two overlap:

    sources:        extra CVE sources added in the web UI (config.yml ones are left out)
    channels:       alert channels (Apprise URLs)
    subscriptions:  which findings go to which channel (channel by name)
    saved_filters:  saved filters of the Findings / Packages / Systems pages
    handoffs:       where approved mitigations are sent (webhook, github, gitlab)

Secrets (header values of sources, channel URLs) are replaced with "***"
unless the export asks for them. On import, "***" keeps the value already
stored, so a masked export can be edited and imported back safely.
"""
from __future__ import annotations

import json
import re

import yaml

from diysca import __version__
from diysca.core import db
from diysca.mitigation import mitigate
from diysca.scanning import sources

MASK = "***"
PARTS = ("sources", "channels", "subscriptions", "saved_filters", "handoffs")


def _mask_url(url: str) -> str:
    """Hide credentials and tokens in an Apprise URL, keep scheme and host readable."""
    m = re.match(r"^([a-z0-9+]+://)(.*)$", url or "", re.IGNORECASE)
    return f"{m.group(1)}{MASK}" if m else MASK


def export_bundle(include_secrets: bool = False, parts=PARTS) -> dict:
    out: dict = {"diysca_settings": 1, "exported_by": f"diysca {__version__}", "exported_at": db.now()}
    if "sources" in parts:
        out["sources"] = []
        for s in sources.all_sources():
            if s["origin"] != "ui":
                continue
            cfg = dict(s["cfg"])
            if cfg.get("headers") and not include_secrets:
                cfg["headers"] = {k: MASK for k in cfg["headers"]}
            out["sources"].append({"name": s["name"], "type": s["type"], "enabled": bool(s["enabled"]), **cfg})
    if "channels" in parts:
        out["channels"] = [{"name": c["name"], "url": c["url"] if include_secrets else _mask_url(c["url"]),
                            "enabled": bool(c["enabled"])} for c in db.q("SELECT * FROM channels ORDER BY name")]
    if "subscriptions" in parts:
        out["subscriptions"] = [
            {"name": s["name"], "channel": s["channel"], "hosts": s["host_pattern"], "packages": s["package_pattern"],
             "min_severity": s["min_severity"], "only_kev": bool(s["only_kev"]), "only_fixable": bool(s["only_fixable"]),
             "enabled": bool(s["enabled"])}
            for s in db.q("""SELECT s.*, c.name channel FROM subscriptions s JOIN channels c ON c.id=s.channel_id
                             ORDER BY s.name""")]
    if "saved_filters" in parts:
        out["saved_filters"] = [{"name": f["name"], "page": f["page"], "query": f["query"]}
                                for f in db.q("SELECT * FROM saved_filters ORDER BY page, name")]
    if "handoffs" in parts:
        out["handoffs"] = [{"name": h["name"], "type": h["type"], "url": h["url"],
                            "token": (h["token"] if include_secrets else MASK) if h["token"] else "",
                            "auto": bool(h["auto"]), "enabled": bool(h["enabled"]), **json.loads(h["config"] or "{}")}
                           for h in db.q("SELECT * FROM handoffs ORDER BY name")]
    return out


def export_yaml(include_secrets: bool = False, parts=PARTS) -> str:
    head = "# diysca settings export. Import it on the Settings > Import / Export page or with `diysca settings import`.\n"
    if not include_secrets:
        head += "# Secrets are shown as ***. Importing *** keeps the value that is already stored.\n"
    return head + yaml.safe_dump(export_bundle(include_secrets, parts), sort_keys=False, allow_unicode=True, width=120)


def _bool(v, default=True) -> int:
    if v is None:
        return int(default)
    return int(str(v).lower() in ("1", "true", "yes", "on"))


def import_bundle(data: dict, replace: bool = False, dry_run: bool = False) -> dict:
    """Upsert everything in `data` by name. `replace` also deletes UI-managed items that are not in it.

    Returns {"added": n, "updated": n, "removed": n, "skipped": [...], "errors": [...]}.
    Nothing is written when an item has an error or when dry_run is set.
    """
    if not isinstance(data, dict):
        raise ValueError("The file must be a YAML or JSON mapping with sources / channels / subscriptions / saved_filters.")
    res = {"added": 0, "updated": 0, "removed": 0, "skipped": [], "errors": []}
    plan: list[tuple] = []

    # sources
    existing = {s["name"]: s for s in sources.all_sources()}
    for i, s in enumerate(data.get("sources") or []):
        if not isinstance(s, dict) or not s.get("name") or not s.get("type"):
            res["errors"].append(f"sources[{i}]: needs name and type")
            continue
        name, typ = str(s["name"]), str(s["type"])
        cfg = {k: v for k, v in s.items() if k not in ("name", "type", "enabled")}
        old = existing.get(name)
        if old and old["origin"] == "config":
            res["skipped"].append(f"source {name}: defined in config.yml")
            continue
        if isinstance(cfg.get("headers"), dict):
            prev = (old or {}).get("cfg", {}).get("headers") or {}
            cfg["headers"] = {k: (prev.get(k, "") if v == MASK else v) for k, v in cfg["headers"].items()}
        try:
            if cfg.get("path") or not str(cfg.get("url") or "https://").startswith(("http://", "https://")):
                raise ValueError("needs an http(s) URL (local files go in config.yml)")
            err = sources.validate(name, typ, cfg)
            if err:
                raise ValueError(err)
        except ValueError as e:
            res["errors"].append(f"source {name}: {e}")
            continue
        plan.append(("source", name, typ, cfg, _bool(s.get("enabled"))))
        res["updated" if old else "added"] += 1

    # channels
    chans = {c["name"]: c for c in db.q("SELECT * FROM channels")}
    names_after = set(chans)
    for i, c in enumerate(data.get("channels") or []):
        if not isinstance(c, dict) or not c.get("name") or not c.get("url"):
            res["errors"].append(f"channels[{i}]: needs name and url")
            continue
        url = str(c["url"])
        if MASK in url:
            if c["name"] not in chans:
                res["errors"].append(f"channel {c['name']}: the URL is masked and no channel of that name exists yet")
                continue
            url = chans[c["name"]]["url"]
        plan.append(("channel", c["name"], url, _bool(c.get("enabled"))))
        res["updated" if c["name"] in chans else "added"] += 1
        names_after.add(c["name"])

    # subscriptions
    subs = {s["name"] for s in db.q("SELECT name FROM subscriptions")}
    for i, s in enumerate(data.get("subscriptions") or []):
        if not isinstance(s, dict) or not s.get("name") or not s.get("channel"):
            res["errors"].append(f"subscriptions[{i}]: needs name and channel")
            continue
        if s["channel"] not in names_after:
            res["errors"].append(f"subscription {s['name']}: unknown channel '{s['channel']}'")
            continue
        sev = str(s.get("min_severity") or "LOW").upper()
        if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            res["errors"].append(f"subscription {s['name']}: min_severity must be critical, high, medium or low")
            continue
        plan.append(("sub", s["name"], s["channel"], str(s.get("hosts") or "*"), str(s.get("packages") or "*"), sev,
                     _bool(s.get("only_kev"), False), _bool(s.get("only_fixable"), False), _bool(s.get("enabled"))))
        res["updated" if s["name"] in subs else "added"] += 1

    # saved filters
    have = {(f["page"], f["name"]) for f in db.q("SELECT page, name FROM saved_filters")}
    for i, f in enumerate(data.get("saved_filters") or []):
        if not isinstance(f, dict) or not f.get("name") or not f.get("page"):
            res["errors"].append(f"saved_filters[{i}]: needs name and page")
            continue
        plan.append(("filter", f["name"], f["page"], str(f.get("query") or "")))
        res["updated" if (f["page"], f["name"]) in have else "added"] += 1

    # hand-off targets
    hos = {h["name"] for h in db.q("SELECT name FROM handoffs")}
    for i, h in enumerate(data.get("handoffs") or []):
        if not isinstance(h, dict) or not h.get("name") or not h.get("type") or not h.get("url"):
            res["errors"].append(f"handoffs[{i}]: needs name, type and url")
            continue
        if h["type"] not in mitigate.HANDOFF_TYPES:
            res["errors"].append(f"handoff {h['name']}: type must be one of {', '.join(mitigate.HANDOFF_TYPES)}")
            continue
        cfg = {k: v for k, v in h.items() if k not in ("name", "type", "url", "token", "auto", "enabled")}
        plan.append(("handoff", str(h["name"]), str(h["type"]), str(h["url"]), h.get("token") or None, cfg,
                     _bool(h.get("enabled")), _bool(h.get("auto"), False)))
        res["updated" if h["name"] in hos else "added"] += 1

    if replace:
        keep = {("source", p[1]) for p in plan if p[0] == "source"} | {("channel", p[1]) for p in plan if p[0] == "channel"} \
            | {("sub", p[1]) for p in plan if p[0] == "sub"} | {("handoff", p[1]) for p in plan if p[0] == "handoff"} | {("filter", (p[2], p[1])) for p in plan if p[0] == "filter"}
        drops = [("source", s["name"]) for s in existing.values() if s["origin"] == "ui" and ("source", s["name"]) not in keep
                 and "sources" in data]
        drops += [("channel", n) for n in chans if ("channel", n) not in keep and "channels" in data]
        drops += [("sub", n) for n in subs if ("sub", n) not in keep and "subscriptions" in data]
        drops += [("filter", k) for k in have if ("filter", k) not in keep and "saved_filters" in data]
        drops += [("handoff", n) for n in hos if ("handoff", n) not in keep and "handoffs" in data]
        res["removed"] = len(drops)
    else:
        drops = []

    if res["errors"] or dry_run:
        return res
    for p in plan:
        if p[0] == "source":
            _, name, typ, cfg, en = p
            db.x("""INSERT INTO feed_sources(name, type, config, origin, enabled) VALUES (?,?,?,'ui',?)
                    ON CONFLICT(name) DO UPDATE SET type=excluded.type, config=excluded.config, enabled=excluded.enabled,
                      fetched_at=NULL""", (name, typ, json.dumps(cfg), en))
        elif p[0] == "channel":
            _, name, url, en = p
            db.x("""INSERT INTO channels(name, url, enabled) VALUES (?,?,?)
                    ON CONFLICT(name) DO UPDATE SET url=excluded.url, enabled=excluded.enabled""", (name, url, en))
        elif p[0] == "sub":
            _, name, ch, hosts, pkgs, sev, kev, fix, en = p
            cid = db.q1("SELECT id FROM channels WHERE name=?", (ch,))["id"]
            row = db.q1("SELECT id FROM subscriptions WHERE name=?", (name,))
            if row:
                db.x("""UPDATE subscriptions SET channel_id=?, host_pattern=?, package_pattern=?, min_severity=?,
                        only_kev=?, only_fixable=?, enabled=? WHERE id=?""", (cid, hosts, pkgs, sev, kev, fix, en, row["id"]))
            else:
                db.x("""INSERT INTO subscriptions(name, channel_id, host_pattern, package_pattern, min_severity, only_kev,
                        only_fixable, enabled) VALUES (?,?,?,?,?,?,?,?)""", (name, cid, hosts, pkgs, sev, kev, fix, en))
        elif p[0] == "handoff":
            _, name, typ, url, token, cfg, en, auto = p
            try:
                mitigate.save_handoff(name, typ, url, token, cfg, bool(en), bool(auto))
            except mitigate.MitigationError as e:
                res["errors"].append(f"handoff {name}: {e}")
        elif p[0] == "filter":
            _, name, page, query = p
            db.x("DELETE FROM saved_filters WHERE page=? AND name=?", (page, name))
            db.x("INSERT INTO saved_filters(name, page, query) VALUES (?,?,?)", (name, page, query))
    for kind, key in drops:
        if kind == "source":
            sources.remove(key)
        elif kind == "channel":
            db.x("DELETE FROM channels WHERE name=?", (key,))
        elif kind == "sub":
            db.x("DELETE FROM subscriptions WHERE name=?", (key,))
        elif kind == "handoff":
            mitigate.remove_handoff(key)
        else:
            db.x("DELETE FROM saved_filters WHERE page=? AND name=?", key)
    db.event("settings", f"import: {res['added']} added, {res['updated']} updated, {res['removed']} removed")
    return res


def parse(text: str) -> dict:
    try:
        data = yaml.safe_load(text)  # YAML is a superset of JSON
    except yaml.YAMLError as e:
        raise ValueError(f"Not valid YAML or JSON: {e}") from e
    if isinstance(data, list):  # a bare list of sources, like config.yml's `sources:`
        data = {"sources": data}
    return data or {}
