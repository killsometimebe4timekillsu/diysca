"""Alerts. Channels are Apprise URLs, so ntfy, Gotify, email, Telegram,
Slack, Matrix, Discord, MS Teams, webhooks ... all work the same way.

    ntfy://ntfy.sh/my-topic            ntfys://user:pass@ntfy.example.org/topic
    mailtos://user:pass@smtp.example.org?to=me@example.org
    tgram://bottoken/chatid            gotifys://gotify.example.org/token

A subscription says "findings matching these hosts/packages/severity go to
this channel". Each finding is sent at most once per channel.
"""
from __future__ import annotations

import asyncio
from fnmatch import fnmatch

from . import db
from .config import settings
from .feeds import sev_rank


def _patterns(s: str | None) -> list[str]:
    return [p.strip() for p in (s or "*").split(",") if p.strip()] or ["*"]


def matches(sub, finding, host) -> bool:
    if not sub["enabled"]:
        return False
    host_ok = False
    groups = [g for g in (host["groups"] or "").split(",") if g]
    for pat in _patterns(sub["host_pattern"]):
        neg = pat.startswith("!")
        pat = pat.lstrip("!")
        if pat.startswith("group:"):
            hit = any(fnmatch(g, pat[6:]) for g in groups)
        else:
            hit = fnmatch(host["name"], pat) or fnmatch(host["address"] or "", pat)
        if hit and neg:
            return False
        host_ok = host_ok or (hit and not neg)
    if not host_ok:
        return False
    names = [finding["package"]] + [b for b in (finding["binaries"] or "").split(",") if b]
    pkg_ok = False
    for pat in _patterns(sub["package_pattern"]):
        neg = pat.startswith("!")
        pat = pat.lstrip("!")
        hit = any(fnmatch(n, pat) for n in names)
        if hit and neg:
            return False
        pkg_ok = pkg_ok or (hit and not neg)
    if not pkg_ok:
        return False
    if sev_rank(finding["severity"]) < sev_rank(sub["min_severity"] or "UNKNOWN"):
        return False
    if sub["only_kev"] and not finding["kev"]:
        return False
    if sub["only_fixable"] and not finding["fix_in_repo"]:
        return False
    return True


def format_finding(f, host) -> str:
    sev = f["severity"] or "UNKNOWN"
    score = f" {f['cvss_score']:.1f}" if f["cvss_score"] else ""
    line = f"{f['package']} {f['version']} installed on {host['name']} affected by {f['vuln_id']} ({sev}{score})"
    if f["kev"]:
        line += " [KNOWN EXPLOITED]"
    if f["fixed_version"]:
        line += f", fixed in {f['fixed_version']}"
        line += " - fix available in your repos" if f["fix_in_repo"] else " - fix NOT yet in your repos"
    else:
        line += ", no fix released yet"
    return line


def _send(url: str, title: str, body: str, severity: str) -> tuple[bool, str]:
    import apprise

    ap = apprise.Apprise()
    if not ap.add(url):
        return False, "invalid Apprise URL"
    ntype = apprise.NotifyType.FAILURE if sev_rank(severity) >= sev_rank("HIGH") else apprise.NotifyType.WARNING
    ok = ap.notify(title=title, body=body, notify_type=ntype)
    return bool(ok), "" if ok else "delivery failed (see server log)"


async def send_to_channel(channel, title: str, body: str, severity: str = "MEDIUM") -> tuple[bool, str]:
    return await asyncio.to_thread(_send, channel["url"], title, body, severity)


async def dispatch(host_id: int | None = None, dry_run: bool = False) -> int:
    """Send every open, not yet notified finding that matches a subscription."""
    subs = db.q("""SELECT s.*, c.url, c.name AS channel_name, c.enabled AS channel_enabled
                   FROM subscriptions s JOIN channels c ON c.id = s.channel_id WHERE s.enabled=1 AND c.enabled=1""")
    if not subs:
        return 0
    where, params = "f.status='open'", []
    if host_id:
        where += " AND f.host_id=?"
        params.append(host_id)
    findings = db.q(f"SELECT f.* FROM findings f WHERE {where} ORDER BY f.cvss_score DESC", params)
    hosts = {h["id"]: h for h in db.q("SELECT * FROM hosts")}
    sent_pairs = {(r["finding_id"], r["channel_id"]) for r in db.q("SELECT finding_id, channel_id FROM notifications WHERE ok=1")}

    # channel_id -> host_id -> [findings]
    batches: dict[int, dict[int, list]] = {}
    for f in findings:
        h = hosts[f["host_id"]]
        for s in subs:
            if (f["id"], s["channel_id"]) in sent_pairs:
                continue
            if matches(s, f, h):
                lst = batches.setdefault(s["channel_id"], {}).setdefault(f["host_id"], [])
                if f not in lst:
                    lst.append(f)
    channels = {s["channel_id"]: s for s in subs}
    count = 0
    for cid, by_host in batches.items():
        ch = {"url": channels[cid]["url"]}
        for hid, fs in by_host.items():
            h = hosts[hid]
            worst = max((f["severity"] or "UNKNOWN" for f in fs), key=sev_rank)
            if len(fs) == 1:
                title = f"[diysca] {fs[0]['vuln_id']} on {h['name']}"
            else:
                title = f"[diysca] {len(fs)} new vulnerabilities on {h['name']}"
            lines = [format_finding(f, h) for f in fs[:25]]
            if len(fs) > 25:
                lines.append(f"... and {len(fs) - 25} more")
            lines.append(f"{settings.base_url.rstrip('/')}/findings?host={h['name']}")
            body = "\n".join(lines)
            if dry_run:
                print(f"--> {channels[cid]['channel_name']}: {title}\n{body}\n")
                count += len(fs)
                continue
            ok, err = await send_to_channel(ch, title, body, worst)
            for f in fs:
                db.x("""INSERT INTO notifications VALUES (?,?,?,?,?) ON CONFLICT(finding_id, channel_id)
                        DO UPDATE SET sent_at=excluded.sent_at, ok=excluded.ok, error=excluded.error""",
                     (f["id"], cid, db.now(), int(ok), err))
            if ok:
                count += len(fs)
            else:
                db.event("notify", f"channel {channels[cid]['channel_name']}: {err}")
    return count
