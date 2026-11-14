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

from diysca.core import db, patterns
from diysca.core.config import settings
from diysca.scanning.describe import (  # noqa: F401  (re-exported)
    action_hint,
    format_finding,
)
from diysca.scanning.feeds import sev_rank


def _patterns(s: str | None) -> list[str]:
    return patterns.split(s)


def matches(sub, finding, host) -> bool:
    if not sub["enabled"]:
        return False
    if not patterns.host_matches(sub["host_pattern"], host):
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


def alert_body(fs: list, host, base: str) -> str:
    """Alert text: one block per finding (worst first), then links."""
    lines = []
    for f in fs[:25]:
        bits = [f["severity"] or "UNKNOWN", f["vuln_id"], f"{f['package']} {f['version']}"]
        extra = []
        if f["cvss_score"]:
            extra.append(f"CVSS {f['cvss_score']:.1f}")
        if f["epss"] is not None and f["epss"] >= 0.01:
            extra.append(f"EPSS {f['epss'] * 100:.0f}%")
        if f["kev"]:
            extra.append("KNOWN EXPLOITED")
        lines.append("  ".join(bits) + (f"  ({', '.join(extra)})" if extra else ""))
        if f["summary"]:
            lines.append(f"  {f['summary'][:160]}")
        lines.append(f"  -> {action_hint(f)}")
        lines.append(f"  {base}/findings/{f['id']}")
    if len(fs) > 25:
        lines.append(f"... and {len(fs) - 25} more")
    lines.append("")
    lines.append(f"All open findings on {host['name']}: {base}/findings?host={host['name']}")
    lines.append(f"Approve for mitigation: {base}/findings?host={host['name']}&approval=unapproved"
                 " (select, then Approve for mitigation)")
    return "\n".join(lines)


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
                title = f"[diysca] {worst} {fs[0]['vuln_id']} in {fs[0]['package']} on {h['name']}"
            else:
                title = f"[diysca] {len(fs)} new vulnerabilities on {h['name']} (worst: {worst})"
            fs.sort(key=lambda f: (-f["kev"], -sev_rank(f["severity"] or "UNKNOWN"), -(f["cvss_score"] or 0)))
            body = alert_body(fs, h, settings.base_url.rstrip("/"))
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


# ------------------------------------------------------------------ event handlers
async def on_scan_finished(host_id: int, send_alerts: bool = True, **_) -> int:
    return await dispatch(host_id) if send_alerts else 0


async def on_scans_finished(**_) -> int:
    return await dispatch()


def on_mitigation_status(mitigation_id: int, status: str, detail: str = "", **_):
    """Tell the channels that alerted about a mitigation's findings how it is going."""
    chans = db.q("""SELECT DISTINCT c.id, c.url, c.name FROM notifications n JOIN channels c ON c.id=n.channel_id
                    JOIN mitigation_findings mf ON mf.finding_id=n.finding_id
                    WHERE mf.mitigation_id=? AND n.ok=1 AND c.enabled=1""", (mitigation_id,))
    if not chans or status not in ("claimed", "done", "failed"):
        return
    m = db.q1("SELECT * FROM mitigations WHERE id=?", (mitigation_id,))
    hosts = [r["name"] for r in db.q("""SELECT DISTINCT h.name FROM mitigation_findings mf JOIN findings f ON f.id=mf.finding_id
                                        JOIN hosts h ON h.id=f.host_id WHERE mf.mitigation_id=? ORDER BY h.name""",
                                     (mitigation_id,))]
    n = db.q1("SELECT COUNT(*) n FROM mitigation_findings WHERE mitigation_id=?", (mitigation_id,))["n"]
    title = f"[diysca] Mitigation #{mitigation_id} {status}"
    body = (f"Mitigation #{mitigation_id}: {detail or status}\n{n} findings on {', '.join(hosts[:10])}\n"
            f"Approved by {m['approved_by']} at {m['created_at']}\n"
            f"{settings.base_url.rstrip('/')}/mitigations/{mitigation_id}")
    sev = "LOW" if status in ("done", "claimed") else "HIGH"
    for c in chans:
        ok, err = _send(c["url"], title, body, sev)
        if not ok:
            db.event("notify", f"channel {c['name']}: mitigation #{mitigation_id}: {err}")
