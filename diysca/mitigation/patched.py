"""Patched CVEs: what went away, when, and how, for a time range.

A finding counts as patched when a scan no longer sees it (status
'resolved'). The scan records the version installed at that moment and how
it went away: upgraded, removed, or not-affected (the advisory changed while
the package stayed the same).

Ranges: "last" (the most recent patching on each system), 24h, 7d, 30d, 90d,
1y, or a custom from/to.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from html import escape
from statistics import median

from diysca.core import db, scope
from diysca.scanning.feeds import SEVERITY_ORDER, sev_rank

RANGES = {
    "last": "Since last patching",
    "24h": "Last 24 hours",
    "7d": "Last 7 days",
    "30d": "Last 30 days",
    "90d": "Last 90 days",
    "1y": "Last year",
}
_DELTA = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30),
          "90d": timedelta(days=90), "1y": timedelta(days=365)}


def _iso(d: datetime) -> str:
    return d.astimezone(UTC).replace(microsecond=0).isoformat()


def _parse(s: str) -> datetime | None:
    try:
        d = datetime.fromisoformat(s)
    except (TypeError, ValueError):
        return None
    return d if d.tzinfo else d.replace(tzinfo=UTC)


def window(rng: str, frm: str = "", to: str = "", now: datetime | None = None):
    """-> (range key, start iso or None, end iso or None, label)."""
    now = now or datetime.now(UTC)
    if rng == "custom":
        a, b = _parse(frm), _parse(to)
        if a and b and len(to) <= 10:
            b = b + timedelta(days=1)  # a date means "the whole day"
        if a:
            return "custom", _iso(a), _iso(b) if b else _iso(now), f"{frm} to {to or 'now'}"
        rng = "7d"
    if rng in _DELTA:
        return rng, _iso(now - _DELTA[rng]), _iso(now), RANGES[rng]
    return "last", None, None, RANGES["last"]


def query(args: dict, now: datetime | None = None) -> dict:
    rng, start, end, label = window(args.get("range") or "last", args.get("from", ""), args.get("to", ""), now)
    where, p = ["f.status='resolved'" + scope.clause("f.host_id")], []
    if rng == "last":
        where.append("""f.resolved_at = (SELECT MAX(f2.resolved_at) FROM findings f2
                                         WHERE f2.host_id=f.host_id AND f2.status='resolved')""")
    else:
        where += ["f.resolved_at >= ?", "f.resolved_at <= ?"]
        p += [start, end]
    if args.get("host"):
        where.append("h.name LIKE ?")
        p.append("%" + args["host"].replace("*", "%") + "%")
    if args.get("group"):
        where.append("(',' || h.groups || ',') LIKE ?")
        p.append(f"%,{args['group']},%")
    if args.get("severity") in SEVERITY_ORDER:
        allowed = [s for s in SEVERITY_ORDER if sev_rank(s) >= sev_rank(args["severity"])]
        where.append(f"f.severity IN ({','.join('?' * len(allowed))})")
        p += allowed
    if args.get("eco") == "os":
        where.append("f.ecosystem=''")
    elif args.get("eco") == "lang":
        where.append("f.ecosystem!=''")
    if args.get("how") in ("upgraded", "removed", "not-affected"):
        where.append("f.resolution=?")
        p.append(args["how"])
    rows = db.q(f"""SELECT f.*, h.name host_name, h.kind host_kind FROM findings f JOIN hosts h ON h.id=f.host_id
                    WHERE {' AND '.join(where)} ORDER BY f.resolved_at DESC, h.name, f.package""", p)

    rows = [dict(r) for r in rows]
    days = []
    for r in rows:
        a, b = _parse(r["first_seen"]), _parse(r["resolved_at"])
        r["days_open"] = round((b - a).total_seconds() / 86400, 1) if a and b else None
        if r["days_open"] is not None:
            days.append(r["days_open"])
    by_sev = {s: 0 for s in SEVERITY_ORDER[::-1]}
    for r in rows:
        by_sev[r["severity"] or "UNKNOWN"] = by_sev.get(r["severity"] or "UNKNOWN", 0) + 1
    stats = {
        "findings": len(rows),
        "cves": len({r["vuln_id"] for r in rows}),
        "systems": len({r["host_id"] for r in rows}),
        "critical_high": sum(1 for r in rows if r["severity"] in ("CRITICAL", "HIGH")),
        "kev": sum(1 for r in rows if r["kev"]),
        "median_days": round(median(days), 1) if days else None,
        "upgraded": sum(1 for r in rows if r["resolution"] == "upgraded"),
        "removed": sum(1 for r in rows if r["resolution"] == "removed"),
        "open_now": db.q1(f"SELECT COUNT(*) n FROM findings WHERE status='open'{scope.clause('host_id')}")["n"],
    }
    if rng == "last" and rows:
        start = min(r["resolved_at"] for r in rows)
        end = max(r["resolved_at"] for r in rows)
    runs = db.q("SELECT * FROM patch_runs WHERE at >= ? AND at <= ? ORDER BY at", (start, end)) if start else []
    last_per_host = db.q(f"""SELECT h.name, MAX(f.resolved_at) at, COUNT(*) n FROM findings f JOIN hosts h ON h.id=f.host_id
                            WHERE f.status='resolved'{scope.clause("h.id")} AND f.resolved_at = (SELECT MAX(f2.resolved_at) FROM findings f2
                                  WHERE f2.host_id=f.host_id AND f2.status='resolved')
                            GROUP BY h.name ORDER BY at DESC""")
    return {"range": rng, "start": start, "end": end, "label": label, "rows": rows, "stats": stats,
            "by_sev": by_sev, "chart": chart(rows, start, end, runs), "runs": runs, "last_per_host": last_per_host}


def _buckets(start: datetime, end: datetime):
    span = end - start
    if span <= timedelta(days=2):
        step, fmt = timedelta(hours=1), "%H:%M"
        first = start.replace(minute=0, second=0, microsecond=0)
    elif span <= timedelta(days=120):
        step, fmt = timedelta(days=1), "%b %d"
        first = start.replace(hour=0, minute=0, second=0, microsecond=0)
    else:
        step, fmt = timedelta(days=7), "%b %d"
        first = (start - timedelta(days=start.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    out, t = [], first
    while t < end and len(out) < 400:
        out.append(t)
        t += step
    return out or [first], step, fmt


def chart(rows, start, end, runs, width=1000, height=220) -> str:
    """Stacked bars per time bucket and severity, with patch-run annotations (inline SVG)."""
    a, b = _parse(start) if start else None, _parse(end) if end else None
    if not a or not b or b <= a:
        if not rows:
            return ""
        a = _parse(min(r["resolved_at"] for r in rows)) - timedelta(hours=1)
        b = _parse(max(r["resolved_at"] for r in rows)) + timedelta(hours=1)
    buckets, step, fmt = _buckets(a, b)
    sevs = ["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]
    counts = [{s: 0 for s in sevs} for _ in buckets]
    for r in rows:
        t = _parse(r["resolved_at"])
        i = int((t - buckets[0]) / step) if t else -1
        if 0 <= i < len(buckets):
            counts[i][r["severity"] if r["severity"] in sevs else "UNKNOWN"] += 1
    peak = max([sum(c.values()) for c in counts] + [1])
    nice = next(n for n in (1, 2, 4, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000, 2000, 5000, 10**9) if n >= peak)
    left, bottom, top = 40, 24, 10
    pw, ph = width - left - 10, height - bottom - top
    bw = pw / len(buckets)
    t0, t1 = buckets[0], buckets[-1] + step
    x_of = lambda t: left + (t - t0) / (t1 - t0) * pw
    out = [f'<svg viewBox="0 0 {width} {height}" class="chart" role="img" aria-label="Patched findings over time">']
    for k in range(5):
        v = nice * k / 4
        y = top + ph - ph * k / 4
        out.append(f'<line x1="{left}" x2="{width - 10}" y1="{y:.1f}" y2="{y:.1f}" class="grid"/>'
                   f'<text x="{left - 6}" y="{y + 4:.1f}" class="axis" text-anchor="end">{v:g}</text>')
    label_every = max(1, len(buckets) // 10)
    for i, (t, c) in enumerate(zip(buckets, counts)):
        x = left + i * bw
        y = top + ph
        for s in sevs:
            if c[s]:
                h = ph * c[s] / nice
                y -= h
                out.append(f'<rect x="{x + bw * 0.12:.1f}" y="{y:.1f}" width="{max(bw * 0.76, 1):.1f}" height="{h:.1f}" '
                           f'class="bar {s}"><title>{t.strftime("%Y-%m-%d %H:%M")}: {c[s]} {s.lower()}</title></rect>')
        if i % label_every == 0:
            out.append(f'<text x="{x + bw / 2:.1f}" y="{height - 6}" class="axis" text-anchor="middle">{t.strftime(fmt)}</text>')
    for r in runs:
        t = _parse(r["at"])
        if t and t0 <= t <= t1:
            x = x_of(t)
            out.append(f'<line x1="{x:.1f}" x2="{x:.1f}" y1="{top}" y2="{top + ph}" class="annot {escape(r["kind"])}"/>'
                       f'<path d="M{x - 4:.1f},{top + ph + 7} l4,-6 l4,6 z" class="annot-mark {escape(r["kind"])}">'
                       f'<title>{r["at"][:16].replace("T", " ")}: {escape(r["summary"] or "")}</title></path>')
    out.append("</svg>")
    return "".join(out)
