"""Correlate installed packages x repo contents x vulnerability data."""
from __future__ import annotations

from dataclasses import dataclass, field

from .collectors import HostFacts, Package
from .feeds import OSVClient, fetch_vulns, sev_rank, vuln_cves, vuln_severity
from .versions import compare, max_version


@dataclass
class Candidate:
    package: str            # source package name (what advisories talk about)
    version: str            # installed (source) version
    binaries: list[str]
    vuln_id: str            # CVE id, or advisory id when it has no CVE
    osv_ids: list[str] = field(default_factory=list)
    fixed_version: str | None = None
    repo_version: str | None = None
    fix_in_repo: bool = False
    severity: str = "UNKNOWN"
    cvss_score: float | None = None
    summary: str = ""


def eco_matches(aff_eco: str, eco: str) -> bool:
    if aff_eco == eco:
        return True
    if eco.startswith("Red Hat:"):
        return aff_eco.startswith(":".join(eco.split(":")[:3]))
    return False


def evaluate(affected: dict, version: str, pkg_type: str) -> tuple[bool, str | None]:
    """OSV affected[] entry -> (is_affected, fixed_version)."""
    if version in (affected.get("versions") or []):
        hit, fixed = True, None
    else:
        hit, fixed = False, None
    for rng in affected.get("ranges") or []:
        if rng.get("type") not in ("ECOSYSTEM", None):
            continue
        events = rng.get("events") or []
        intros = [e["introduced"] for e in events if "introduced" in e]
        limits = [("fixed", e["fixed"]) for e in events if "fixed" in e] + \
                 [("last", e["last_affected"]) for e in events if "last_affected" in e]
        for intro in intros:
            if intro != "0" and compare(pkg_type, version, intro) < 0:
                continue
            after = [(k, v) for k, v in limits if intro == "0" or compare(pkg_type, v, intro) > 0]
            after.sort(key=lambda kv: _Key(pkg_type, kv[1]))
            if not after:
                hit = True
                continue
            kind, lim = after[0]
            if kind == "fixed" and compare(pkg_type, version, lim) < 0:
                hit = True
                fixed = lim if fixed is None or compare(pkg_type, lim, fixed) < 0 else fixed
            elif kind == "last" and compare(pkg_type, version, lim) <= 0:
                hit = True
    return hit, fixed


class _Key:
    def __init__(self, t, v):
        self.t, self.v = t, v

    def __lt__(self, o):
        return compare(self.t, self.v, o.v) < 0


def query_units(facts: HostFacts) -> dict[tuple[str, str], list[Package]]:
    """Group installed packages by the (name, version) we ask the feed about."""
    units: dict[tuple[str, str], list[Package]] = {}
    for p in facts.packages:
        if p.type == "rpm":
            names = {p.name, p.source_name or p.name}
            for n in names:
                units.setdefault((n, p.version), []).append(p)
        else:
            units.setdefault((p.source_name or p.name, p.source_version or p.version), []).append(p)
    return units


async def correlate(facts: HostFacts, ecosystem: str, client: OSVClient,
                    repo_versions: dict[str, str]) -> list[Candidate]:
    pkg_type = facts.pkg_type
    units = query_units(facts)
    keys = list(units)
    queries = [{"package": {"name": n, "ecosystem": ecosystem}, "version": v} for n, v in keys]
    id_lists = await client.query_ids(queries)
    all_ids = {i for ids in id_lists for i in ids}
    vulns = await fetch_vulns(client, all_ids)

    out: dict[tuple[str, str], Candidate] = {}
    for (name, version), ids in zip(keys, id_lists):
        bins = sorted({p.name for p in units[(name, version)]})
        display = units[(name, version)][0].source_name or name
        repo_v = max_version(pkg_type, [repo_versions.get(b) for b in bins])
        for vid in ids:
            v = vulns.get(vid)
            if not v or v.get("withdrawn"):
                continue
            entries = [a for a in v.get("affected") or []
                       if a.get("package", {}).get("name") == name
                       and eco_matches(a.get("package", {}).get("ecosystem", ""), ecosystem)]
            fixed = None
            if entries:
                hits = [evaluate(a, version, pkg_type) for a in entries]
                if not any(h for h, _ in hits):
                    continue  # stale server-side match; trust the ranges
                fixes = [f for h, f in hits if h and f]
                fixed = max_version(pkg_type, fixes) if fixes else None
            score, sev, _ = vuln_severity(v)
            for cve in vuln_cves(v) or [v["id"]]:
                key = (display, cve)
                c = out.get(key)
                if c is None:
                    c = out[key] = Candidate(display, version, bins, cve, summary=v.get("summary") or "")
                c.binaries = sorted(set(c.binaries) | set(bins))
                if v["id"] not in c.osv_ids:
                    c.osv_ids.append(v["id"])
                if fixed and (c.fixed_version is None or compare(pkg_type, fixed, c.fixed_version) > 0):
                    c.fixed_version = fixed
                if sev_rank(sev) > sev_rank(c.severity):
                    c.severity = sev
                if score is not None and (c.cvss_score is None or score > c.cvss_score):
                    c.cvss_score = score
                if not c.summary and v.get("summary"):
                    c.summary = v["summary"]
                c.repo_version = repo_v
                c.fix_in_repo = bool(repo_v and c.fixed_version and compare(pkg_type, repo_v, c.fixed_version) >= 0)
    return list(out.values())
