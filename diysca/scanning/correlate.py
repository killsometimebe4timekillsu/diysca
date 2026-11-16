"""Correlate installed packages x repo contents x vulnerability data."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from diysca.core.config import settings
from diysca.core.versions import compare, max_version
from diysca.scanning.collectors import HostFacts, Package
from diysca.scanning.feeds import (
    OSVClient,
    eco_matches,
    fetch_vulns,
    sev_rank,
    vuln_cves,
    vuln_severity,
)
from diysca.scanning.langpkgs import LangPackage


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
    ecosystem: str = ""     # '' = OS package, else PyPI, npm, Maven, ...
    location: str = ""      # language packages: where they were found


def evaluate(affected: dict, version: str, pkg_type: str) -> tuple[bool, str | None]:
    """OSV affected[] entry -> (is_affected, fixed_version)."""
    if version in (affected.get("versions") or []):
        hit, fixed = True, None
    else:
        hit, fixed = False, None
    for rng in affected.get("ranges") or []:
        if rng.get("type") not in ("ECOSYSTEM", "SEMVER", None):
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


def pro_ecosystem(ecosystem: str) -> str | None:
    """Ubuntu:24.04:LTS -> Ubuntu:Pro:24.04:LTS. Ubuntu publishes fixes for most universe packages only through
    Ubuntu Pro (ESM), and OSV lists those under the Pro ecosystem alone. Without it such packages look clean."""
    m = re.fullmatch(r"Ubuntu:(\d+\.\d+):LTS", ecosystem)
    return f"Ubuntu:Pro:{m.group(1)}:LTS" if m and settings.ubuntu_pro_advisories else None


PRO_NOTE = "Fixed only in Ubuntu Pro (ESM); no fix in the standard Ubuntu archive."


async def correlate(facts: HostFacts, ecosystem: str, client: OSVClient,
                    repo_versions: dict[str, str]) -> list[Candidate]:
    pkg_type = facts.pkg_type
    units = query_units(facts)
    keys = list(units)
    out: dict[tuple[str, str], Candidate] = {}
    pro = pro_ecosystem(ecosystem)
    passes = []
    for eco in [ecosystem] + ([pro] if pro else []):
        queries = [{"package": {"name": n, "ecosystem": eco}, "version": v} for n, v in keys]
        id_lists = await client.query_ids(queries)
        passes.append((eco, id_lists, await fetch_vulns(client, {i for ids in id_lists for i in ids})))
    # Ubuntu notices (USN-...) list every CVE of an update, also ones that never applied to this release or were
    # fixed earlier. Ubuntu's own per-CVE record (UBUNTU-CVE-...) says whether this version is affected, so a
    # notice only names the CVEs whose record matched too; with none left it stands under its own id.
    ubuntu_cves: dict[tuple[str, str], set[str]] = {}
    for eco, id_lists, vulns in passes:
        for (name, version), ids in zip(keys, id_lists):
            got = ubuntu_cves.setdefault((name, version), set())
            for i in ids:
                v = vulns.get(i)
                if i.startswith("UBUNTU-CVE-") and v and any(
                        evaluate(a, version, pkg_type)[0] for a in v.get("affected") or []
                        if a.get("package", {}).get("name") == name
                        and eco_matches(a.get("package", {}).get("ecosystem", ""), eco)):
                    got.add(i[len("UBUNTU-"):])
    for eco, id_lists, vulns in passes:
        covered = set(out) if eco == pro else set()  # a CVE the standard archive speaks to is not overridden
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
                           and eco_matches(a.get("package", {}).get("ecosystem", ""), eco)]
                fixed = None
                if entries:
                    hits = [evaluate(a, version, pkg_type) for a in entries]
                    if not any(h for h, _ in hits):
                        continue  # stale server-side match; trust the ranges
                    fixes = [f for h, f in hits if h and f]
                    fixed = max_version(pkg_type, fixes) if fixes else None
                score, sev, _ = vuln_severity(v)
                cves = vuln_cves(v)
                if v["id"].startswith("USN-") and eco.startswith("Ubuntu"):
                    cves = [c for c in cves if c in ubuntu_cves[(name, version)]]
                for cve in cves or [v["id"]]:
                    key = (display, cve)
                    if key in covered:
                        continue
                    c = out.get(key)
                    if c is None:
                        c = out[key] = Candidate(display, version, bins, cve, summary=v.get("summary") or "")
                        if eco == pro:
                            c.summary = (PRO_NOTE + " " + c.summary).strip()
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
                    c.fix_in_repo = bool(repo_v and c.fixed_version
                                         and compare(pkg_type, repo_v, c.fixed_version) >= 0)
    return list(out.values())


async def correlate_lang(pkgs: list[LangPackage], client) -> list[Candidate]:
    """Language packages: same feed, per-ecosystem version semantics, no repo awareness."""
    if not pkgs:
        return []
    queries = [{"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version} for p in pkgs]
    id_lists = await client.query_ids(queries)
    vulns = await fetch_vulns(client, {i for ids in id_lists for i in ids})
    trust_server = not getattr(client, "local_match", False)
    out: dict[tuple[str, str, str], Candidate] = {}
    for p, ids in zip(pkgs, id_lists):
        for vid in ids:
            v = vulns.get(vid)
            if not v or v.get("withdrawn"):
                continue
            entries = [a for a in v.get("affected") or []
                       if a.get("package", {}).get("ecosystem") == p.ecosystem
                       and _same_name(p.ecosystem, a.get("package", {}).get("name", ""), p.name)]
            fixed = None
            if entries:
                hits = [evaluate(a, p.version, p.ecosystem) for a in entries]
                if not any(h for h, _ in hits) and not trust_server:
                    continue
                fixes = [f for h, f in hits if f]
                fixed = max_version(p.ecosystem, fixes) if fixes else None
            score, sev, _ = vuln_severity(v)
            for cve in vuln_cves(v) or [v["id"]]:
                key = (p.ecosystem, p.name, cve)
                c = out.get(key)
                if c is None:
                    c = out[key] = Candidate(p.name, p.version, [], cve, summary=v.get("summary") or "",
                                             ecosystem=p.ecosystem, location=", ".join(p.locations[:3]))
                if v["id"] not in c.osv_ids:
                    c.osv_ids.append(v["id"])
                if fixed and (c.fixed_version is None or compare(p.ecosystem, fixed, c.fixed_version) > 0):
                    c.fixed_version = fixed
                if sev_rank(sev) > sev_rank(c.severity):
                    c.severity = sev
                if score is not None and (c.cvss_score is None or score > c.cvss_score):
                    c.cvss_score = score
    return list(out.values())


def _same_name(eco: str, a: str, b: str) -> bool:
    if eco == "PyPI":
        import re
        n = lambda s: re.sub(r"[-_.]+", "-", s).lower()  # noqa: E731
        return n(a) == n(b)
    return a == b
