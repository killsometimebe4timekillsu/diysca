"""CycloneDX 1.5 SBOM per system (components + known vulnerabilities)."""
from __future__ import annotations

import json
import uuid
from urllib.parse import quote

from diysca import __version__
from diysca.core import db
from diysca.scanning.describe import UPGRADE_TOOL

PURL_TYPE = {"deb": "deb", "rpm": "rpm", "apk": "apk"}
LANG_PURL = {"PyPI": "pypi", "npm": "npm", "RubyGems": "gem", "Maven": "maven", "Packagist": "composer",
             "crates.io": "cargo", "Go": "golang"}


def lang_purl(eco: str, name: str, version: str) -> str:
    t = LANG_PURL.get(eco, "generic")
    if t == "maven" and ":" in name:
        g, a = name.split(":", 1)
        return f"pkg:maven/{quote(g)}/{quote(a)}@{quote(version)}"
    return f"pkg:{t}/{quote(name, safe='/')}@{quote(version)}"


def purl(pkg_type: str, os_id: str, name: str, version: str, arch: str = "", distro: str = "") -> str:
    p = f"pkg:{PURL_TYPE.get(pkg_type, 'generic')}/{quote(os_id or 'unknown')}/{quote(name)}@{quote(version)}"
    q = []
    if arch:
        q.append(f"arch={quote(arch)}")
    if distro:
        q.append(f"distro={quote(distro)}")
    return p + ("?" + "&".join(q) if q else "")


def build_sbom(host_id: int) -> dict:
    h = db.q1("SELECT * FROM hosts WHERE id=?", (host_id,))
    if h is None:
        raise KeyError(host_id)
    distro = f"{h['os_id']}-{h['os_version']}" if h["os_id"] else ""
    comps, refs = [], {}
    for p in db.q("SELECT * FROM packages WHERE host_id=? ORDER BY ecosystem, name", (host_id,)):
        if p["ecosystem"] == "Apache" and p["source_name"]:
            continue  # module shipped by an OS package: that package is in the SBOM already
        if p["ecosystem"]:
            ref = lang_purl(p["ecosystem"], p["name"], p["version"])
            c = {"type": "library", "bom-ref": f"{ref}#{len(comps)}", "name": p["name"], "version": p["version"],
                 "purl": ref, "properties": [{"name": "diysca:ecosystem", "value": p["ecosystem"]},
                                             {"name": "diysca:location", "value": p["location"] or ""}]}
            refs.setdefault(p["name"], []).append(c["bom-ref"])
            comps.append(c)
            continue
        ref = purl(p["type"], h["os_id"], p["name"], p["version"], p["arch"], distro)
        refs.setdefault(p["source_name"] or p["name"], []).append(ref)
        c = {"type": "library" if p["name"].startswith("lib") else "application", "bom-ref": ref,
             "name": p["name"], "version": p["version"], "purl": ref}
        props = []
        if p["source_name"] and p["source_name"] != p["name"]:
            props.append({"name": "diysca:source_package", "value": p["source_name"]})
        if p["repo_version"]:
            props.append({"name": "diysca:repo_candidate_version", "value": p["repo_version"]})
        if props:
            c["properties"] = props
        comps.append(c)

    for ct in db.q("SELECT * FROM hosts WHERE parent_id=? AND kind='container' ORDER BY name", (host_id,)):
        comps.append({"type": "container", "bom-ref": f"container:{ct['name']}", "name": ct["image"] or ct["name"],
                      "properties": [{"name": "diysca:container_name", "value": ct["name"].split("/", 1)[-1]},
                                     {"name": "diysca:container_runtime", "value": ct["container_runtime"] or ""}]})

    vulns = []
    for f in db.q("""SELECT f.*, v.summary AS vsum, v.refs FROM findings f LEFT JOIN vulns v ON v.id = f.vuln_id
                     WHERE f.host_id=? AND f.status='open' ORDER BY f.cvss_score DESC""", (host_id,)):
        affects = [{"ref": r} for r in refs.get(f["package"], [])]
        entry = {
            "bom-ref": f"{f['vuln_id']}:{f['package']}",
            "id": f["vuln_id"],
            "source": {"name": "NVD" if f["vuln_id"].startswith("CVE-") else "OSV",
                       "url": f"https://osv.dev/vulnerability/{f['vuln_id']}"},
            "ratings": [{"severity": (f["severity"] or "unknown").lower(),
                         **({"score": f["cvss_score"], "method": "CVSSv31"} if f["cvss_score"] else {})}],
            "description": f["summary"] or "",
            "affects": affects,
        }
        if f["fixed_version"]:
            entry["recommendation"] = f"Upgrade {f['package']} to {f['fixed_version']}" + (
                f" (via {UPGRADE_TOOL.get(f['ecosystem'], f['ecosystem'])})" if f["ecosystem"] and f["ecosystem"] != "Apache"
                else " (available in configured repos)" if f["fix_in_repo"] else " (not yet in configured repos)")
        if f["osv_ids"]:
            entry["advisories"] = [{"title": i, "url": f"https://osv.dev/vulnerability/{i}"}
                                   for i in f["osv_ids"].split(",") if i]
        vulns.append(entry)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": h["last_scan"] or db.now(),
            "tools": {"components": [{"type": "application", "name": "diysca", "version": __version__}]},
            "component": {
                "type": "operating-system", "bom-ref": f"host:{h['name']}", "name": h["name"],
                "version": h["os_version"] or "", "description": h["os_pretty"] or "",
                "properties": [{"name": "diysca:address", "value": h["address"] or ""},
                               {"name": "diysca:groups", "value": h["groups"] or ""},
                               {"name": "diysca:kernel", "value": h["kernel"] or ""},
                               {"name": "diysca:arch", "value": h["arch"] or ""},
                               {"name": "diysca:os_id", "value": h["os_id"] or ""},
                               {"name": "diysca:os_version", "value": h["os_version"] or ""},
                               {"name": "diysca:pkg_type", "value": h["pkg_type"] or ""},
                               *[{"name": "diysca:repo", "value": json.dumps(
                                   {"kind": r["kind"], "url": r["url"], "suite": r["suite"] or "",
                                    "components": r["components"] or "", "name": r["name"] or "",
                                    "enabled": bool(r["enabled"])})}
                                 for r in db.q("SELECT * FROM repos WHERE host_id=? ORDER BY id", (host_id,))]],
            },
        },
        "components": comps,
        "vulnerabilities": vulns,
    }


def sbom_json(host_id: int) -> str:
    return json.dumps(build_sbom(host_id), indent=2)
