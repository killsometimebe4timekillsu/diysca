"""Human-readable lines about a finding: used by the finding page, alerts and the CLI."""
from __future__ import annotations


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


def action_hint(f) -> str:
    """What to do about a finding, in one line."""
    if f["ecosystem"]:
        return (f"bump {f['package']} to {f['fixed_version']} in the application ({f['location'] or 'see finding'})"
                if f["fixed_version"] else "no fix released yet; check the advisory for workarounds")
    if not f["fixed_version"]:
        return "no fix released yet; check the advisory for workarounds, or ignore it if it doesn't apply"
    if f["fix_in_repo"]:
        return f"{f['repo_version'] or f['fixed_version']} is in your repos: patch it, or approve it for mitigation"
    return (f"the fix ({f['fixed_version']}) isn't in your repos yet: update the repo mirror "
            f"(Patching > Patch), then patch")
