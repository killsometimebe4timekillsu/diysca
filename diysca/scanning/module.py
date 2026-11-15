"""Scanning: inventory (Ansible and other providers), collectors, CVE sources, correlation, SBOM. Always on."""
from diysca.core.modules import Module

MODULE = Module(
    name="scanning", title="Scanning",
    description="Finds systems, reads their packages and repos, matches them against CVE sources, builds SBOMs.",
    routes="diysca.scanning.routes",
    nav=[("systems", "/systems", "Systems", "M3 4h18v6H3zM3 14h18v6H3zM7 7h.01M7 17h.01", 10),
         ("findings", "/findings", "Findings", "M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6zM12 8v5M12 16h.01", 20)],
    tabs={"findings": [("findings", "/findings", "Findings", 0), ("packages", "/packages", "Packages", 10)]},
    settings_tabs=[("sources", "/settings/sources", "CVE Sources", 10), ("inventory", "/settings/inventory", "Inventory", 15)],
    mcp_tools=("list_systems", "search_findings", "get_finding", "get_sbom", "start_scan"),
    openapi_tags=[{"name": "inventory", "description": "Systems and installed packages."},
                  {"name": "findings", "description": "Vulnerable packages per system (open, ignored, resolved)."},
                  {"name": "sources", "description": "Vulnerability data sources."},
                  {"name": "scans", "description": "Start scans."}],
)
