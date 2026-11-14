"""Mitigation: patch playbooks, repo managers, reprovisioning, approvals and hand-off, patched CVEs, patch log."""
from diysca.core.modules import Module

MODULE = Module(
    name="mitigation", title="Mitigation",
    description="Playbooks, repo updates, approvals handed to agents and CI/CD, the patch log and patched CVEs.",
    routes="diysca.mitigation.routes",
    nav=[("patching", "/patching", "Patching", "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 16.5V8M8 11.5l4-4 4 4", 30)],
    tabs={"patching": [("patching", "/patching", "Patch", 0), ("mitigations", "/mitigations", "Mitigations", 10),
                       ("patchlog", "/patchlog", "Patch log", 20), ("patched", "/patched", "Patched CVEs", 30)]},
    settings_tabs=[("repos", "/settings/repos", "Repo Manager", 30), ("handoff", "/settings/handoff", "Hand-off", 40)],
    mcp_tools=("list_patched", "generate_playbook", "list_mitigations", "get_mitigation", "claim_mitigation",
               "report_mitigation", "approve_findings", "cancel_mitigation", "patch_log"),
    openapi_tags=[{"name": "mitigations", "description": "Approved findings handed to agents, CI/CD or people who can reach the systems."},
                  {"name": "patch log", "description": "One record per patching: what, when, who approved, who ran it, result."},
                  {"name": "patched", "description": "What was fixed, when and how."}],
)
