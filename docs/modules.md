# Modules

diysca is split into modules. Scanning is the core and is always on. The others can be switched off when
you don't need them, which also removes their pages, API endpoints, MCP tools and settings tabs.

| Module | What it adds | Pages / API |
|---|---|---|
| `core` (always) | database, config, settings import / export, event bus, host scopes | Settings > General, Import / Export |
| `scanning` (always) | inventories and inventory providers, SSH / local / container scans, CVE sources, correlation, SBOM | Systems, Findings, Packages, Settings > CVE Sources, Inventory, `/api/systems`, `/api/findings`, `/api/scan` |
| `alerting` | Apprise channels and subscriptions, alerts after scans and on mitigation changes | Settings > Notifications, `/api/channels` |
| `mitigation` | patch playbooks, repo manager runs, reprovisioning, approvals and hand-off, patch log, patched CVEs | Patching (Patch, Mitigations, Patch log, Patched CVEs), Settings > Repo Manager, Hand-off, `/api/mitigations`, `/api/patchlog` |
| `auth` | OIDC login, roles (viewer, operator, approver, admin), host scopes, audit log | Login, Settings > Access, `/api/me` |

```yaml
modules: [alerting, mitigation, auth]   # default: all of them
```

Examples:

* Inventory and findings only, alerts go to your own SIEM through the API: `modules: []` keeps scanning only.
* A read-only scanner for auditors: `modules: [auth]` plus `rbac.default_role: viewer`.

## How modules talk to each other

Modules don't import each other. The scanner emits events and the other modules subscribe:

| Event | Sent when | Used by |
|---|---|---|
| `scan.finished` | one system was scanned | alerting (new findings), mitigation (verifies running mitigations) |
| `scans.finished` | a scan run ended | alerting (severity changes) |
| `mitigation.status` | a mitigation was approved, claimed, reported or cancelled | alerting, hand-off |
| `audit` | something worth recording happened | auth (audit log) |

Each module describes itself in `diysca/<module>/module.py` (routes, menu entries, tabs, settings tabs, MCP
tools, setup). To write your own, copy one of those files; the registry is in `diysca/core/modules.py`.
