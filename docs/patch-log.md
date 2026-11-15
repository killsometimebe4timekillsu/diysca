# Patch log

One entry for every time diysca patched or helped patch something, exportable for auditors and change
management.

| Kind | Written when | Who |
|---|---|---|
| `playbook` | a patch playbook was generated (UI, API, CLI, MCP) | the user or token that generated it |
| `repo` | a self-hosted repo was synced / published / promoted (aptly, Pulp, Foreman) | who started it, with the result |
| `mitigation` | an approved mitigation finished: done, failed or cancelled | approver and approval time, executor, start and end, last lines of its log |
| `reprovision` | a rebuild playbook was generated from an SBOM | who generated it |

Every entry lists the systems, the number of findings and the CVEs. For mitigations, `verified` shows how many
of the mitigation's findings the rescan found resolved (`3/3`).

## Where

* UI: *Patching > Patch log*, with the time picker (24 h, 7 / 30 / 90 days, a year, custom) and filters for kind,
  status, system, CVE, approver and executor. Buttons export the current view as CSV or JSON.
* API: `GET /api/patchlog?range=30d&kind=mitigation&host=db*` (JSON), `GET /patchlog.csv?...`,
  `GET /mitigations/{id}/log.json` (one mitigation with its full log).
* CLI: `diysca patchlog --range 90d --format csv -o patchlog.csv`
* MCP: the `patch_log` tool.

Users with a host scope only see entries that touch one of their systems.

## Columns

`id, at, kind, status, summary, hosts, findings, cves, approver, approved_at, executor, started_at,
finished_at, verified, mitigation_id, actor, detail`. Lists (`hosts`, `cves`) are space separated in CSV and
arrays in JSON.
