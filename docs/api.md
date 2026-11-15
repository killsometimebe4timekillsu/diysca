# API

diysca has a JSON API for scripts, dashboards, CI/CD jobs and agents. Everything the web UI shows can be read
through it, and mitigations can be worked through end to end.

* Interactive reference (OpenAPI / Swagger UI): `<base_url>/docs`; machine-readable: `<base_url>/openapi.json`
* AI agents: the same functions as [MCP tools](mcp.md)

## Authentication

| Who | How | Opens |
|---|---|---|
| People | OIDC login (session cookie) or HTTP basic auth with `web_user` / `web_password` | web UI and API |
| Agents, CI/CD, MCP clients | `Authorization: Bearer <token>`, tokens from `api_tokens` | `/api/*` and `/mcp` only |
| Probes | nothing | `/healthz` |

```yaml
# config.yml
web_user: admin
web_password: change-me
api_tokens:
  ci: 3f9c…            # openssl rand -hex 32
  grafana: 81aa…
agents_can_approve: false
```

or `DIYSCA_API_TOKENS=ci:3f9c…,grafana:81aa…`. The token's name is recorded as `token:<name>` when it claims or
reports a mitigation.

With the auth module, every caller has a role (viewer, operator, approver, admin) and optionally a host scope;
tokens get them per token: `api_tokens: {ci: {token: "…", role: operator, hosts: "group:dmz"}}`. A call outside
the role answers `403`, systems outside the scope are invisible (`404`). `GET /api/me` shows who you are. See
[auth.md](auth.md).

Without any login configured, everything is open, and diysca then only listens on `127.0.0.1`. Once
`api_tokens` are set, `/api/*` always needs a token or the basic-auth login, and the web pages need a login for
people too (`web_user` / `web_password` or OIDC), because an open UI would bypass the tokens' roles. A lab can lift
both with `allow_no_login: true`. After 5 failed logins an address has to wait (`429` with `Retry-After`).

## Conventions

* JSON in, JSON out. Times are ISO 8601 in UTC (`2026-11-14T22:10:00+00:00`).
* List endpoints take the **same query parameters as the filters in the UI**, so you can copy a filtered page's
  query string: `/findings?group=prod&fix=repo` → `/api/findings?group=prod&fix=repo`. The *JSON* link on the
  Findings and Patched pages does exactly that.
* Text filters are case-insensitive substring matches; `*` is a wildcard.
* Errors: `401` (no or wrong credentials), `403` (not allowed, e.g. a token approving), `404`, `409` (state
  conflict, e.g. claiming a mitigation someone else claimed), `422` (invalid input). The body is
  `{"detail": "…"}`.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/hosts` | systems |
| GET | `/api/packages` | installed packages |
| GET | `/api/findings` | findings (vulnerable packages) |
| GET | `/api/findings/{id}` | one finding |
| GET | `/api/hosts/{id}/repos` | package repositories of a system, with the result of reading each index |
| GET | `/api/hosts/{id}/sbom` | CycloneDX SBOM of a system |
| GET | `/api/patched` | patched findings in a time range |
| GET | `/api/sources` | extra vulnerability sources |
| POST | `/api/scan` | scan all, one or selected systems |
| GET | `/api/patchlog` | the patch log (also `/patchlog.csv`) |
| GET | `/api/me` | the caller's name, role and scope |
| GET | `/api/mitigations` | mitigations |
| POST | `/api/mitigations` | approve findings |
| GET | `/api/mitigations/{id}` | one mitigation, with playbook |
| GET | `/api/mitigations/{id}/playbook.yml` | its playbook |
| POST | `/api/mitigations/{id}/claim` | claim it |
| POST | `/api/mitigations/{id}/report` | report running / done / failed |
| POST | `/api/mitigations/{id}/cancel` | cancel it |
| POST | `/mcp` | MCP (JSON-RPC 2.0) |
| GET | `/healthz` | health check |

### GET /api/hosts

| Parameter | Meaning |
|---|---|
| `host` | name or address |
| `group` | Ansible inventory group (exact) |
| `os` | OS name or version, e.g. `rocky`, `24.04` |
| `kind` | `host` or `container` |
| `status` | last scan status: `ok`, `partial`, `error` |

```sh
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/api/hosts?group=prod" | jq '.[] | {name, os_pretty, last_scan}'
```

### GET /api/packages

| Parameter | Meaning |
|---|---|
| `name`, `version` | package name / version |
| `host`, `group`, `os`, `kind` | as for hosts |
| `eco` | `os` (distro packages), `lang` (all language packages), or one ecosystem: `PyPI`, `npm`, `Maven`, `RubyGems`, `Go`, `crates.io`, `Packagist` |
| `vulnerable=1` | only packages with open findings |
| `upgradable=1` | only packages where the repos offer a newer version |

```sh
# where is log4j-core installed?
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/api/packages?name=log4j-core" | jq -r '.[] | "\(.host_name) \(.version) \(.location)"'
```

### GET /api/findings

Worst first: known exploited, then severity, then CVSS. At most 5000 rows.

| Parameter | Meaning |
|---|---|
| `status` | `open` (default), `ignored`, `resolved`, `all` |
| `host`, `group`, `os`, `kind` | as for hosts |
| `package` | source or binary package name |
| `cve` | CVE or advisory id (`CVE-2025-`, `DSA-5850`, `GHSA-`) |
| `severity` | minimum: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `fix` | `repo` (the fix is in the system's repos), `upstream` (released, not in your repos yet), `none` |
| `kev=1` | only CISA known exploited |
| `eco` | as for packages |
| `approval` | `approved` (in an open mitigation), `unapproved` |

Each finding has: `id`, `host_id`, `host_name`, `package`, `version`, `ecosystem` (empty for distro packages),
`location` (lockfile or directory of a language package), `binaries`, `vuln_id`, `cve`, `osv_ids` (distro
advisories), `summary`, `severity`, `cvss_score`, `kev`, `epss`, `fixed_version`, `repo_version`, `fix_in_repo`,
`status`, `first_seen`, `last_seen`, `resolved_at`, `resolved_version`, `resolution`, `mitigation_id`,
`mitigation_status`.

```sh
# critical, fixable today, prod: count per system
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/api/findings?group=prod&severity=CRITICAL&fix=repo" \
  | jq 'group_by(.host_name) | map({host: .[0].host_name, n: length})'
```

### GET /api/findings/{id}

One finding (all fields above) plus `mitigation`: the mitigation it was last approved in, or `null`.

### GET /api/hosts/{id}/repos

The repositories configured on the system, as read at its last scan. Each has `kind` (`apt`, `yum`, `apk`), `url`,
`suite`, `components`, `name`, `file`, `enabled`, `status` (`ok`, `error`, `disabled`, `skipped`), `error` (why the
index could not be read, or a note such as the priority of a backports repo), `pkg_count` and `fetched_at`.

```sh
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/api/hosts/3/repos" | jq '.[] | select(.status=="error")'
```

### GET /api/hosts/{id}/sbom

CycloneDX 1.5 JSON: OS packages and language packages as components with package URLs, container images,
and in `metadata.properties` the OS (`diysca:os_id`, `diysca:os_version`, `diysca:pkg_type`) and the configured
repositories (`diysca:repo`). The UI download is at `/systems/{id}/sbom.json`.

### GET /api/patched

| Parameter | Meaning |
|---|---|
| `range` | `last` (each system's most recent patching), `24h`, `7d`, `30d`, `90d`, `1y`, `custom` |
| `from`, `to` | `YYYY-MM-DD`, with `range=custom` |
| `host`, `group` | as for hosts |
| `severity` | minimum severity |
| `eco` | as for packages |
| `how` | `upgraded`, `removed`, `not-affected` |

Returns `{"range", "start", "end", "stats", "findings"}`. `stats` has `cves`, `findings`, `systems`,
`critical_high`, `kev`, `median_days` (first seen to gone), `upgraded`, `removed`, `open_now`. Each finding has `resolved_at`, `resolved_version`,
`resolution` and `days_open`.

```sh
# weekly report: what got patched in the last 7 days
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/api/patched?range=7d" | jq '.stats'
```

### GET /api/sources

The extra vulnerability sources (Debian tracker, Alpine secdb, OSV feeds, custom feeds, EPSS) with `name`, `type`,
`origin` (`config` or `ui`), `enabled`, `fetched_at`, `count`, `status`, `error`. Header values are masked.

### POST /api/scan

| Parameter | Scans |
|---|---|
| none | every enabled system |
| `host=web1` | that system (returns one result object) |
| `hosts=web*,group:prod,!test-*` | systems matching the patterns (the syntax of alert subscriptions) |
| `id=3&id=7` | those systems by id, disabled ones too |
| `wait=false` | start in the background, answer `202 {"started": [names]}` |

`hosts` and `id` combine; no match answers `404`. Only systems in the caller's scope are scanned.

```sh
curl -X POST -H "Authorization: Bearer $TOKEN" "https://diysca.example.org/api/scan?hosts=group:dmz&wait=false"
```

Without `wait=false` the request waits for the scan and returns the result per system (`host`, `packages`, `language_packages`, `open_findings`, `alerts_sent`, `error`, and `containers` for the containers on it). Use a long client timeout for full scans.

### GET /api/patchlog

One entry per patching: generated playbooks, repo updates, finished mitigations, rebuild playbooks, with
approver, executor, times, systems, CVEs and result. Same filters as the UI (`range`, `from`, `to`, `kind`,
`status`, `host`, `cve`, `approver`, `executor`). `/patchlog.csv` gives the same as CSV. See
[patch-log.md](patch-log.md).

### Mitigations

See [mitigations.md](mitigations.md) for the workflow and CI/CD examples.

**GET /api/mitigations?status=** `open` (default: approved, claimed or running), `approved`, `claimed`, `running`,
`done`, `failed`, `cancelled`, `all`. Each entry: `id`, `status`, `created_at`, `approved_by`, `note`,
`handoff`, `handoff_result`, `claimed_by`, `claimed_at`, `updated_at`, `summary` (`findings`, `hosts`,
`worst_severity`, `kev`, `cves`, `playbook_hosts`, `playbook_packages`, `manual_items`), `findings` (count),
`still_open`, `links`.

**POST /api/mitigations** (status 201)

```json
{"filter": "group=prod&fix=repo&severity=HIGH", "note": "CHG-1234", "handoff": "gh-actions", "rescan": true}
```

`finding_ids: [1, 2, 3]` instead of `filter` works too. Only open findings are taken. Without `handoff`, the
targets marked *send every approval* get it; with none, agents pull it. Tokens get `403` unless
`agents_can_approve: true`. `422` when nothing open was selected or the target doesn't exist.

**GET /api/mitigations/{id}** the mitigation with `findings` (list), `hosts`, `open_findings`, `playbook`,
`log`, `rescan`, `links`.

**GET /api/mitigations/{id}/playbook.yml** the playbook (YAML) stored at approval time.

**POST /api/mitigations/{id}/claim** no body. `200` with the mitigation, or `409` if it isn't `approved` any more.

**POST /api/mitigations/{id}/report**

```json
{"status": "done", "log": "PLAY RECAP ... ok=5 changed=2 failed=0"}
```

`status` is `running`, `done` or `failed`. `log` is appended to the mitigation's log (up to 20,000 characters per
report). On `done` the response has `rescan_hosts`: the names of the systems being rescanned. `409` if the mitigation is
already done or cancelled.

**POST /api/mitigations/{id}/cancel** optional `{"reason": "…"}`. The findings can be approved again. Tokens
need `agents_can_approve`.

### POST /mcp

JSON-RPC 2.0 for MCP clients (`initialize`, `tools/list`, `tools/call`, `ping`). See [mcp.md](mcp.md).

### GET /healthz

`{"ok": true, "version": "0.2.3"}`, without authentication. Use it for container and orchestrator probes.

## Examples

**Grafana (Infinity data source):** URL `https://diysca.example.org/api/findings?severity=HIGH`, auth *Bearer
token*, parser JSON. Group by `host_name` for a per-system bar chart; `/api/patched?range=30d` for a
patched-per-day panel.

**Fail a pipeline on known exploited, fixable findings:**

```sh
n=$(curl -sf -H "Authorization: Bearer $TOKEN" "$BASE/api/findings?host=$HOST&kev=1&fix=repo" | jq length)
[ "$n" -eq 0 ] || { echo "$n known exploited findings with a fix available on $HOST"; exit 1; }
```

**Python:**

```python
import httpx
c = httpx.Client(base_url="https://diysca.example.org", headers={"Authorization": f"Bearer {TOKEN}"})
for f in c.get("/api/findings", params={"severity": "CRITICAL", "fix": "repo"}).json():
    print(f["host_name"], f["vuln_id"], f["package"], f["version"], "->", f["repo_version"])
```
