# Approving findings for mitigation

diysca often can't reach the systems it reports on: another network zone, an air gap, or a deployment owned by
another team or pipeline. Instead of patching them itself, a person **approves** findings. The approval becomes a
**mitigation**: a work item with the findings, an Ansible playbook pinned to the versions your repos offer, and
links to report back. Whoever *can* reach the systems picks it up: an agent, a CI/CD pipeline, an MCP client or a
colleague.

```
 person approves        hand-off                         agent / CI / person          diysca
 ───────────────►  approved ──► claimed ──► running ──► done ──────────────────► rescan, Patched CVEs
                       │                            └──► failed  (alert channels are told)
                       └──► cancelled  (findings can be approved again)
```

## Approve

* **Findings page:** select findings (or use the current filter), open *Approve for mitigation…*, add a note
  (change number, maintenance window), pick a hand-off target if you want, then *Approve selected* or
  *Approve everything in this filter*.
* **Finding page:** *Approve for mitigation*.
* **CLI:** `diysca mitigations approve --filter 'group=prod&fix=repo&severity=HIGH' --note CHG-1234 [--handoff gh-actions]`
* **API:** `POST /api/mitigations` with `{"filter": "host=web1&fix=repo", "note": "CHG-1234"}` or `{"finding_ids": [1, 2]}`.

Only **open** findings are taken, and findings that already are in an open mitigation (approved, claimed or
running) are left out, so the same finding is never handed out twice. The playbook is created at approval time and stored with the mitigation, so it
doesn't change under the agent's feet. Language packages, container images and fixes that aren't in your repos yet
are listed as comments at the top of the playbook, the same as on *Patching > Patch*.

Approving is a person's decision. API tokens (agents, CI/CD, MCP) can claim and report but **can't approve or
cancel** unless you set `agents_can_approve: true`.

Approved findings show a `#12 approved` tag on the Findings page. Filter with *Approval: approved, in progress* or
*not approved*.

## Hand off

**Pull** (no setup): agents ask diysca for work.

```sh
TOKEN=...   # from api_tokens in config.yml
curl -s -H "Authorization: Bearer $TOKEN" "https://diysca.example.org/api/mitigations?status=approved"
```

**Push**: add a target under *Settings > Hand-off*. Pick it when approving, or tick *send every approval*.

| Type | URL | Token | What is sent |
|---|---|---|---|
| `webhook` | any `https://` URL | sent as `Authorization: Bearer` | `POST` with the [full payload](#webhook-payload) (JSON) |
| `github` | `https://github.com/OWNER/REPO` (converted to the dispatches API) | fine-grained PAT with *Contents: write* on the repo | `repository_dispatch`, event type `diysca-mitigation` |
| `gitlab` | `https://gitlab.example.org/api/v4/projects/ID/trigger/pipeline` | pipeline trigger token | pipeline on `ref` (default `main`) with `DIYSCA_*` variables |

The delivery result (`gh-actions: HTTP 204`) is on the mitigation's page and in its log. *Hand off* on that page
sends it again or to another target.

## Claim, run, report

```sh
BASE=https://diysca.example.org; H="Authorization: Bearer $TOKEN"; ID=12
curl -sf -X POST -H "$H" $BASE/api/mitigations/$ID/claim             # 409 if someone else was faster
curl -sf -H "$H" $BASE/api/mitigations/$ID/playbook.yml -o mitigation.yml
curl -sf -X POST -H "$H" -H 'Content-Type: application/json' $BASE/api/mitigations/$ID/report -d '{"status":"running"}'
if ansible-playbook -i inventory mitigation.yml > run.log 2>&1; then STATUS=done; else STATUS=failed; fi
jq -n --arg s $STATUS --rawfile log run.log '{status:$s, log:($log|.[-20000:])}' |
  curl -sf -X POST -H "$H" -H 'Content-Type: application/json' $BASE/api/mitigations/$ID/report -d @-
```

* `claim` moves `approved` to `claimed` and records who claimed it (the token's name, e.g. `token:ci`).
* `report` takes `running`, `done` or `failed` plus an optional `log`. Reporting without claiming first is allowed
  (the reporter becomes the claimer). `failed` can be followed by another `running` / `done`.
* On `done`, the systems are rescanned in the background (unless approved with `rescan: false`). Findings the
  rescan no longer sees move to *Patched CVEs*, and the patch run shows up as an annotation there.
* People can set the status by hand on the mitigation's page, e.g. when a colleague patched it manually.

Run the playbook with `--check --diff` first if your process requires a dry run. Inventory host names must match the
system names in diysca (the playbook targets them by name).

### GitHub Actions example

```yaml
# .github/workflows/diysca.yml in the repo that holds your inventory
on:
  repository_dispatch:
    types: [diysca-mitigation]
jobs:
  patch:
    runs-on: [self-hosted, prod-network]      # a runner that can reach the systems
    steps:
      - uses: actions/checkout@v4
      - name: Claim and fetch the playbook
        env: { TOKEN: "${{ secrets.DIYSCA_TOKEN }}", P: "${{ toJson(github.event.client_payload) }}" }
        run: |
          ID=$(jq -r .mitigation_id <<<"$P")
          curl -sf -X POST -H "Authorization: Bearer $TOKEN" "$(jq -r .playbook_url <<<"$P" | sed 's#/playbook.yml#/claim#')"
          curl -sf -H "Authorization: Bearer $TOKEN" "$(jq -r .playbook_url <<<"$P")" -o mitigation.yml
      - name: Patch
        run: ansible-playbook -i inventory/prod mitigation.yml | tee run.log
      - name: Report
        if: always()
        env: { TOKEN: "${{ secrets.DIYSCA_TOKEN }}", URL: "${{ github.event.client_payload.report_url }}" }
        run: |
          S=$([ "${{ job.status }}" = success ] && echo done || echo failed)
          jq -n --arg s $S --rawfile log run.log '{status:$s, log:($log|.[-20000:])}' |
            curl -sf -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$URL" -d @-
```

`client_payload` has: `mitigation_id`, `hosts` (comma separated), `findings` (count), `worst_severity`,
`approved_by`, `note`, `playbook_url`, `report_url`, `ui_url`.

### GitLab CI example

```yaml
diysca:
  rules: [{ if: '$DIYSCA_MITIGATION_ID' }]
  tags: [prod-network]
  script:
    - 'curl -sf -X POST -H "Authorization: Bearer $DIYSCA_TOKEN" "${DIYSCA_REPORT_URL%/report}/claim"'
    - 'curl -sf -H "Authorization: Bearer $DIYSCA_TOKEN" "$DIYSCA_PLAYBOOK_URL" -o mitigation.yml'
    - ansible-playbook -i inventory/prod mitigation.yml | tee run.log
  after_script:
    - S=$([ "$CI_JOB_STATUS" = success ] && echo done || echo failed)
    - "jq -n --arg s $S --rawfile log run.log '{status:$s, log:($log|.[-20000:])}' | curl -sf -X POST -H \"Authorization: Bearer $DIYSCA_TOKEN\" -H 'Content-Type: application/json' \"$DIYSCA_REPORT_URL\" -d @-"
```

Variables: `DIYSCA_MITIGATION_ID`, `DIYSCA_HOSTS`, `DIYSCA_PLAYBOOK_URL`, `DIYSCA_REPORT_URL`, `DIYSCA_UI_URL`.
`DIYSCA_TOKEN` is a CI/CD variable you add yourself.

### Webhook payload

```json
{
  "event": "mitigation.approved",
  "diysca": "0.2.4",
  "mitigation": {"id": 12, "status": "approved", "created_at": "2026-11-14T22:10:00+00:00", "approved_by": "alice",
                 "note": "CHG-1234", "hosts": ["db1", "web1"],
                 "summary": {"findings": 7, "hosts": ["db1", "web1"], "worst_severity": "CRITICAL", "kev": 1,
                             "cves": ["CVE-2025-1094", "..."], "cves_total": 7, "playbook_hosts": 2, "playbook_packages": 5, "manual_items": 2}},
  "findings": [{"id": 812, "host": "db1", "package": "postgresql-16", "version": "16.6-1~deb12u1", "ecosystem": "",
                "vuln_id": "CVE-2025-1094", "severity": "CRITICAL", "cvss_score": 9.8, "kev": 1, "epss": 0.61,
                "fixed_version": "16.7-0+deb12u1", "repo_version": "16.7-0+deb12u1", "fix_in_repo": 1, "status": "open"}],
  "links": {"ui": ".../mitigations/12", "self": ".../api/mitigations/12", "playbook": ".../api/mitigations/12/playbook.yml",
            "claim": ".../api/mitigations/12/claim", "report": ".../api/mitigations/12/report"},
  "playbook": "# Generated by diysca ...\n---\n- name: ..."
}
```

`summary.cves` lists at most 50 CVE ids; `summary.cves_total` is the full count, and `findings` always has them all.

Extra headers for a webhook (e.g. an API key header) go in its `headers:` when you import the target as YAML
(*Settings > Import / Export*):

```yaml
handoffs:
  - name: soar
    type: webhook
    url: https://soar.example.org/api/diysca
    token: "***"          # *** keeps the stored token
    auto: true
    headers: {X-Tenant: security}
```

## Agents and MCP

An MCP client (an AI agent with shell access in the right network, for example) can do the whole loop with the
`list_mitigations`, `get_mitigation`, `claim_mitigation` and `report_mitigation` tools. See [mcp.md](mcp.md).

## Settings

```yaml
api_tokens:                 # name: token. Name shows up as token:<name> in claims and logs
  ci: "long-random-string"
  agent-dmz: "another-one"
agents_can_approve: false   # true lets token holders approve and cancel too
base_url: https://diysca.example.org   # used in every link that is handed off
```

Generate tokens with `openssl rand -hex 32`. Tokens only open `/api/*` and `/mcp`, not the web UI.
