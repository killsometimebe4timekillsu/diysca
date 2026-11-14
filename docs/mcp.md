# MCP server

diysca speaks the [Model Context Protocol](https://modelcontextprotocol.io), so AI agents and MCP clients can look
at your systems and findings and work through approved [mitigations](mitigations.md).

Two transports, the same tools:

| Transport | Start | Auth | Use it for |
|---|---|---|---|
| stdio | `diysca mcp` | whoever can run the command and read config.yml / the database | desktop MCP clients, an agent on the diysca host |
| Streamable HTTP | built into `diysca serve` at `POST <base_url>/mcp` | `Authorization: Bearer <token>` from `api_tokens` | remote agents, agents in other networks |

The HTTP endpoint returns plain JSON responses (no server-sent events) and keeps no session state.
Protocol versions `2025-06-18`, `2025-03-26` and `2024-11-05` are accepted.

## Client configuration

stdio (Claude Desktop, Claude Code and most clients use this shape):

```json
{
  "mcpServers": {
    "diysca": {
      "command": "diysca",
      "args": ["mcp", "--actor", "mcp:laptop"],
      "env": {"DIYSCA_CONFIG": "/etc/diysca/config.yml"}
    }
  }
}
```

With the OCI image: `"command": "podman", "args": ["run", "-i", "--rm", "-v", "/etc/diysca:/config:ro",
"-e", "DIYSCA_CONFIG=/config/config.yml", "ghcr.io/killsometimebe4timekillsu/diysca", "diysca", "mcp"]`.

HTTP:

```json
{
  "mcpServers": {
    "diysca": {
      "type": "http",
      "url": "https://diysca.example.org/mcp",
      "headers": {"Authorization": "Bearer ${DIYSCA_TOKEN}"}
    }
  }
}
```

Claude Code: `claude mcp add --transport http diysca https://diysca.example.org/mcp --header "Authorization: Bearer $DIYSCA_TOKEN"`.

## Tools

| Tool | Read only | What it does |
|---|---|---|
| `list_systems` | yes | Systems with open finding counts. Filters: `host`, `group`, `os`. |
| `search_findings` | yes | Findings, worst first. Filters: `status`, `host`, `group`, `package`, `cve`, `severity`, `fix` (`repo`/`upstream`/`none`), `kev`, `eco`, `approval`, `limit` (default 100). Returns `total` and `findings`. |
| `get_finding` | yes | One finding with its mitigation. |
| `get_sbom` | yes | CycloneDX SBOM of a system (by name or id). |
| `list_patched` | yes | Patched findings in a range (`last`, `24h`, `7d`, `30d`, `90d`, `1y`, `custom` with `from`/`to`). |
| `generate_playbook` | yes | Ansible playbook for `finding_ids` or a `filter`. Doesn't run anything. |
| `list_mitigations` | yes | Mitigations by `status` (`open` default, `approved` = waiting to be claimed). |
| `get_mitigation` | yes | A mitigation with findings, links, log and playbook (`include_playbook`). |
| `claim_mitigation` | no | Claim an approved mitigation. Fails if someone else claimed it. |
| `report_mitigation` | no | `status` = `running`, `done` or `failed`, plus `log`. `done` triggers a rescan. |
| `patch_log` | yes | The patch log over a `range`, filtered by `kind`, `host`, `cve`, `status`. |
| `start_scan` | no | Scan one system (`host`), a selection (`hosts` patterns like `web*,group:prod`, and / or `host_ids`) or every enabled system, and return the results. |
| `approve_findings` | no | Only listed with `agents_can_approve: true`. |
| `cancel_mitigation` | no | Only listed with `agents_can_approve: true`. |

Results are JSON text. Large results are cut at 200,000 characters; narrow the query (`limit`, filters) instead.
Errors (unknown id, mitigation already claimed) come back as tool results with `isError: true`, so the agent can
read them.

## A typical agent loop

1. `list_mitigations {"status": "approved"}`
2. `claim_mitigation {"id": 12}`
3. `get_mitigation {"id": 12}` and save `playbook` to a file
4. `report_mitigation {"id": 12, "status": "running"}`
5. run `ansible-playbook --check --diff`, then for real
6. `report_mitigation {"id": 12, "status": "done", "log": "<last lines of the output>"}`
7. later: `search_findings {"host": "db1"}` or `list_patched {"range": "24h", "host": "db1"}` to confirm

The server sends these hints to the client in its `instructions` at initialization.

## Security

* A token is a key to your vulnerability data: which system has which unpatched hole. Give each agent its own
  token (`api_tokens: {agent-dmz: …}`), so claims and logs show who did what, and you can revoke one.
* Agents can't approve or cancel by default. Approval stays with people unless you set `agents_can_approve: true`.
* `start_scan` makes diysca connect to systems over SSH with its own credentials. It's the only tool that touches
  systems; everything else reads or writes diysca's database.
* Put diysca behind HTTPS (reverse proxy) when the HTTP transport is used across networks.

## Testing by hand

```sh
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' \
              '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_findings","arguments":{"severity":"CRITICAL","limit":3}}}' \
  | diysca mcp

curl -s https://diysca.example.org/mcp -H "Authorization: Bearer $DIYSCA_TOKEN" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq '.result.tools[].name'
```
