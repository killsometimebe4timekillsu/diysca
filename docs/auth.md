# Login, roles and audit (auth module)

Without any configuration diysca is open, like before: put it behind a VPN or a TLS reverse proxy. There
are three ways to log in, and they can be combined:

| Who | How | Role |
|---|---|---|
| People | OIDC single sign-on (Keycloak, Entra ID, Authentik, Zitadel, Okta, Google, GitLab, Dex, ...) | from `rbac.bindings` |
| Break-glass admin | `web_user` / `web_password` (HTTP basic auth) | always admin |
| Agents, CI/CD, MCP clients | `api_tokens` (Bearer), only on `/api/*` and `/mcp` | per token, default operator |

## OIDC

```yaml
base_url: https://diysca.example.org
oidc:
  issuer: https://sso.example.org/realms/acme
  client_id: diysca
  client_secret_env: DIYSCA_OIDC_SECRET
  scopes: [openid, profile, email, groups]
  username_claim: preferred_username
  groups_claim: groups              # Keycloak realm roles: realm_access.roles, Entra ID: groups or roles
```

At the provider, register a confidential client with the redirect URI `<base_url>/auth/callback` and the
post-logout URI `<base_url>/login`. diysca uses the authorization code flow with PKCE. It checks the ID
token's issuer, audience, expiry and nonce; the token comes straight from the provider's token endpoint over
TLS, so (as the OIDC spec allows) its signature is not checked. If the ID token has no groups, the userinfo
endpoint is asked.

Sessions are signed cookies (HttpOnly, SameSite=Lax, Secure when `base_url` is https), valid for
`session_hours` (default 8). The signing key is `session_secret`, or a random key in `<data_dir>/session.key`.
A role change takes effect at the next login.

## Roles

Each role includes the ones before it.

| Role | Can |
|---|---|
| `viewer` | see systems, findings, packages, SBOMs, mitigations, patched CVEs, the patch log |
| `operator` | + start scans, ignore / reopen findings, generate playbooks, claim and report mitigations, saved filters |
| `approver` | + approve and cancel mitigations |
| `admin` | + every setting: CVE sources, inventory, channels, subscriptions, hand-off, repo manager runs, systems, import |

```yaml
rbac:
  default_role: ""                  # users no binding matches: "" = no access, or viewer
  bindings:
    - {group: secops, role: admin}
    - {group: dba, role: approver, hosts: "group:db"}
    - {user: alice, role: approver}
    - {email: "*@ops.example.org", role: operator}
```

The highest matching role wins. `hosts` limits a binding to some systems, with the pattern syntax of alert
subscriptions (`web*`, `group:prod`, `!test-*`). A user with a scope only sees those systems, their findings,
mitigations and patch log entries, and can only scan and approve those. If one of the user's bindings for the
winning role has no `hosts`, the user sees everything.

API tokens get a role and a scope the same way:

```yaml
api_tokens:
  ci: {token: "long-random-string", role: operator, hosts: "group:dmz"}
  auditor: {token: "...", role: viewer}
  legacy: "plain-string"            # operator (approver with agents_can_approve: true)
```

MCP tools follow the roles too: viewers get the read tools, operators also `start_scan`, `claim_mitigation`
and `report_mitigation`, approvers also `approve_findings` and `cancel_mitigation`.

## Audit log

Every change (each non-GET request), every login, failed login and logout is recorded with who, role, what,
the HTTP status and the client address. *Settings > Access* shows it and exports it as CSV. Entries older than
`audit_days` (default 365) are removed.
