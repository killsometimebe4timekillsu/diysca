# Security policy

diysca logs into your systems over SSH and generates patch playbooks, so security problems in it matter.
Please **don't open a public issue** for them.

## Reporting a vulnerability

Report it privately through GitHub:
[Security → Report a vulnerability](https://github.com/killsometimebe4timekillsu/diysca/security/advisories/new).

Please include:

* what an attacker can do (for example: run commands on the diysca server or on scanned hosts, read secrets,
  bypass login or roles, change findings or approvals)
* what the attacker needs first (network access to the UI, a viewer account, an API token, control of a
  scanned host, ...)
* steps or a proof of concept, and the diysca version (`diysca --version`) and install type

You'll get an answer within a week. Fixes are released as soon as they're ready, and the advisory is
published once a fixed version is out. Tell us if you'd like to be credited.

## Supported versions

Only the latest release gets security fixes.

## Scope

In scope: the diysca server, web UI, API, MCP endpoint, CLI, the scripts it runs on scanned hosts, the
playbooks it generates, and the packages and OCI image built from this repository.

Out of scope: vulnerabilities that diysca *reports* in your systems (that's its job), and problems that need
an admin account to exploit, unless they let that admin break out of what diysca is meant to allow.
