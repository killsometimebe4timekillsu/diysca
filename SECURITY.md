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

## How diysca treats untrusted input

* **Scanned systems are untrusted.** Package names, versions, repo URLs, file names and OS facts come from the
  systems diysca scans, and a compromised system (or a container image built by someone else) controls them.
  Generated playbooks only install packages whose names and versions look like real ones, mark every string with
  template markers as `!unsafe` so Ansible never evaluates it, and keep values out of conditions. Still review a
  playbook before you run it.
* **The scan script** runs on the target as the SSH user, which often has more rights than the users who can
  write below the scan paths. It never passes file names or file contents to a program as code.
* **Repo indexes** are only fetched over http(s), never from loopback or link-local addresses (cloud metadata),
  and with size limits.
* **Browsers:** changes sent from another website are refused (CSRF), and redirects only go to diysca's own pages.
* **No login configured means everyone who reaches the UI is an admin.** So diysca only listens on `127.0.0.1`
  without a login, and closes the web UI when API tokens are set but people have no login. `allow_no_login: true`
  lifts that for labs, with a warning on every page.
* **Logins:** OIDC ID token signatures are checked against the provider's keys. Failed logins are limited per
  client address.
* **The web UI reads inventories only from configured paths** (`inventories`, `inventory_dirs`).
