# Changelog

All notable changes to diysca. Versions follow [semantic versioning](https://semver.org/) (0.x: minor
versions may change behaviour). Dates are release dates (UTC).

## [Unreleased]

## [0.2.6] - 2026-11-17

### Added
- Go and Rust programs installed as plain binaries (`/usr/local/bin/gh`, release tarballs in `/opt`) are
  scanned: the Go standard library version and the Go modules from the build info, and the crates of Rust
  programs built with cargo-auditable. Needs only `od`, `head`, `tr` and `find`, so BusyBox works too.
  Settings `scan_binaries` (default on) and `binary_scan_paths` (default: the language scan paths).

### Fixed
- Go, npm and crates.io versions are compared by semver precedence. Pre-releases ranked above the release,
  so for example Go 1.26.2 matched GO-2023-1987.

## [0.2.5] - 2026-11-16

### Fixed
- OSV bulk mode downloads the maintained ecosystem exports (`Debian/all.zip`, `Ubuntu/all.zip`) and filters
  them by release. The per-release exports it used before stopped being updated in October 2024, so newer
  CVEs were missed. A warning goes to the events when a feed's newest advisory is older than 14 days.
- Ubuntu notices (USN) only name the CVEs whose own Ubuntu record matches the installed version.

### Added
- Fixes that Ubuntu publishes only through Ubuntu Pro (ESM) are reported and marked as such (setting
  `ubuntu_pro_advisories`, default on).

## [0.2.4] - 2026-11-16

### Security
- Systems whose name Ansible would read as a host pattern (`all`, `web*`, `a,b`) are listed for manual
  patching instead of becoming a play target.
- Inventory providers can no longer take over a system that another source or a person added under the
  same name.
- The system filter matches whole names (`web1` no longer matches `web10`); `%` and `_` are literal.
- Host scopes: a scoped user only sees their own findings of a mitigation, not its playbook, and can't
  claim, report on or cancel a mitigation that covers systems outside their scope.
- Roles are worked out from the bindings on every request; unverified OIDC email addresses don't match
  email bindings; malformed session cookies are rejected instead of causing a 500.

### Fixed
- One scan per system at a time; database and parsing work run off the event loop; local and SSH commands
  are stopped on timeout, including the processes the shell started; one failing system no longer ends a
  scan of all.
- `/healthz` answers 503 while the database is down; missing columns are added on every start.
- Bad JSON bodies and a deleted system in a repo update give 4xx instead of 500.

### Changed
- Error pages for browsers, JSON errors for API clients.
- Config mistakes are named: invalid YAML, wrong types, unknown keys with a hint.
- The Findings page says when its list is cut at 5000 rows; approving by filter and `diysca playbook` are
  never cut.

## [0.2.3] - 2026-11-16

### Added
- Each system's package repositories: a repo list in the Systems table, a repositories card at the top of
  the system page with the number of unreadable repos and their errors, and `GET /api/hosts/{id}/repos`.

### Fixed
- CI: the Flatpak is built with the runner's own SDK copy, so a new Flathub SDK no longer breaks the build.

## [0.2.2] - 2026-11-15

### Fixed
- Patched CVEs: "still open" follows the host, group, severity and ecosystem filters like every other
  number of the view.
- Tests no longer read the machine's own diysca config (`/etc/diysca/config.yml` and friends).

## [0.2.1] - 2026-11-15

### Fixed
- apt sources with `mirror+file:`, `mirror+http(s):` and `mirror:` URIs (the Debian cloud image default)
  are resolved to the real mirror; before, none of such a system's repos could be read and no fix was ever
  seen as available in its repos.
- Repo priorities: backports (`NotAutomatic` + `ButAutomaticUpgrades`) and experimental only count the
  way apt's default pin priorities do, so playbooks pin the version apt would install.
- A scan whose repos can't be read is reported as partial and names the first failing repo.
- Mitigations: a finding can't be in two open mitigations; the patch log no longer shows the canceller as
  executor and says how many packages and manual items a mitigation covered; an approval or
  `diysca playbook` whose filter matches nothing says so.
- Mitigation API: `summary.cves_total` gives the full count (`summary.cves` lists at most 50);
  `rescan_hosts` in the report answer lists system names; the playbook header no longer names a file.

## [0.2.0] - 2026-11-15

### Security
- Without a web login (`web_user` / `web_password` or OIDC) diysca only listens on 127.0.0.1;
  `diysca serve` on another address exits with code 2 unless `allow_no_login: true`.
- Failed logins are rate limited (5 failures, then a wait that doubles up to 1 hour).
- OIDC ID token signatures are checked against the provider's keys.
- Fixes from the security review: playbook template injection, scan script injection, CSRF, file reads
  through the inventory import, scope checks; security headers (no framing, no MIME sniffing,
  same-origin referrer).

### Added
- Modular architecture (`modules:`), OIDC login with roles and host scopes, audit log, patch log,
  inventory providers (cloud and virtualisation APIs), scan selection by pattern.
- Approving findings for mitigation, hand-off to webhooks, GitHub Actions and GitLab CI, API tokens,
  MCP server.
- Grafana-style web UI, Patched CVEs view, pluggable CVE sources, settings import / export,
  reprovisioning a system from its SBOM.
- PHP applications from `vendor/composer/installed.json` and Apache modules.
- Docs for the NVD API key; issue templates and a security policy; GPL-3.0-or-later license.

### Changed
- NVD enrichment runs in the background and stops on outages, so NVD rate limits never block scans.
- Language package findings say how to upgrade instead of "not in your repos".

## [0.1.0] - 2026-11-14

First release.

- Agentless scans over SSH (or locally): OS packages (dpkg, rpm, apk) and the repos each system uses.
- CVE matching with OSV, NVD and CISA KEV, aware of what your own repos offer.
- Language packages and container images, CycloneDX SBOMs, Apprise alerts.
- Ansible patch playbooks pinned to the repo version; aptly, Pulp and Foreman repo updates.
- SQLite or PostgreSQL; packaged as deb, rpm, OCI image, AppImage and Flatpak.

[Unreleased]: https://github.com/killsometimebe4timekillsu/diysca/compare/a60d9df...HEAD
[0.2.6]: https://github.com/killsometimebe4timekillsu/diysca/compare/e3aae69...a60d9df
[0.2.5]: https://github.com/killsometimebe4timekillsu/diysca/compare/f2369a3...e3aae69
[0.2.4]: https://github.com/killsometimebe4timekillsu/diysca/compare/v0.2.3...f2369a3
[0.2.3]: https://github.com/killsometimebe4timekillsu/diysca/compare/1a355c6...v0.2.3
[0.2.2]: https://github.com/killsometimebe4timekillsu/diysca/compare/c58ccdc...1a355c6
[0.2.1]: https://github.com/killsometimebe4timekillsu/diysca/compare/84d6595...c58ccdc
[0.2.0]: https://github.com/killsometimebe4timekillsu/diysca/compare/f9fc297...84d6595
[0.1.0]: https://github.com/killsometimebe4timekillsu/diysca/commit/f9fc297
