# Changelog

All notable changes to diysca. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versions follow [Semantic Versioning](https://semver.org/). Only tagged versions are published as releases on
GitHub; the others are on `main` and in the packages that CI builds for each commit.

## [0.2.7] - 2026-11-17

### Added
- This changelog.
- [docs/comparison.md](docs/comparison.md): what diysca finds compared with Trivy on the same system, and why the
  numbers differ.

### Changed
- README: the known limitations name what the Go and Rust program scan can't see, and no longer claim that OIDC
  signatures aren't verified (they are since 0.2.0).

## [0.2.6] - 2026-11-17

### Added
- Go and Rust programs installed as plain binaries are scanned (#25). Go programs (1.18 and newer) report the Go
  standard library version and every module from their build info, with `replace` directives applied. Rust
  programs built with [cargo-auditable](https://github.com/rust-secure-code/cargo-auditable) report their crates.io
  crates. Only `od`, `head`, `tr` and `find` are needed on the system, so BusyBox works.
- Settings `scan_binaries` (default on) and `binary_scan_paths` (default: `lang_scan_paths`).

### Fixed
- Go, npm and crates.io versions are compared by semver precedence. `1.21.0-0`, the lowest pre-release OSV uses in
  ranges, ranked above `1.21.0`, so newer versions matched old records (for example Go 1.26.2 and GO-2023-1987).

## [0.2.5] - 2026-11-17

### Fixed
- `osv_mode: bulk` used OSV's per-release exports (`Ubuntu:24.04:LTS/all.zip`, `Debian:12/all.zip`), which OSV
  stopped updating in October 2024. It now downloads the maintained ecosystem exports (`Ubuntu/all.zip`,
  `Debian/all.zip`) and filters by release (#24). `file://` mirrors with per-release zips still work.
- An Ubuntu notice (USN) only names the CVEs whose own record matches the installed version.

### Added
- Ubuntu LTS systems are also matched against `Ubuntu:Pro:<release>:LTS`. Findings fixed only in Ubuntu Pro (ESM)
  are marked so and shown as fix upstream unless the system has ESM repos. Setting `ubuntu_pro_advisories`.
- A warning in Events when a feed's newest advisory is more than 14 days old.

## [0.2.4] - 2026-11-16

Fixes from the review of 0.2.3 (#23).

### Security
- A system whose name Ansible would read as a pattern (`all`, `web*`, `a,b`, `!x`) is listed for manual patching
  instead of becoming a play's `hosts:`.
- Inventory providers can't take over a system that another source added under the same name.
- The system filter matches whole names; `%` and `_` are literal in all text filters.
- A user with a host scope sees only their own findings of a mixed mitigation, not its playbook, and can't act on it.
- Roles are worked out on every request, so removing a binding takes effect at once.
- OIDC addresses marked `email_verified: false` don't match `email:` bindings.

### Fixed
- One scan per system at a time; database writes and index parsing run off the event loop.
- Local and SSH commands are stopped (with their child processes) on timeout.
- One failing system no longer ends a scan of all systems.
- `/healthz` answers 503 while the database can't be reached; missing columns are added on every start.
- Bad JSON on the mitigation API gives 422; a repo update for a deleted system no longer crashes.

### Changed
- `host=` is an exact match (was a substring match). Use `web*` for a prefix.
- Error pages for browsers, JSON for API clients. Config mistakes are named, with a did-you-mean hint for unknown keys.
- The findings page says when it shows the worst 5000 of more.

## [0.2.3] - 2026-11-16

First published release.

### Added
- Each system's repositories in the Systems table (expandable count, failed repos marked) and at the top of its
  page; `GET /api/hosts/{id}/repos` (#21).

### Fixed
- CI builds the Flatpak with the runner's own SDK copy (#22).

## [0.2.2] - 2026-11-15

### Fixed
- Patched CVEs: "still open" follows the filters.
- Tests no longer pick up the machine's own `config.yml` (#20).

## [0.2.1] - 2026-11-15

### Fixed
- The same findings could be approved into two open mitigations (#17).
- The patch log named the person who cancelled a mitigation as its executor (#17).
- Approving with a filter that matches nothing says so (#17).
- apt mirror lists (`mirror+file:`, the default on Debian cloud images) are followed to the real repo (#18).
- Repos marked `NotAutomatic` (backports) only count for packages installed from them, as with apt's priorities (#18).
- A repo that can't be read makes the scan "partial" and shows the error (#18).
- Mitigations report the full CVE count (`summary.cves_total`) and system names in `rescan_hosts` (#19).

## [0.2.0] - 2026-11-15

### Security
- Fixes from a security review (#14): playbooks can't carry template code from scanned systems, the language scan
  script no longer runs file names as code, inventory import only reads configured paths, CSRF protection, host
  scopes on all playbook and MCP paths, open redirects, repo fetch limits, CSV formula escaping.
- Without a login diysca only listens on 127.0.0.1 (`allow_no_login` for labs); API tokens need a web login; OIDC
  ID token signatures are verified; failed logins are rate limited per address (#15).

### Changed
- The OCI image needs `DIYSCA_WEB_USER` / `DIYSCA_WEB_PASSWORD` or OIDC to start.

## [0.1.0] - 2026-11-14

First version (#1 to #13).

- Agentless scanning over SSH or locally: dpkg, rpm and apk databases, configured repos and their indexes, and a
  "your repos offer" fix version per finding.
- CVE data from OSV (API or bulk mirror), NVD and CISA KEV, plus the Debian tracker, Alpine secdb, EPSS and custom
  feeds.
- Language packages (PyPI, npm, RubyGems, Maven, Packagist, crates.io, Go), PHP `vendor/` directories, Apache
  modules and the images of running containers.
- PostgreSQL (SQLite as fallback), CycloneDX SBOMs, Apprise alerts with subscriptions.
- Patching: Ansible playbooks pinned to the repo version, aptly / Pulp / Foreman repo updates, approvals for
  mitigation with hand-off to webhooks, GitHub and GitLab, an MCP server, a patch log and reprovisioning from an
  SBOM.
- Modules, OIDC login with roles and host scopes, an audit log, and inventory providers for hypervisors, clouds
  and Kubernetes.
- Grafana-style web UI; native packages, AppImage, Flatpak and an OCI image.

[0.2.7]: https://github.com/killsometimebe4timekillsu/diysca/compare/v0.2.3...main
[0.2.6]: https://github.com/killsometimebe4timekillsu/diysca/pull/25
[0.2.5]: https://github.com/killsometimebe4timekillsu/diysca/pull/24
[0.2.4]: https://github.com/killsometimebe4timekillsu/diysca/pull/23
[0.2.3]: https://github.com/killsometimebe4timekillsu/diysca/releases/tag/v0.2.3
[0.2.2]: https://github.com/killsometimebe4timekillsu/diysca/pull/20
[0.2.1]: https://github.com/killsometimebe4timekillsu/diysca/pull/19
[0.2.0]: https://github.com/killsometimebe4timekillsu/diysca/pull/16
[0.1.0]: https://github.com/killsometimebe4timekillsu/diysca/pull/1
