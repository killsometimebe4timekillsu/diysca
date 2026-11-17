# diysca: a poor man's DIY CVE scanner

diysca is a self-hosted scanner for your Linux systems. It doesn't need an agent, and it has no SaaS dependency. It ships as a native package (deb/rpm), an OCI image, an AppImage and a Flatpak.

> [!WARNING]
> **AI-generated code.** diysca was written largely with an AI coding assistant (Claude) and reviewed by a person,
> but not audited. It connects to your systems over SSH and can generate and hand off patch playbooks, so
> review what it does before you trust it in production: read generated playbooks before running them, give
> its SSH user and API tokens only the rights they need, and treat findings as a starting point, not a
> guarantee that a system is (or isn't) vulnerable. Provided as is, without warranty (GNU GPL v3 or later, see [License](#license)).

* **Public CVE sources:** [OSV.dev](https://osv.dev) is the main source. It aggregates the Debian, Ubuntu, Alpine, AlmaLinux, Rocky, SUSE and Red Hat security trackers, with exact fixed versions per distro release. **NVD** adds CVSS scores and descriptions, and **CISA KEV** flags known exploited CVEs.
* **More CVE sources, your own included:** the Debian security tracker (adds CVEs Debian hasn't fixed yet), Alpine secdb, FIRST **EPSS** exploit probabilities, any OSV-format feed (a GHSA export, Go vulndb, your own advisories), and **custom JSON / YAML / CSV feeds** mapped field by field. Configure them in `config.yml` or on the **CVE sources** page. See [CVE sources](#cve-sources).
* **Local systems:** hosts are scanned agentless over SSH (or locally) for installed `dpkg`, `rpm` and `apk` packages. No root is needed.
* **Repos:** each host's configured repositories are read (`sources.list`, deb822 `.sources`, `yum.repos.d`, `/etc/apk/repositories`), and their package indexes are downloaded. This includes local mirrors, Aptly, Pulp and Nexus. diysca can then tell you whether the fix is actually installable from *your* repos.
  * apt mirror lists (`mirror+file:`, the default on Debian cloud images, and `mirror+https:`) are followed to the real repo.
  * The fix version is the one the system's package manager would install: repos marked `NotAutomatic` (backports, experimental) only count for packages already installed from them, as with apt's pin priorities. Custom pins in `/etc/apt/preferences` are not read.
  * A repo that can't be read is shown on the system's page and makes the scan result "partial", because fixes in it are not seen.
* **Language packages:** PyPI, npm, RubyGems, Maven (from the `pom.properties` inside jars), Packagist, crates.io and Go are covered. diysca reads installed packages (`*.dist-info`, `node_modules`, gemspecs, jars) and lockfiles (`package-lock.json`, `yarn.lock`, `Gemfile.lock`, `poetry.lock`, `Pipfile.lock`, `requirements*.txt`, `composer.lock`, `Cargo.lock`, `go.mod`). PHP applications deployed with their `vendor/` directory are read from `vendor/composer/installed.json`, even without `composer.lock`. Go and Rust programs installed as plain binaries (`/usr/local/bin/gh`, release tarballs in `/opt`) are read too: the Go standard library version and Go modules from the build info, and the crates of Rust programs built with [cargo-auditable](https://github.com/rust-secure-code/cargo-auditable). This needs only `od`, `head`, `tr` and `find` on the system, so it works with BusyBox as well.
* **Apache modules:** every module Apache loads (`LoadModule` in the Debian, RHEL and source-build config locations) is listed with the OS package it comes from. Modules and an `httpd` from packages are checked for CVEs through that package; modules nobody's package manager owns (built or copied by hand) are flagged, since diysca can't check them.
* **Container images:** on each host, the images of running containers are scanned (podman, docker, nerdctl and crictl). Each image appears as its own system, `<host>/<container>`, and gets its own OS packages, language packages and SBOM.
* **Correlation:** installed version × distro advisory ranges × repo candidate version. The comparison uses real dpkg, rpm and apk version semantics, plus per-ecosystem rules for language packages.
* **Patching:**
  * diysca generates an **Ansible playbook** for the selected findings. It pins every affected package to the exact version your repos offer, and includes an optional reboot.
  * If a fix is released upstream but your mirror doesn't have it yet, diysca can update the **self-hosted repo**: aptly (mirror update → snapshot → publish switch), Pulp 3 (sync → publication → distribution) or Foreman/Katello (sync → publish the content view → promote it to your lifecycle stages). It does a dry run first.
* **SBOM:** one CycloneDX 1.5 JSON file per system, including a `vulnerabilities` section.
* **Alerts** ([docs/alerts.md](docs/alerts.md)): sent via [Apprise](https://github.com/caronc/apprise/wiki), which covers ntfy, Gotify, e-mail, Telegram, Slack, Matrix, Discord, Teams, webhooks and more. Subscriptions decide *which packages on which systems at which severity* go to *which channel*. Each finding is sent only once.
* **Ansible inventories:** INI and YAML, groups, `:children`, `:vars`, `group_vars/`, `host_vars/` and host ranges. If `ansible-inventory` is installed, it is used instead, so dynamic and vaulted inventories also work.
* **Inventory providers** ([docs/inventory-providers.md](docs/inventory-providers.md)): systems straight from Proxmox VE, VMware vSphere, KVM/libvirt, OpenStack, Kubernetes and OpenShift (nodes, and the pod containers running on them), AWS EC2, Microsoft Azure, Google Cloud and Hetzner Cloud. Windows systems get an inventory (build, updates, programs) over OpenSSH; CVE matching for Windows isn't built yet.
* **Scan what you pick:** all systems, one, the ones ticked on the Systems page, or a pattern (`web*,group:prod,!test-*`), from the UI, API, MCP and CLI.
* **Patched CVEs:** what was patched, where, when and how (upgraded or removed), with a Grafana-style time picker: since the last patching of each system, the last 24 hours, 7, 30 or 90 days, a year, or a custom range. Playbook runs and repo updates show up as annotations on the chart.
* **Reprovision from the SBOM:** every system's SBOM records its repositories, OS packages, pip/gem packages and container images. diysca turns it (or any CycloneDX SBOM with package URLs, e.g. from Syft or Trivy) into an Ansible playbook that rebuilds the system on a fresh install of the same OS release, at the recorded versions or with fixable vulnerabilities fixed.
* **Approve for mitigation:** when diysca can't reach a system, approve its findings instead. Agents, CI/CD pipelines (GitHub Actions, GitLab CI, any webhook) or colleagues who can reach it claim the mitigation, run its playbook and report back; diysca then rescans. See [docs/mitigations.md](docs/mitigations.md).
* **MCP server:** AI agents and MCP clients use diysca through `diysca mcp` (stdio) or `<base_url>/mcp` (HTTP). See [docs/mcp.md](docs/mcp.md).
* **API:** everything in the UI is available as JSON, with bearer tokens for automation. See [docs/api.md](docs/api.md) and `<base_url>/docs`.
* **Web UI:** a classic Grafana-style dark UI (light theme on request). Click the logo to show the menu with or without names. Pages: dashboard, systems, **Findings** (tabs Findings and Packages), **Patching** (tabs Patch, Mitigations, Patch log and Patched CVEs), and one **Settings** area (General, CVE Sources, Inventory, Notifications, Repo Manager, Hand-off, Access, Import / Export). Findings can be filtered by system, group, OS, host or container, package, ecosystem, CVE, severity, fix availability and KEV. Filters can be saved, and you can manage channels and subscriptions from the UI.
* **Modules** ([docs/modules.md](docs/modules.md)): scanning is the core; alerting, mitigation and auth can be switched off.
* **Login and roles** ([docs/auth.md](docs/auth.md)): OIDC single sign-on (Keycloak, Entra ID, Authentik, Okta, ...), roles viewer / operator / approver / admin bound to groups, users or e-mail patterns, optionally limited to some systems, and an audit log of every change.
* **Patch log** ([docs/patch-log.md](docs/patch-log.md)): every patching with what, where, when, who approved it, who ran it and whether the rescan confirmed it, exportable as CSV or JSON.
* **Database:** PostgreSQL. SQLite remains available for single-user desktop installs, i.e. the AppImage and Flatpak.

![patched CVEs](docs/patched.png)

Example alert:

```
postgresql-16 16.6-1~deb12u1 installed on system_a affected by CVE-2025-1094 (HIGH 8.1), fixed in 16.7-0+deb12u1 - fix available in your repos
```

## Install

Every release ships the same app in four forms. Pick whichever fits your environment. None of them needs a system Python, and nothing is installed on the scanned hosts.

| Format | For | Get it |
|---|---|---|
| **Native package** `.deb` / `.rpm` | a VM or bare-metal server; runs as a hardened systemd service | release assets |
| **OCI image** | any standalone runtime (Podman, containerd/nerdctl, CRI-O, …) or an orchestrator (Kubernetes, Nomad, …) | `ghcr.io/killsometimebe4timekillsu/diysca` |
| **AppImage** | a single file that runs on any x86_64 distro, no install | release assets |
| **Flatpak** | sandboxed desktop install; double-click opens the UI in your browser | release assets (`diysca.flatpak`) |

### Native package (Debian/Ubuntu, RHEL/Rocky/Alma/SUSE)

```bash
sudo apt install ./diysca_0.2.6_amd64.deb        # or: sudo dnf install ./diysca-0.2.6-1.x86_64.rpm
sudoedit /etc/diysca/config.yml                  # inventories, base_url, ...
sudo -u diysca ssh-keygen -t ed25519 -f /var/lib/diysca/.ssh/id_ed25519 -N ''
sudo systemctl enable --now diysca               # UI on 127.0.0.1:8080 (change in /etc/default/diysca)
```

The package installs to `/opt/diysca` and adds `/usr/bin/diysca`, a `diysca` system user, `/var/lib/diysca` for state, and `/etc/diysca/config.yml`.

### OCI image

```bash
# Podman (rootless works):
podman run -d --name diysca -p 8080:8080 \
  -e DIYSCA_WEB_USER=admin -e DIYSCA_WEB_PASSWORD='choose-one' \
  -v diysca-data:/data -v ./config.yml:/config/config.yml:ro \
  -v ./inventories:/inventories:ro -v ./keys:/keys:ro \
  ghcr.io/killsometimebe4timekillsu/diysca:latest
```

diysca only listens beyond `127.0.0.1` when a login is configured: `web_user` / `web_password` as above, or OIDC ([docs/auth.md](docs/auth.md)). Without one it stops with a message that says so. For a lab without a login, set `DIYSCA_ALLOW_NO_LOGIN=true`.

* **systemd-managed Podman:** use the Quadlet in [`packaging/quadlet/diysca.container`](packaging/quadlet/diysca.container).
* **Compose-spec tools** (`podman compose`, `nerdctl compose`, …): use [`compose.yaml`](compose.yaml).
* **Kubernetes:** run `kubectl apply -k packaging/k8s` with the manifests in [`packaging/k8s/`](packaging/k8s). They include PostgreSQL, run non-root with a read-only root filesystem, and use a ConfigMap and Secrets for the config, the SSH key and the database.
* **Building the image yourself:** `podman build -f Containerfile -t diysca .` works, as does `buildah bud`, or any other OCI builder.

### From source (pip)

For a quick test on any Linux with Python 3.12 or newer:

```bash
sudo python3 -m venv /opt/diysca
sudo /opt/diysca/bin/pip install "git+https://github.com/killsometimebe4timekillsu/diysca"
sudo ln -s /opt/diysca/bin/diysca /usr/local/bin/diysca   # so `diysca` is on the PATH
diysca serve                                              # UI on 127.0.0.1:8080
```

To update a source install to the latest commit, add `--force-reinstall --no-deps` (the version number only
changes with releases, so a plain `--upgrade` sees nothing to do), then `sudo systemctl restart diysca` if you run it as a service.

Config: `--config /etc/diysca/config.yml` or `DIYSCA_CONFIG`; copy `config.example.yml` to start. For PostgreSQL set `database_url`. The packages above set all of this up for you (system user, systemd unit, config).

### AppImage

```bash
chmod +x diysca-0.2.6-x86_64.AppImage
./diysca-0.2.6-x86_64.AppImage          # starts the UI on 127.0.0.1:8765 and opens your browser
./diysca-0.2.6-x86_64.AppImage scan     # or use it as the CLI
```

### Flatpak

```bash
flatpak install --user ./diysca.flatpak
flatpak run io.github.killsometimebe4timekillsu.diysca          # UI in your browser
flatpak run io.github.killsometimebe4timekillsu.diysca scan     # CLI
```

The Flatpak sandbox can use the network and your ssh-agent, and has read-only access to your home directory for inventories and `known_hosts`.

### First steps (any format)

1. Create an unprivileged `diysca` user with your SSH key on the hosts you want to scan. An Ansible one-liner does it, and no sudo is needed.
2. Run `diysca import /path/to/inventory`, or set `inventories:` in the config.
3. Click **Scan all** in the UI, or run `diysca scan`.

### PostgreSQL

Server installs use PostgreSQL. Set `database_url` in the config, or the `DIYSCA_DATABASE_URL` environment variable. The schema is created automatically on start.

* **Native package:** `sudo -u postgres createuser -P diysca && sudo -u postgres createdb -O diysca diysca`.
* **compose.yaml, the Quadlet and the Kubernetes manifests:** each ships a PostgreSQL 17 container. You can also point them at an existing cluster.

### Patching

1. Open **Patching**. You can also select findings on **Findings**, or click **Patch playbook** on a system. Then download the playbook and run it with `ansible-playbook -i <inventory> diysca-patch.yml --check --diff`, followed by a real run.
2. For fixes that aren't in your repos yet, configure `repo_managers` (see `config.example.yml`). Use **Dry run** and then **Run** on the Patching page, or `diysca repo-update <name> [--run] [--stage Test]`. The affected hosts are rescanned afterwards, so their findings move to "fix available in your repos".

### Reprovision a system from its SBOM

On a system, click **Reprovision playbook**, or upload an SBOM under **Patching > Reprovision**, or run `diysca reprovision system_a [--mode exact] [--target newbox] -o rebuild.yml` (or `--sbom file.cdx.json`). The playbook checks the target's OS release, adds the original repositories, installs the OS packages at the recorded versions (`--mode fixed`, the default, raises vulnerable packages to the fixed version in your repos), installs pip and gem packages, and pulls the container images. npm, Maven, Composer, Cargo and Go dependencies are listed as comments because they belong to the application's build. Repository signing keys aren't in an SBOM, so install them first.

### Settings import / export

**Settings > Import / Export** (or `diysca settings export|import`) moves CVE sources, alert channels, subscriptions and saved filters as one YAML file. Secrets are written as `***` unless you ask for them. Importing `***` keeps the stored value, so a masked export can be edited and re-imported. Use preview first; "replace" also removes items that are not in the file.

### CVE sources

| type | what it adds | default URL |
|---|---|---|
| `debian-tracker` | CVEs Debian hasn't fixed yet (status "open") and Debian's urgency | security-tracker.debian.org/tracker/data/json |
| `alpine-secdb` | Alpine secfixes per release and repo | secdb.alpinelinux.org/v3.20/main.json |
| `osv` | any OSV-format feed: `.zip`, JSON record or list, NDJSON, or a local directory | – |
| `custom` | your own JSON / YAML / CSV feed, mapped with `fields:` | – |
| `epss` | FIRST EPSS probability per CVE, shown on findings | epss.cyentia.com/epss_scores-current.csv.gz |

Records from extra sources keep their own id, prefixed with the source name (`debian-tracker/CVE-2025-1234`), so you can see which source reported a finding. When OSV and an extra source report the same CVE for the same package, you get one finding listing both. Sources added in the web UI must be http(s) URLs. Local files and directories (`path:` or `file://`) can only be configured in `config.yml`. Examples are in `config.example.yml`.

### Patched CVEs

A finding is patched when a scan no longer sees it. diysca stores when that happened, the version installed at that point, and how it went away: `upgraded`, `removed`, or `not-affected` (the advisory changed). The **Patched CVEs** page and `GET /api/patched?range=7d` show them per time range. `range=last` means the most recent patching of each system.

### CLI

```bash
diysca import ~/ansible/inventory/hosts.ini
diysca add-host myself --local          # scan the machine diysca runs on
diysca scan --no-alerts
diysca scan 'web*' group:dmz            # only some systems (names or patterns)
diysca findings
diysca sbom system_a > system_a.cdx.json
diysca channel ntfy ntfy://ntfy.sh/my-secret-topic
diysca subscribe "postgres prod" --channel ntfy --hosts 'group:prod' --packages 'postgresql*,libpq*' --min-severity HIGH
diysca notify --dry-run
diysca playbook --filter 'fix=repo&severity=HIGH' -o patch.yml
diysca repo-update                      # list repo managers and what they would fix
diysca repo-update satellite --stage Test --run
diysca sources --refresh                # download the extra CVE sources now
diysca settings export > settings.yml   # sources, channels, subscriptions, saved filters (secrets masked)
diysca settings import settings.yml --dry-run
diysca reprovision system_a -o rebuild.yml
diysca patched --range 7d               # what got patched in the last week
diysca patchlog --range 90d -o patchlog.csv   # the patch log for auditors (--format json)
diysca mitigations approve --filter 'host=db1&fix=repo' --note CHG-1234
diysca mitigations                      # open mitigations
diysca mitigations report 12 --status done --log @run.log
diysca mcp                              # MCP server on stdio
diysca serve                            # UI + scheduler on :8080
```

### Building the packages yourself

```bash
packaging/scripts/build-standalone.sh                                        # dist/diysca/ (PyInstaller bundle)
ARCH=amd64 VERSION=0.2.6 nfpm package -f packaging/nfpm.yaml -p deb -t dist/ # .deb  (-p rpm for .rpm)
packaging/scripts/build-appimage.sh                                          # needs appimagetool
flatpak-builder --user --install --force-clean build/flatpak packaging/flatpak/io.github.killsometimebe4timekillsu.diysca.yml
```

CI (`.github/workflows/package.yml`) builds and install-tests every format on each PR. A `v*` tag publishes a GitHub release and the OCI image.

Config is looked up in this order: `$DIYSCA_CONFIG`, then `./config.yml`, then `~/.config/diysca/config.yml`, then `/etc/diysca/config.yml`. State goes to systemd's `StateDirectory` (`/var/lib/diysca`), or to `$XDG_DATA_HOME/diysca` otherwise.

## How it works

```
 Ansible inventory ─┐
                    ▼
                 hosts ──SSH──► os-release, dpkg/rpm/apk db, repo config
                    │                          │
                    │                          ▼
                    │            repo indexes (Packages / primary.xml / APKINDEX)
                    ▼                          │
      OSV (api or bulk mirror) ──► correlate ◄─┘──► findings ──► Apprise channels
      NVD (CVSS) + CISA KEV ────►      │                           (subscriptions)
                                       ▼
                             PostgreSQL ──► Web UI / JSON API / CycloneDX SBOM / patch playbooks
```

* Advisories are matched on the **source package** (that is how Debian, Ubuntu and Alpine publish them). A finding lists every installed binary built from it, for example `postgresql-16` → `libpq5, postgresql-16`.
* Each finding is keyed by CVE. DSA, DLA, USN, ALSA and RLSA advisories that mention the CVE are linked to it.
* "Fixed in" is the distro's fixed version. "Your repos offer" is the newest version found in the host's configured repos. If that version is at least the fixed one, the fix is installable now.
* When a package is upgraded, the next scan marks the finding `resolved`. Findings you accept can be set to `ignored`.

### OSV modes

| `osv_mode` | how | when |
|---|---|---|
| `api` (default) | `api.osv.dev/v1/querybatch` per scan | normal internet access |
| `bulk` | downloads `<Ecosystem>/all.zip` (`Debian` ~45 MB, `Ubuntu` ~800 MB, one file for all releases) every `osv_bulk_hours` and matches locally. A warning appears under Events when the newest advisory in it is more than 14 days old | lots of hosts, flaky or limited egress, air-gapped (point `osv_bulk_url` at a `file://` mirror) |

Supported distros: Debian, Ubuntu, Alpine, Rocky, AlmaLinux, RHEL (including 10), SLES (including 16) and openSUSE Leap. Fedora and Arch are not covered by OSV. CI install-tests the native packages on Debian 12, Ubuntu 22.04/24.04, AlmaLinux 8, Rocky 9, RHEL 10 (UBI 10) and SLES 16 (BCI 16).

## API

Everything in the UI is available as JSON: systems, packages, findings, SBOMs, patched CVEs, sources, scans and
mitigations. Agents and CI/CD use bearer tokens (`api_tokens` in config.yml). Full reference with examples:
[docs/api.md](docs/api.md); interactive OpenAPI docs at `<base_url>/docs`.

```sh
curl -s -H "Authorization: Bearer $TOKEN" "https://diysca.example.org/api/findings?group=prod&severity=CRITICAL&fix=repo"
```

### Approve for mitigation, hand-off and MCP

Approve findings on the Findings page (or `POST /api/mitigations`). Agents and pipelines that can reach the systems
pull them (`GET /api/mitigations?status=approved`) or get them pushed (webhook, GitHub `repository_dispatch`, GitLab
pipeline trigger, under *Settings > Hand-off*), claim, run the playbook and report `done` or `failed`. Guide with
GitHub Actions and GitLab CI examples: [docs/mitigations.md](docs/mitigations.md). The same through MCP:
`diysca mcp` or `<base_url>/mcp`, see [docs/mcp.md](docs/mcp.md).

## Known limitations / roadmap

* yum/dnf repos that only use `mirrorlist` or `metalink` are not indexed (set `baseurl`).
* NVD without an API key is slow (about 5 CVEs per 30 s), so CVSS scores from NVD fill in over several runs. Scans don't wait for it. A free key makes it about 10x faster: [docs/nvd-api-key.md](docs/nvd-api-key.md).
* Images without `/bin/sh` (distroless, scratch) can't be scanned through `exec`.
* Language packages are reported with a fix version and their location. Upgrading them is left to the application's own build, and the playbook lists them as manual items.
* Fat jars that nest other jars are only read one level deep.
* Windows systems are inventoried but not matched against Microsoft's security updates (MSRC) yet.
* OIDC ID token signatures aren't verified (the token comes straight from the provider over TLS, which the spec allows); issuer, audience, expiry and nonce are.

## Issues and security

Found a bug or want a feature? [Open an issue](https://github.com/killsometimebe4timekillsu/diysca/issues/new/choose).
Security problems: please report them privately, see [SECURITY.md](SECURITY.md).

## License

Copyright (C) 2026 killsometimebe4timekillsu and contributors.

diysca is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
It is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See [LICENSE](LICENSE) for the full text.
