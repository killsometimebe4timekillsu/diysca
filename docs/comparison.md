# diysca compared with Trivy, Grype and OSV-Scanner

Two side-by-side runs on 2026-11-17 with diysca 0.2.6 and that day's databases:

* **Two Debian 13.7 test VMs:** diysca agrees with Trivy on 418 of Trivy's 424 findings on one and 410 of 416 on
  the other. The 6 Trivy-only findings per VM are Debian `TEMP-…` entries without a CVE id, which OSV doesn't publish.
* **An Ubuntu 24.04 container with many language runtimes and programs:** diysca finds 3,663 of Trivy's 3,676 OS
  findings, including all 2,332 that have a fix. Of the 13 it doesn't report, Ubuntu's own CVE tracker says 9 don't
  affect this release. In language packages and programs, 34 of the 43 Trivy findings diysca misses are outside
  the default scan paths, 6 are in jars diysca can't identify, and 2 are CVEs OSV doesn't have yet.

A longer write-up, with a feature comparison against Grype, Vuls, OpenVAS and Wazuh, is in the
[comparison report](https://claude.ai/artifact/BZ7XLhpRfr9cUohs49gzKx).

## Debian 13 test VMs

diysca 0.2.6 scanned the systems over SSH. The other tools ran on a copy of each system's `/var/lib/dpkg/status`,
`/etc/os-release` and the language scan paths (`/opt`, `/srv`, `/usr/local`, `/home`, `/root`, `/var/www`), taken
at the same time.

| Tool | Version, database |
|---|---|
| diysca | 0.2.6, OSV API + NVD + CISA KEV |
| Trivy | 0.76.2 (`trivy rootfs --scanners vuln`), DB of 2026-11-17 13:00 UTC |
| Grype | 0.121.3 (`grype dir:`), DB v6.1.10 of 2026-11-17 |
| OSV-Scanner | 2.7.1 (`-L dpkg-status:…`, and `-r` for language files) |

Findings are compared as (CVE, source package) pairs, because Trivy and Grype report one row per binary package
(`openssh-client`, `openssh-server`, …) while Debian publishes advisories per source package (`openssh`).

### Results

| | system 1 (scanner, Python venv) | system 2 (PHP shop) |
|---|---|---|
| diysca | 429 | 421 |
| Trivy | 424 | 416 |
| Grype | 419 | 396 |
| OSV-Scanner | 426 | 407 |
| same as Trivy | 418 | 410 |
| same as Grype | 418 | 396 |
| same as OSV-Scanner | 423 | 407 |

What the differences are:

* **11 CVEs only diysca (and OSV-Scanner) report**, on both systems: OSV's Debian records for openssl, sqlite3,
  rtmpdump, openssh, gnutls28 and pam that the Trivy and Grype databases don't have (yet). None has a fixed
  version, so none is patchable.
* **6 Debian `TEMP-…` entries only Trivy reports** (tar, groff, bash, sysvinit, shadow, dbus): issues the Debian
  security tracker records without a CVE id. OSV doesn't publish them.
* **PHP vendor directory:** diysca and Trivy find the 14 CVEs of
  `guzzlehttp/guzzle` from `vendor/composer/installed.json` (no `composer.lock` deployed). OSV-Scanner and Grype
  don't read that file and report none.
* **OSV-Scanner false positives:** 3 old CVEs in `postgresql-common` (fixed in source version 178/188/210),
  because OSV-Scanner compares the binary version `17+278` with the source version. diysca compares source
  versions.
* **Fixed versions:** where a fix exists (the 6 PyPI findings of `pip`, the 14 of guzzle), all tools name the same
  fixed version. No OS finding had a fix in the Debian repos at the time.

### Severity

diysca takes the NVD CVSS rating; Trivy takes Debian's rating, which is often lower for issues that don't
matter in Debian's build ("unimportant" → LOW). On system 1, 232 of 418 shared findings have the same severity.
The rest are mostly diysca HIGH / Trivy LOW (42), diysca MEDIUM / Trivy LOW (50) and diysca CRITICAL / Trivy LOW
(11). 33 findings without an NVD score show as UNKNOWN in diysca where Trivy shows Debian's rating.

### Not covered by the VM run

* Go and Rust programs: neither system has any outside OS packages, so there was nothing to compare.
* Container images: no containers ran on the systems.
* Repo awareness (is the fix in *your* repos?), mitigation and patching are diysca features the other tools
  don't have, so they aren't compared.

## Ubuntu 24.04 container

Both tools scanned the same cloud container within minutes of each other. diysca ran with `osv_mode: bulk`.

### OS packages

| | diysca 0.2.6 | Trivy 0.76.2 |
| --- | --- | --- |
| Findings (one per source package and CVE) | 4,595 | 3,676 |
| Found by both | 3,663 | 3,663 |
| Only this tool | 932 | 13 |
| Trivy's 2,332 fixable findings, also found | 2,332 | 2,332 |
| Fix installable from the system's own repos | 2,336 | not reported |
| Fix only in Ubuntu Pro (ESM) | 179 | reported as affected |

Why they differ:

| Difference | Count | Cause | Who is right |
| --- | --- | --- | --- |
| Only diysca: open CVEs without a fix | 932 | Mostly Ubuntu status "needs-triage" (not assessed yet). OSV keeps these, Trivy leaves them out. 52 are kernel CVEs | Both defensible |
| Only Trivy: nasm (7), patch (1), linux (1) | 9 | Ubuntu now marks them "not-affected". OSV picked that up on 2026-11-17, Trivy's database (built 13:00 UTC that day) had not | diysca |
| Only Trivy: git-lfs CVE-2024-53263, CVE-2025-26625 | 2 | Ubuntu fixed them in 3.4.1-1ubuntu0.3+esm2 (Pro). The installed 3.4.1-1ubuntu0.4 sorts above that | Unclear: the version says fixed, Ubuntu doesn't say whether 0.4 carries the patch |
| Only Trivy: ffmpeg CVE-2023-6601, CVE-2023-6604 | 2 | Ubuntu status "deferred". OSV doesn't export deferred CVEs | Trivy |

### Language packages and programs

| | diysca 0.2.6 | Trivy 0.76.2 |
| --- | --- | --- |
| Findings (package and CVE or GHSA id) | 559 | 439 |
| Found by both | 396 | 396 |
| Only this tool | 163 | 43 |

* **Only Trivy (43):**
  * 27 in `/opt/rclone`, a separate mount (the scan doesn't cross mounts), and 7 in Docker's programs in `/usr/bin`
    and `/usr/libexec` (left to the OS scan by default). Add those paths to `binary_scan_paths` to include them.
  * 6 in Bouncy Castle jars shipped with Gradle. These jars have no `pom.properties`, so diysca can't tell what they
    are; Trivy looks up the jar's checksum in its own Java database.
  * 2 in Ruby's bundled `resolv` gem. diysca lists the gem, but OSV has no record for these two CVEs yet.
  * 1 in a crate's `Cargo.lock` inside `~/.cargo/registry`, a download cache that diysca skips on purpose.
* **Only diysca (163):**
  * 64 in Python libraries bundled with the Google Cloud SDK (`gsutil`).
  * 38 in crates compiled into `uv`, a Rust program built with cargo-auditable, which Trivy doesn't report.
  * 36 from lock files in the Go source trees under `/usr/local/go*` (25 npm, 11 Go) and 19 from lock files inside
    the rbenv Ruby installs. Trivy's `rootfs` mode skips lock files.
  * 4 in `gh` (Go standard library and modules) that Trivy's database doesn't match, and 2 others.

### How the container run was measured

* **System:** a cloud container running Ubuntu 24.04.5 with 847 OS packages and 2,380 language packages.
* **Trivy:** `trivy rootfs --scanners vuln`, OS and library package types in separate runs, database of
  2026-11-17.
* **diysca:** `osv_mode: bulk` (the OSV exports downloaded the same evening), NVD and KEV off, default scan paths,
  a fresh database.
* **Matching:** OS findings per source package and CVE, Trivy's binary package names mapped to source packages
  with `dpkg-query`. Language findings per package name and CVE or GHSA id, aliases included.
* **Checks:** each Trivy-only OS finding was looked up in the
  [Ubuntu CVE tracker](https://ubuntu.com/security/cves) for noble.
