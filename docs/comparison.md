# diysca compared with Trivy, Grype and OSV-Scanner

A side-by-side run on the two Debian 13.7 test systems (2026-11-17). All tools scanned the same data at the same
time: diysca 0.2.6 over SSH, the other tools on a copy of each system's `/var/lib/dpkg/status`, `/etc/os-release`
and the language scan paths (`/opt`, `/srv`, `/usr/local`, `/home`, `/root`, `/var/www`).

| Tool | Version, database |
|---|---|
| diysca | 0.2.6, OSV API + NVD + CISA KEV |
| Trivy | 0.76.2 (`trivy rootfs --scanners vuln`), DB of 2026-11-17 13:00 UTC |
| Grype | 0.121.3 (`grype dir:`), DB v6.1.10 of 2026-11-17 |
| OSV-Scanner | 2.7.1 (`-L dpkg-status:…`, and `-r` for language files) |

Findings are compared as (CVE, source package) pairs, because Trivy and Grype report one row per binary package
(`openssh-client`, `openssh-server`, …) while Debian publishes advisories per source package (`openssh`).

## Results

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

## Severity

diysca takes the NVD CVSS rating; Trivy takes Debian's rating, which is often lower for issues that don't
matter in Debian's build ("unimportant" → LOW). On system 1, 232 of 418 shared findings have the same severity.
The rest are mostly diysca HIGH / Trivy LOW (42), diysca MEDIUM / Trivy LOW (50) and diysca CRITICAL / Trivy LOW
(11). 33 findings without an NVD score show as UNKNOWN in diysca where Trivy shows Debian's rating.

## Go and Rust programs

Three release tarballs were unpacked in `/opt` on system 2: GitHub CLI 2.104.0 (`gh`, Go), uv 0.13.9 (`uv`,
`uvx`, Rust, built with cargo-auditable) and fd 10.5.2 (Rust without cargo-auditable, as a control).

| | diysca 0.2.6 | Trivy 0.76.2 | Grype 0.121.3 |
|---|---|---|---|
| gh: Go modules found | 156 (incl. stdlib 1.27.4) | 156 | – |
| gh: findings | 3 | 3, the same | 0 |
| uv: crates found | 446 (build-only crates left out) | 510 | – |
| uv: findings | 28 | 0 | 0 |
| fd: crates / findings | 0 / 0 (no dependency list in the binary) | 0 / 0 | 0 / 0 |

* **Go:** diysca and Trivy list the same 156 modules and report the same 3 advisories (`golang.org/x/net`
  v0.61.0: GO-2026-6860, GO-2026-6866; `golang.org/x/crypto` v0.58.0: GO-2026-5932).
* **Rust:** both list the same crates, including the ones that appear in two versions (`zstd-safe` 7.2.4 and
  8.0.0). Trivy reports no vulnerabilities for them. diysca reports 28 RustSec advisories, among them
  RUSTSEC-2023-0071 (CVE-2023-49092, `rsa` 0.9.10), RUSTSEC-2026-0386 (`tokio` 1.53.2) and twelve for
  `zstd-safe` 7.2.4; the OSV API returns the same advisories for these versions. 5 of the 28 are "unmaintained"
  notices without a fix.
* **Grype** found neither the Go modules nor the crates when pointed at the directory or at each binary.

## Not covered by this run

* Container images: no containers ran on the systems.
* Repo awareness (is the fix in *your* repos?), mitigation and patching are diysca features the other tools
  don't have, so they aren't compared.
