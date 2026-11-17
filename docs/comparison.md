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
* **PHP vendor directory:** diysca, Trivy and OSV-Scanner do not agree here. diysca and Trivy find the 14 CVEs of
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

## Not covered by this run

* Go and Rust programs: neither system has any outside OS packages, so there was nothing to compare.
* Container images: no containers ran on the systems.
* Repo awareness (is the fix in *your* repos?), mitigation and patching are diysca features the other tools
  don't have, so they aren't compared.
