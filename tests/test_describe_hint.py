from diysca.scanning.describe import format_finding


def _f(**kw):
    base = {"package": "guzzlehttp/guzzle", "version": "7.4.0", "vuln_id": "CVE-2022-29248", "severity": "HIGH",
            "cvss_score": 8.0, "kev": 0, "fixed_version": "7.4.3", "fix_in_repo": 0, "ecosystem": "Packagist"}
    base.update(kw)
    return base


def test_language_package_says_how_to_upgrade():
    line = format_finding(_f(), {"name": "vm2"})
    assert "upgrade via composer to >= 7.4.3" in line
    assert "repos" not in line


def test_distro_package_keeps_repo_wording():
    assert "fix NOT yet in your repos" in format_finding(_f(ecosystem="", package="openssl"), {"name": "vm2"})
    assert "fix available in your repos" in format_finding(_f(ecosystem="", fix_in_repo=1), {"name": "vm2"})
