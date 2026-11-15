import pytest

from diysca.core.versions import apk_compare, dpkg_compare, max_version, rpm_compare


@pytest.mark.parametrize("a,b,r", [
    ("1.0", "1.0", 0), ("1.0-1", "1.0-2", -1), ("1:1.0", "2.0", 1), ("1.0~rc1", "1.0", -1),
    ("16.6-1", "16.7-1~deb12u1", -1), ("3.0.13-0ubuntu3.2", "3.0.13-0ubuntu3.10", -1),
    ("2.36-9+deb12u4", "2.36-9+deb12u10", -1), ("1.2.3+dfsg-1", "1.2.3-1", 1), ("1.0a", "1.0", 1),
    ("16.4-0ubuntu0.24.04.1", "16.10-0ubuntu0.24.04.1", -1),
])
def test_dpkg(a, b, r):
    assert dpkg_compare(a, b) == r
    assert dpkg_compare(b, a) == -r


@pytest.mark.parametrize("a,b,r", [
    ("1.0-1.el9", "1.0-2.el9", -1), ("1:1.0-1", "2.0-1", 1), ("3.0.7-27.el9", "3.0.7-27.el9_4.1", -1),
    ("1.0~rc1-1", "1.0-1", -1), ("5.14.0-427.13.1.el9_4", "5.14.0-427.2.1.el9_4", 1), ("1.0a-1", "1.0-1", 1),
])
def test_rpm(a, b, r):
    assert rpm_compare(a, b) == r
    assert rpm_compare(b, a) == -r


@pytest.mark.parametrize("a,b,r", [
    ("3.1.4-r5", "3.1.4-r6", -1), ("1.2.3_rc1-r0", "1.2.3-r0", -1), ("1.2.3_p1-r0", "1.2.3-r0", 1),
    ("1.10-r0", "1.9-r0", 1), ("3.3.2-r0", "3.3.2-r0", 0),
])
def test_apk(a, b, r):
    assert apk_compare(a, b) == r


def test_max_version():
    assert max_version("deb", ["1.0-1", None, "1.0-10", "1.0-2"]) == "1.0-10"
