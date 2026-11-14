import gzip

from diysca.repos import parse_apt_packages, parse_primary_xml

PRIMARY = b"""<?xml version="1.0"?><metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm">
<package type="rpm"><name>openssl-libs</name><arch>x86_64</arch><version epoch="1" ver="3.0.7" rel="27.el9"/>
<format><rpm:sourcerpm>openssl-3.0.7-27.el9.src.rpm</rpm:sourcerpm></format></package>
<package type="rpm"><name>openssl-libs</name><arch>x86_64</arch><version epoch="1" ver="3.0.7" rel="28.el9_4"/>
<format><rpm:sourcerpm>openssl-3.0.7-28.el9_4.src.rpm</rpm:sourcerpm></format></package>
</metadata>"""


def test_primary_xml_keeps_newest():
    assert parse_primary_xml(gzip.decompress(gzip.compress(PRIMARY))) == {"openssl-libs": ("1:3.0.7-28.el9_4", "openssl")}


def test_apt_packages():
    idx = parse_apt_packages("Package: libpq5\nVersion: 16.6-1\nSource: postgresql-16\n\n"
                             "Package: libpq5\nVersion: 16.7-1\nSource: postgresql-16 (16.7-1)\n\nPackage: bash\nVersion: 5.2\n")
    assert idx == {"libpq5": ("16.7-1", "postgresql-16"), "bash": ("5.2", "bash")}
