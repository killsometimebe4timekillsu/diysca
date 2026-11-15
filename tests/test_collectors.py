from diysca.scanning.collectors import (
    SEP,
    parse_apk_db,
    parse_apt_sources,
    parse_collect_output,
    parse_deb822,
    parse_dpkg,
    parse_rpm,
    parse_yum_repos,
)


def test_dpkg_with_source_and_removed():
    out = ("postgresql-16\t16.6-1.pgdg120+1\tamd64\t\tinstalled\n"
           "libpq5\t16.6-1.pgdg120+1\tamd64\tpostgresql-16\tinstalled\n"
           "libssl3\t3.0.15-1~deb12u1\tamd64\topenssl (3.0.15-1~deb12u1)\tinstalled\n"
           "oldpkg\t1.0\tamd64\t\tconfig-files\n")
    p = parse_dpkg(out)
    assert [x.name for x in p] == ["postgresql-16", "libpq5", "libssl3"]
    assert p[1].source_name == "postgresql-16" and p[1].source_version == "16.6-1.pgdg120+1"
    assert p[2].source_name == "openssl"


def test_rpm():
    out = ("bash\t0\t5.1.8\t9.el9\tx86_64\tbash-5.1.8-9.el9.src.rpm\n"
           "openssl-libs\t1\t3.0.7\t27.el9\tx86_64\topenssl-3.0.7-27.el9.src.rpm\n"
           "gpg-pubkey\t0\tabc\tdef\t(none)\t(none)\n")
    p = parse_rpm(out)
    assert len(p) == 2
    assert p[1].version == "1:3.0.7-27.el9" and p[1].source_name == "openssl"


def test_apk():
    p = parse_apk_db("P:musl\nV:1.2.4-r2\nA:x86_64\no:musl\n\nP:libcrypto3\nV:3.1.4-r5\no:openssl\n")
    assert [(x.name, x.source_name) for x in p] == [("musl", "musl"), ("libcrypto3", "openssl")]


def test_apt_sources():
    r = parse_apt_sources("#FILE /etc/apt/sources.list\ndeb [arch=amd64 signed-by=/k.gpg] http://mirror.local/debian bookworm main contrib\n"
                          "# deb http://disabled bookworm main\ndeb-src http://x y z\ndeb http://repo.local/flat ./\n")
    assert len(r) == 2
    assert r[0].url == "http://mirror.local/debian" and r[0].components == ["main", "contrib"]
    assert r[1].suite == "./"


def test_deb822():
    r = parse_deb822("#FILE x.sources\nTypes: deb deb-src\nURIs: http://archive.ubuntu.com/ubuntu\nSuites: noble noble-updates\n"
                     "Components: main universe\n\nTypes: deb\nURIs: http://off\nSuites: x\nEnabled: no\n")
    assert [(x.suite, x.components) for x in r] == [("noble", ["main", "universe"]), ("noble-updates", ["main", "universe"])]


def test_yum():
    r = parse_yum_repos("#FILE /etc/yum.repos.d/local.repo\n[local-base]\nname=Local\nbaseurl=http://pulp.local/rocky/$releasever/BaseOS/$basearch/os/\n"
                        "enabled=1\n[off]\nbaseurl=http://x\nenabled=0\n")
    assert r[0].url == "http://pulp.local/rocky/$releasever/BaseOS/$basearch/os" and r[0].enabled
    assert not r[1].enabled


def test_full_output():
    out = (f"{SEP}os-release\nID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n"
           f"{SEP}hostname\nsystem_a\n{SEP}arch\nx86_64\n{SEP}dpkg-arch\namd64\n"
           f"{SEP}dpkg\nbash\t5.2.15-2+b7\tamd64\tbash (5.2.15-2)\tinstalled\n{SEP}rpm\n{SEP}apk\n"
           f"{SEP}apt-sources\ndeb http://deb.debian.org/debian bookworm main\n{SEP}end\n")
    f = parse_collect_output(out)
    assert f.os_id == "debian" and f.os_version == "12" and f.deb_arch == "amd64"
    assert f.packages[0].source_version == "5.2.15-2" and f.pkg_type == "deb"
    assert len(f.repos) == 1
