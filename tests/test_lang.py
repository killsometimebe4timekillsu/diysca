import asyncio

from diysca.core.versions import compare
from diysca.scanning.correlate import correlate_lang
from diysca.scanning.langpkgs import (
    MARK,
    LangPackage,
    lang_script,
    parse_lang_output,
    parse_lockfile,
)


def test_parse_installed_artifacts():
    out = "\n".join([
        "D\t/srv/app/venv/lib/python3.12/site-packages/Requests-2.31.0.dist-info",
        "D\t/opt/x/lib/python3.9/site-packages/PyYAML-5.3.1-py3.9.egg-info",
        "G\t/opt/ruby/lib/ruby/gems/3.3.0/specifications/nokogiri-1.15.4-x86_64-linux.gemspec",
        "N\t/srv/web/node_modules/lodash/package.json\tlodash\t4.17.20",
        "N\t/srv/web/node_modules/@babel/core/package.json\t@babel/core\t7.22.0",
        "P\t/opt/app/lib/log4j-core-2.14.1.jar\tgroupId=org.apache.logging.log4j",
        "P\t/opt/app/lib/log4j-core-2.14.1.jar\tartifactId=log4j-core",
        "P\t/opt/app/lib/log4j-core-2.14.1.jar\tversion=2.14.1",
        "J\t/opt/app/lib/log4j-core-2.14.1.jar",
        "J\t/opt/app/lib/no-pom.jar",
    ])
    got = {(p.ecosystem, p.name, p.version) for p in parse_lang_output(out)}
    assert got == {("PyPI", "requests", "2.31.0"), ("PyPI", "pyyaml", "5.3.1"), ("RubyGems", "nokogiri", "1.15.4"),
                   ("npm", "lodash", "4.17.20"), ("npm", "@babel/core", "7.22.0"),
                   ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")}


def test_lockfiles():
    plock = '{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/express":{"version":"4.17.1"},' \
            '"node_modules/a/node_modules/qs":{"version":"6.7.0"}}}'
    assert {(p.name, p.version) for p in parse_lockfile("/x/package-lock.json", plock)} == {("express", "4.17.1"), ("qs", "6.7.0")}
    gem = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.3)\n    nokogiri (1.13.0-x86_64-linux)\n      racc (~> 1.4)\n\nPLATFORMS\n"
    assert {(p.name, p.version) for p in parse_lockfile("/x/Gemfile.lock", gem)} == {("rack", "2.2.3"), ("nokogiri", "1.13.0")}
    req = "flask==2.0.1\nrequests>=2\n# c\nJinja2[i18n]==3.0.0 ; python_version>'3'\n"
    assert {(p.name, p.version) for p in parse_lockfile("/x/requirements.txt", req)} == {("flask", "2.0.1"), ("Jinja2", "3.0.0")}
    cargo = '[[package]]\nname = "serde"\nversion = "1.0.100"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n' \
            '[[package]]\nname = "myapp"\nversion = "0.1.0"\n'
    assert [(p.ecosystem, p.name) for p in parse_lockfile("/x/Cargo.lock", cargo)] == [("crates.io", "serde")]
    gomod = "module x\n\ngo 1.22\n\nrequire (\n\tgolang.org/x/net v0.17.0\n\tgithub.com/a/b v1.2.3 // indirect\n)\n"
    assert {(p.name, p.version) for p in parse_lockfile("/x/go.mod", gomod)} == {("golang.org/x/net", "v0.17.0"), ("github.com/a/b", "v1.2.3")}
    yarn = '"lodash@^4.17.0", lodash@^4.17.15:\n  version "4.17.15"\n  resolved "x"\n\n"@types/node@*":\n  version "20.1.0"\n'
    assert {(p.name, p.version) for p in parse_lockfile("/x/yarn.lock", yarn)} == {("lodash", "4.17.15"), ("@types/node", "20.1.0")}


def test_lockfile_block_in_output():
    out = f"{MARK} /srv/app/composer.lock\n" + '{"packages":[{"name":"guzzlehttp/guzzle","version":"v7.4.0"}]}' + f"\n{MARK}END\n"
    assert [(p.ecosystem, p.name, p.version) for p in parse_lang_output(out)] == [("Packagist", "guzzlehttp/guzzle", "7.4.0")]


def test_script_mentions_paths():
    s = lang_script(["/srv", "/opt/my app"])
    assert "'/opt/my app'" in s and "dist-info" in s and "pom.properties" in s


def test_lang_versions():
    assert compare("npm", "1.2.3-beta.1", "1.2.3") < 0
    assert compare("Maven", "2.14.1", "2.15.0") < 0
    assert compare("PyPI", "2.0.0rc1", "2.0.0") < 0
    assert compare("Go", "v0.17.0", "v0.9.0") > 0
    assert compare("RubyGems", "1.15.4", "1.15.10") < 0


class FakeOSV:
    local_match = True
    V = {"GHSA-jfh8-c2jp-5v3q": {"id": "GHSA-jfh8-c2jp-5v3q", "aliases": ["CVE-2021-44228"],
                                 "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
                                 "affected": [{"package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
                                               "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.13.0"}, {"fixed": "2.15.0"}]}]}]}}

    async def query_ids(self, queries):
        return [list(self.V) if q["package"]["name"].endswith("log4j-core") else [] for q in queries]

    async def get_vuln(self, vid):
        return self.V[vid]


def test_correlate_lang():
    pkgs = [LangPackage("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1", ["/opt/app/x.jar"]),
            LangPackage("Maven", "org.apache.logging.log4j:log4j-core", "2.17.0", ["/opt/new/x.jar"])]
    c = asyncio.run(correlate_lang(pkgs, FakeOSV()))
    assert len(c) == 1
    assert (c[0].vuln_id, c[0].fixed_version, c[0].severity, c[0].ecosystem) == ("CVE-2021-44228", "2.15.0", "CRITICAL", "Maven")
    assert c[0].location == "/opt/app/x.jar"


def test_composer_installed_json():
    from diysca.scanning.langpkgs import parse_lang_output, MARK, lang_script
    v2 = '{"packages": [{"name": "guzzlehttp/guzzle", "version": "7.4.0"}, {"name": "monolog/monolog", "version": "v2.3.5"},' \
         ' {"name": "acme/x", "version": "dev-main"}], "dev": true}'
    v1 = '[{"name": "symfony/http-kernel", "version": "v4.4.10"}]'
    out = (f"{MARK} /var/www/shop/vendor/composer/installed.json\n{v2}\n{MARK}END\n"
           f"{MARK} /srv/old/vendor/composer/installed.json\n{v1}\n{MARK}END\n"
           f"{MARK} /srv/other/installed.json\n{v1}\n{MARK}END\n")
    got = {(p.ecosystem, p.name, p.version, p.locations[0]) for p in parse_lang_output(out)}
    assert got == {("Packagist", "guzzlehttp/guzzle", "7.4.0", "/var/www/shop"),
                   ("Packagist", "monolog/monolog", "2.3.5", "/var/www/shop"),
                   ("Packagist", "symfony/http-kernel", "4.4.10", "/srv/old")}
    assert "vendor/composer" in lang_script(["/var/www"])
