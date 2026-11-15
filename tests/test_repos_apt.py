"""apt repos as the system itself sees them: mirror lists, repo priorities (backports), visible fetch errors."""
import asyncio

import pytest

from diysca.core.config import settings
from diysca.scanning import collectors, repos
from diysca.scanning.collectors import HostFacts, Package, Repo


def _pkgs(*rows):
    return "".join(f"Package: {n}\nVersion: {v}\n\n" for n, v in rows).encode()


class FakeFetcher(repos.Fetcher):
    files: dict[str, bytes] = {}

    def __init__(self, transport=None):
        self.asked = []

    async def get(self, url):
        self.asked.append(url)
        if not url.startswith(("http://", "https://")):
            raise repos.FetchError(f"unsupported repo URL {url[:80]}")
        if url not in self.files:
            raise repos.FetchError(f"HTTP 404 for {url}")
        return self.files[url]

    async def close(self):
        pass


@pytest.fixture
def fetch(monkeypatch):
    monkeypatch.setattr(settings, "repo_fetch", "scanner")
    monkeypatch.setattr(repos, "Fetcher", FakeFetcher)
    repos._CACHE.clear()
    FakeFetcher.files = {}
    yield FakeFetcher
    repos._CACHE.clear()


def _facts(repo_list, *installed):
    return HostFacts(os_id="debian", os_version="13", arch="x86_64", deb_arch="amd64", repos=repo_list,
                     packages=[Package(n, v, type="deb") for n, v in installed])


def test_mirror_file_sources_are_resolved():
    out = "\n".join([
        f"{collectors.SEP}apt-deb822", "#FILE /etc/apt/sources.list.d/debian.sources",
        "Types: deb deb-src", "URIs: mirror+file:///etc/apt/mirrors/debian.list", "Suites: trixie trixie-updates",
        "Components: main", "",
        "Types: deb", "URIs: mirror+file:///etc/apt/mirrors/debian-security.list", "Suites: trixie-security",
        "Components: main", "",
        "Types: deb", "URIs: mirror+file:///etc/apt/mirrors/missing.list", "Suites: x", "Components: main", "",
        f"{collectors.SEP}apt-mirrors",
        "#FILE /etc/apt/mirrors/debian.list", "# comment", "https://deb.debian.org/debian\tpriority:1",
        "https://ftp.de.debian.org/debian/", "",
        "#FILE /etc/apt/mirrors/debian-security.list", "https://deb.debian.org/debian-security", ""])
    got = [(r.url, r.suite) for r in collectors.parse_collect_output(out).repos]
    assert got == [("https://deb.debian.org/debian", "trixie"), ("https://deb.debian.org/debian", "trixie-updates"),
                   ("https://deb.debian.org/debian-security", "trixie-security"),
                   ("mirror+file:///etc/apt/mirrors/missing.list", "x")]


def test_unreadable_mirror_list_and_odd_urls_give_a_clear_error(fetch):
    facts = _facts([Repo("apt", "mirror+file:///etc/apt/mirrors/missing.list", "x", ["main"]),
                    Repo("apt", "cdrom:[Debian 13]", "trixie", ["main"])])
    _, status = asyncio.run(repos.collect_repo_versions(facts))
    assert [s[1] for s in status] == ["error", "error"]
    assert status[0][2] == "mirror list /etc/apt/mirrors/missing.list could not be read on the system"
    assert status[1][2] == "unsupported repo URL cdrom:[Debian 13]"


def test_mirror_http_list_is_fetched(fetch):
    fetch.files = {"https://mirrors.example/list.txt": b"# c\nhttps://deb.example/debian/ priority:1\n",
                   "https://deb.example/debian/dists/trixie/main/binary-amd64/Packages": _pkgs(("curl", "8.14.1-2+deb13u7"))}
    facts = _facts([Repo("apt", "mirror+https://mirrors.example/list.txt", "trixie", ["main"])], ("curl", "8.14.1-2"))
    newest, status = asyncio.run(repos.collect_repo_versions(facts))
    assert newest == {"curl": "8.14.1-2+deb13u7"} and status[0][1] == "ok"


def test_backports_are_not_the_upgrade_candidate(fetch):
    base = "https://deb.example/debian/dists"
    fetch.files = {
        f"{base}/trixie-security/main/binary-amd64/Packages": _pkgs(("curl", "8.14.1-2+deb13u7"), ("vim", "9.1-2")),
        f"{base}/trixie-security/Release": b"Suite: stable-security\nCodename: trixie-security\n",
        f"{base}/trixie-backports/main/binary-amd64/Packages": _pkgs(("curl", "8.21.0-2~bpo13+1"), ("tmux", "3.6-1~bpo13+1"),
                                                                    ("jq", "1.9-1~bpo13+1")),
        f"{base}/trixie-backports/Release": b"Suite: stable-backports\nNotAutomatic: yes\nButAutomaticUpgrades: yes\n",
        f"{base}/experimental/main/binary-amd64/Packages": _pkgs(("vim", "9.9-1"), ("zsh", "6.0-1")),
        f"{base}/experimental/Release": b"Suite: experimental\nNotAutomatic: yes\n",
    }
    url = "https://deb.example/debian"
    facts = _facts([Repo("apt", url, s, ["main"]) for s in ("trixie-security", "trixie-backports", "experimental")],
                   ("curl", "8.14.1-2"),          # from stable: security fix wins over the newer backport
                   ("tmux", "3.5-1~bpo13+1"),     # installed from backports: follows backports
                   ("jq", "1.7-1"),               # only backports is newer: apt upgrades to it (priority 100)
                   ("vim", "9.1-1"), ("zsh", "5.9-1"))  # experimental is never an upgrade
    newest, status = asyncio.run(repos.collect_repo_versions(facts))
    assert newest == {"curl": "8.14.1-2+deb13u7", "tmux": "3.6-1~bpo13+1", "jq": "1.9-1~bpo13+1", "vim": "9.1-2"}
    assert "priority 100" in status[1][2] and "priority 1:" in status[2][2] and status[0][2] == ""
    # second run comes from the cache and gives the same answer
    assert asyncio.run(repos.collect_repo_versions(facts))[0] == newest


def test_scan_reports_unreadable_repos(monkeypatch):
    from diysca.core import db
    from diysca.scanning import scanner

    from .test_pipeline import FakeOSV, FakeTransport

    async def no_repos(facts, t):
        return {}, [(Repo("apt", "mirror+file:///etc/apt/mirrors/debian.list", "trixie"), "error", "boom", 0),
                    (Repo("apt", "https://deb.example/debian", "trixie"), "ok", "", 5)]

    monkeypatch.setattr(scanner, "transport_for", lambda h: FakeTransport())
    monkeypatch.setattr(scanner, "collect_repo_versions", no_repos)
    db.x("INSERT INTO hosts(name,address,groups) VALUES ('system_a','10.0.0.11','db')")
    res = asyncio.run(scanner.scan_host(1, client=FakeOSV()))
    assert "1 of 2 package repos could not be read" in res["error"] and "boom" in res["error"]
    assert db.q1("SELECT last_status FROM hosts WHERE id=1")["last_status"] == "partial"
