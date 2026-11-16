"""Access the package repositories configured on a host.

For every repo we download its package index (apt Packages, yum/dnf
repodata primary.xml, apk APKINDEX) and learn the newest version it offers
for each package. This tells us whether a CVE fix is actually installable
from *your* repos (local mirrors, Aptly, Pulp, Nexus, ...), not just
whether upstream has released one.

Indexes are fetched by the scanner itself (`repo_fetch: scanner`) or, for
repos only reachable from inside the host's network, through the host via
SSH using curl/wget (`repo_fetch: host`).
"""
from __future__ import annotations

import asyncio
import bz2
import io
import ipaddress
import lzma
import re
import shlex
import socket
import tarfile
import time
import zlib
import xml.etree.ElementTree as ET

import httpx

from diysca.core.config import settings
from diysca.core.versions import compare
from diysca.scanning.collectors import HostFacts, Repo, parse_apk_db

_CACHE: dict[str, tuple[float, dict[str, str]]] = {}
CACHE_TTL = 3600


class FetchError(Exception):
    pass


MAX_DOWNLOAD = 400 * 1024 * 1024      # compressed index, as downloaded
MAX_INDEX = 2 * 1024 * 1024 * 1024    # after decompression


def _bounded(decompressor, data: bytes) -> bytes:
    out = decompressor.decompress(data, MAX_INDEX)
    if not decompressor.eof and len(out) >= MAX_INDEX:
        raise FetchError("index is larger than 2 GB after decompression")
    return out


def _decompress(url: str, data: bytes) -> bytes:
    """Repo URLs come from the scanned systems, so a hostile one can serve a decompression bomb: stop at 2 GB."""
    if url.endswith(".gz"):
        out = b""
        while data:  # gzip files may have several members
            d = zlib.decompressobj(wbits=31)
            out += d.decompress(data, MAX_INDEX - len(out))
            if not d.eof:
                if len(out) >= MAX_INDEX:
                    raise FetchError("index is larger than 2 GB after decompression")
                break
            data = d.unused_data
        return out
    if url.endswith(".xz"):
        return _bounded(lzma.LZMADecompressor(), data)
    if url.endswith(".bz2"):
        return _bounded(bz2.BZ2Decompressor(), data)
    if url.endswith(".zst"):
        try:
            import zstandard
        except ImportError as e:
            raise FetchError("zstd index needs the 'zstandard' package") from e
        return zstandard.ZstdDecompressor().decompressobj().decompress(data)
    return data


def _forbidden_address(host: str) -> str | None:
    """Why the scanner must not fetch from `host`, or None. Loopback and link-local addresses are never a
    package mirror for the scanner; they are the scanner itself and the cloud metadata service."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return None  # let the HTTP client report the DNS error
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            return f"{host} resolves to {ip} (loopback / link-local)"
    return None


async def _guard_request(request: httpx.Request):
    """Runs for every request, redirects included. The URLs are whatever the scanned system's repo files say."""
    if request.url.scheme not in ("http", "https"):
        raise FetchError(f"unsupported repo URL {str(request.url)[:80]}")
    why = await asyncio.to_thread(_forbidden_address, request.url.host)
    if why:
        raise FetchError(f"refusing to fetch {request.url}: {why}. Use repo_fetch: host for repos only the system "
                         "itself can reach.")


class Fetcher:
    def __init__(self, transport=None):
        self.transport = transport if settings.repo_fetch == "host" else None
        self.client = httpx.AsyncClient(timeout=settings.http_timeout, follow_redirects=True, max_redirects=5,
                                        verify=settings.http_proxy_ca or True,
                                        event_hooks={"request": [_guard_request]})

    async def get(self, url: str) -> bytes:
        if url.startswith("file://") and self.transport is None:
            raise FetchError("file:// repos can only be read with repo_fetch: host")
        if self.transport is not None:
            if url.startswith("file://"):
                cmd = f"cat -- {shlex.quote(url[7:])}"
            elif not url.startswith(("http://", "https://", "ftp://")):
                raise FetchError(f"unsupported repo URL {url[:80]}")  # also keeps "-o file" style values from curl
            else:
                u = shlex.quote(url)
                cmd = f"curl -fsSL -- {u} 2>/dev/null || wget -qO- -- {u}"
            data = await self.transport.run(cmd, binary=True)
            if not data:
                raise FetchError(f"empty response for {url}")
            return data
        if not url.startswith(("http://", "https://")):
            raise FetchError(f"unsupported repo URL {url[:80]} (the scanner reads http and https repos; "
                             "repo_fetch: host also reads file and ftp)")
        async with self.client.stream("GET", url) as r:
            if r.status_code != 200:
                raise FetchError(f"HTTP {r.status_code} for {url}")
            chunks, size = [], 0
            async for chunk in r.aiter_bytes():
                size += len(chunk)
                if size > MAX_DOWNLOAD:
                    raise FetchError(f"{url} is larger than {MAX_DOWNLOAD // 1024 // 1024} MB")
                chunks.append(chunk)
            return b"".join(chunks)

    async def get_first(self, urls: list[str]) -> tuple[str, bytes]:
        errors = []
        for u in urls:
            try:
                data = await self.get(u)
                return u, await asyncio.to_thread(_decompress, u, data)  # tens of MB: not on the event loop
            except Exception as e:  # try next compression variant
                if str(e) not in errors:
                    errors.append(str(e))
        raise FetchError("; ".join(errors[-2:]))

    async def close(self):
        await self.client.aclose()


# ------------------------------------------------------------------ parsers
def parse_apt_packages(text: str) -> dict[str, tuple[str, str]]:
    """name -> (version, source) keeping the newest version."""
    out: dict[str, tuple[str, str]] = {}
    name = ver = src = None
    for line in text.splitlines() + [""]:
        if not line.strip():
            if name and ver:
                if name not in out or compare("deb", ver, out[name][0]) > 0:
                    out[name] = (ver, (src or name).split()[0])
            name = ver = src = None
        elif line.startswith("Package:"):
            name = line[8:].strip()
        elif line.startswith("Version:"):
            ver = line[8:].strip()
        elif line.startswith("Source:"):
            src = line[7:].strip()
    return out


def parse_primary_xml(data: bytes) -> dict[str, tuple[str, str]]:
    out: dict[str, tuple[str, str]] = {}
    for _, el in ET.iterparse(io.BytesIO(data)):
        if el.tag.endswith("}package") or el.tag == "package":
            name = ver = None
            src = ""
            for c in el:
                t = c.tag.split("}")[-1]
                if t == "name":
                    name = c.text
                elif t == "version":
                    e, v, r = c.get("epoch", "0"), c.get("ver"), c.get("rel")
                    ver = f"{v}-{r}" if e in ("0", None) else f"{e}:{v}-{r}"
                elif t == "format":
                    for f in c:
                        if f.tag.split("}")[-1] == "sourcerpm" and f.text:
                            src = f.text.rsplit("-", 2)[0]
            if name and ver and (name not in out or compare("rpm", ver, out[name][0]) > 0):
                out[name] = (ver, src or name)
            el.clear()
    return out


def parse_apkindex_tar(data: bytes) -> dict[str, tuple[str, str]]:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        member = next((m for m in tf.getmembers() if m.name == "APKINDEX"), None)
        if member is None:
            raise FetchError("APKINDEX missing in archive")
        text = tf.extractfile(member).read(MAX_INDEX).decode(errors="replace")
    out = {}
    for p in parse_apk_db(text):
        if p.name not in out or compare("apk", p.version, out[p.name][0]) > 0:
            out[p.name] = (p.version, p.source_name)
    return out


# ---------------------------------------------------------- per repo kind
def _yum_subst(url: str, facts: HostFacts) -> str:
    major = facts.os_version.split(".")[0]
    rel = major if facts.os_id in ("rocky", "almalinux", "rhel", "centos", "ol") else facts.os_version
    for k, v in (("$releasever_major", major), ("${releasever}", rel), ("$releasever", rel),
                 ("${basearch}", facts.arch), ("$basearch", facts.arch), ("$arch", facts.arch)):
        url = url.replace(k, v)
    return url


async def _apt_base(fetcher: Fetcher, repo: Repo) -> str:
    """The real base URL of an apt repo. apt's mirror method (`mirror+https://host/list`, `mirror://host/list`)
    names a list of mirrors: fetch it and take the first entry. `mirror+file:` lists are read on the host during
    the scan (collectors.resolve_mirror_files); one that is still here could not be read."""
    url = repo.url
    if url.startswith("mirror+file:"):
        raise FetchError(f"mirror list /{url[len('mirror+file:'):].lstrip('/')} could not be read on the system")
    if url.startswith(("mirror+http://", "mirror+https://", "mirror://")):
        list_url = "http://" + url[len("mirror://"):] if url.startswith("mirror://") else url[len("mirror+"):]
        for raw in (await fetcher.get(list_url)).decode(errors="replace").splitlines():
            line = raw.split("#", 1)[0].split()
            if line and line[0].startswith(("http://", "https://")):
                return line[0].rstrip("/")
        raise FetchError(f"mirror list {list_url[:80]} has no http(s) entry")
    if not url.startswith(("http://", "https://", "file://", "ftp://")):
        raise FetchError(f"unsupported repo URL {url[:80]}")  # cdrom:, s3:, tor+http:, ...
    return url


async def apt_priority(fetcher: Fetcher, repo: Repo, base: str | None = None) -> int:
    """apt's default pin priority for the repo, from its Release file: 500, or 100 for `NotAutomatic: yes` with
    `ButAutomaticUpgrades: yes` (backports), or 1 for `NotAutomatic: yes` alone (experimental). apt never picks a
    candidate from such a repo while a normal repo offers one, so neither may diysca."""
    base = base or await _apt_base(fetcher, repo)
    where = f"{base}/{repo.suite.rstrip('/')}".replace("/./", "/") if repo.suite.endswith("/") else f"{base}/dists/{repo.suite}"
    try:
        text = (await fetcher.get(f"{where}/Release")).decode(errors="replace")[:20000]
    except Exception:
        return 500  # no Release file (some flat repos): a normal repo
    head = {k.strip().lower(): v.strip().lower() for k, _, v in
            (line.partition(":") for line in text.splitlines() if line[:1] not in (" ", "\t") and ":" in line)}
    if head.get("notautomatic") != "yes":
        return 500
    return 100 if head.get("butautomaticupgrades") == "yes" else 1


async def fetch_repo_index(fetcher: Fetcher, repo: Repo, facts: HostFacts, base: str | None = None) -> dict[str, tuple[str, str]]:
    if repo.kind == "apt":
        arch = facts.deb_arch or {"x86_64": "amd64", "aarch64": "arm64"}.get(facts.arch, facts.arch)
        url = base or await _apt_base(fetcher, repo)
        bases = []
        if repo.suite.endswith("/"):  # flat repository
            bases.append(f"{url}/{repo.suite.rstrip('/')}/Packages".replace("/./", "/"))
        else:
            for comp in repo.components or ["main"]:
                bases.append(f"{url}/dists/{repo.suite}/{comp}/binary-{arch}/Packages")
        merged: dict[str, tuple[str, str]] = {}
        for b in bases:
            _, data = await fetcher.get_first([b + ".xz", b + ".gz", b])
            parsed = await asyncio.to_thread(lambda d=data: parse_apt_packages(d.decode(errors="replace")))
            for n, (v, s) in parsed.items():
                if n not in merged or compare("deb", v, merged[n][0]) > 0:
                    merged[n] = (v, s)
        return merged
    if repo.kind == "yum":
        if not repo.url.startswith(("http", "file:", "ftp")) or "mirrorlist" in repo.url or "metalink" in repo.url:
            raise FetchError("mirrorlist/metalink repos not supported yet; set baseurl")
        base = _yum_subst(repo.url, facts)
        if "$" in base:
            raise FetchError(f"unresolved variable in baseurl {base}")
        _, repomd = await fetcher.get_first([f"{base}/repodata/repomd.xml"])
        m = re.search(rb'<data type="primary">.*?<location href="([^"]+)"', repomd, re.S)
        if not m:
            raise FetchError("primary metadata not found in repomd.xml")
        href = m.group(1).decode()
        _, primary = await fetcher.get_first([f"{base}/{href}"])
        return await asyncio.to_thread(parse_primary_xml, primary)
    if repo.kind == "apk":
        arch = facts.arch or "x86_64"
        data = await fetcher.get(f"{repo.url}/{arch}/APKINDEX.tar.gz")
        return await asyncio.to_thread(parse_apkindex_tar, data)
    raise FetchError(f"unknown repo kind {repo.kind}")


def _candidate(installed: str | None, by_priority: dict[int, str], pkg_type: str) -> str | None:
    """What the package manager would install: among the versions that are no downgrade, the one from the repo with
    the highest priority. The installed version itself counts with priority 100, as in apt."""
    for prio in sorted(by_priority, reverse=True):
        v = by_priority[prio]
        if installed is None:
            return v
        if prio < 100:
            return None  # e.g. experimental: never chosen over what is installed
        if compare(pkg_type, v, installed) >= 0:
            return v
    return None


async def collect_repo_versions(facts: HostFacts, transport=None):
    """Returns (name -> the version the system would upgrade to, per-repo status list)."""
    offers: dict[str, dict[int, str]] = {}  # name -> {repo priority: newest version at that priority}
    statuses = []
    if settings.repo_fetch == "off":
        return {}, [(r, "skipped", "repo_fetch=off", 0) for r in facts.repos]
    fetcher = Fetcher(transport)
    try:
        for repo in facts.repos:
            if not repo.enabled:
                statuses.append((repo, "disabled", "", 0))
                continue
            key = f"{settings.repo_fetch}|{facts.arch}|{repo.key}"
            try:
                cached = _CACHE.get(key)
                if cached and time.time() - cached[0] < CACHE_TTL:
                    idx, prio = cached[1], cached[2]
                else:
                    base = await _apt_base(fetcher, repo) if repo.kind == "apt" else None
                    full = await fetch_repo_index(fetcher, repo, facts, base)
                    idx = {n: v for n, (v, _s) in full.items()}
                    prio = await apt_priority(fetcher, repo, base) if repo.kind == "apt" else 500
                    _CACHE[key] = (time.time(), idx, prio)
                for n, v in idx.items():
                    have = offers.setdefault(n, {})
                    if prio not in have or compare(facts.pkg_type, v, have[prio]) > 0:
                        have[prio] = v
                statuses.append((repo, "ok", "" if prio == 500 else f"priority {prio}: only used for packages "
                                 "already installed from it", len(idx)))
            except Exception as e:
                statuses.append((repo, "error", str(e)[:500], 0))
    finally:
        await fetcher.close()
    installed = {p.name: p.version for p in facts.packages}
    newest = {}
    for n, by_priority in offers.items():
        v = _candidate(installed.get(n), by_priority, facts.pkg_type)
        if v is not None:
            newest[n] = v
    return newest, statuses
