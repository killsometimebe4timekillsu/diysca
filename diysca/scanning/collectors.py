"""What we run on a host, and how we parse the output.

Everything here is pure parsing so it can be unit tested without a host.
No command needs root: package databases and repo config files are
world-readable on all supported distros.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

# One shell script, sections separated by markers. Runs under plain /bin/sh.
SEP = "@@DIYSCA@@"
COLLECT_SCRIPT = f"""
echo '{SEP}os-release'; cat /etc/os-release 2>/dev/null || cat /usr/lib/os-release 2>/dev/null
echo '{SEP}hostname'; hostname 2>/dev/null || cat /etc/hostname
echo '{SEP}arch'; uname -m
echo '{SEP}kernel'; uname -r
echo '{SEP}dpkg-arch'; command -v dpkg >/dev/null && dpkg --print-architecture
echo '{SEP}dpkg'; command -v dpkg-query >/dev/null && dpkg-query -W -f='${{Package}}\\t${{Version}}\\t${{Architecture}}\\t${{Source}}\\t${{db:Status-Status}}\\n'
echo '{SEP}rpm'; command -v rpm >/dev/null && rpm -qa --qf '%{{NAME}}\\t%{{EPOCHNUM}}\\t%{{VERSION}}\\t%{{RELEASE}}\\t%{{ARCH}}\\t%{{SOURCERPM}}\\n'
echo '{SEP}apk'; [ -r /lib/apk/db/installed ] && cat /lib/apk/db/installed
echo '{SEP}apt-sources'; for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list; do [ -r "$f" ] && echo "#FILE $f" && cat "$f"; done
echo '{SEP}apt-deb822'; for f in /etc/apt/sources.list.d/*.sources; do [ -r "$f" ] && echo "#FILE $f" && cat "$f" && echo; done
echo '{SEP}apt-mirrors'; grep -ohs 'mirror+file:[^][:space:]]*' /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources | sed 's|^mirror+file:/*|/|' | sort -u | while IFS= read -r f; do [ -r "$f" ] && echo "#FILE $f" && cat -- "$f" && echo; done
echo '{SEP}yum-repos'; for f in /etc/yum.repos.d/*.repo /etc/zypp/repos.d/*.repo; do [ -r "$f" ] && echo "#FILE $f" && cat "$f"; done
echo '{SEP}apk-repos'; [ -r /etc/apk/repositories ] && cat /etc/apk/repositories
echo '{SEP}apache'
""" + r"""for c in /etc/apache2/mods-enabled/*.load /etc/apache2/conf-enabled/*.conf /etc/apache2/httpd.conf \
         /etc/httpd/conf.modules.d/*.conf /etc/httpd/conf.d/*.conf /etc/httpd/conf/httpd.conf \
         /usr/local/apache2/conf/httpd.conf /etc/apache2/sites-enabled/*.conf; do
  [ -r "$c" ] && grep -hiE '^[[:space:]]*LoadModule[[:space:]]' "$c" 2>/dev/null
done | awk '{print $2" "$3}' | tr -d '"' | sort -u | while read -r m f; do
  case "$f" in /*) ;; *) for r in /usr/lib/apache2 /etc/httpd /usr/lib64/httpd /usr/local/apache2; do
    [ -e "$r/$f" ] && f="$r/$f" && break; done ;; esac
  o=""
  command -v dpkg >/dev/null 2>&1 && o=$(dpkg -S "$f" 2>/dev/null | grep -v '^diversion' | head -1 | cut -d: -f1)
  if [ -z "$o" ] && command -v rpm >/dev/null 2>&1; then o=$(rpm -qf --qf '%{NAME}' "$f" 2>/dev/null) || o=""; fi
  printf 'M\t%s\t%s\t%s\n' "$m" "$f" "$o"
done
for b in apache2 httpd /usr/sbin/apache2 /usr/sbin/httpd /usr/local/apache2/bin/httpd; do
  p=$(command -v "$b" 2>/dev/null) || continue
  v=$("$p" -v 2>/dev/null | sed -n 's/^Server version: *//p' | head -1)
  o=""
  command -v dpkg >/dev/null 2>&1 && o=$(dpkg -S "$p" 2>/dev/null | head -1 | cut -d: -f1)
  if [ -z "$o" ] && command -v rpm >/dev/null 2>&1; then o=$(rpm -qf --qf '%{NAME}' "$p" 2>/dev/null) || o=""; fi
  [ -n "$v" ] && printf 'S\t%s\t%s\t%s\n' "$v" "$p" "$o" && break
done
""" + f"""echo '{SEP}end'
"""


@dataclass
class Package:
    name: str
    version: str
    arch: str = ""
    source_name: str = ""
    source_version: str = ""
    type: str = "deb"  # deb | rpm | apk


@dataclass
class Repo:
    kind: str  # apt | yum | apk
    url: str
    suite: str = ""
    components: list[str] = field(default_factory=list)
    name: str = ""
    file: str = ""
    enabled: bool = True

    @property
    def key(self) -> str:
        return f"{self.kind}|{self.url}|{self.suite}|{' '.join(self.components)}"


@dataclass
class HostFacts:
    os_id: str = ""
    os_version: str = ""
    os_pretty: str = ""
    os_codename: str = ""
    hostname: str = ""
    arch: str = ""
    deb_arch: str = ""
    kernel: str = ""
    packages: list[Package] = field(default_factory=list)
    repos: list[Repo] = field(default_factory=list)
    apache: list[dict] = field(default_factory=list)  # loaded Apache modules (and the server), see parse_apache

    @property
    def pkg_type(self) -> str:
        return self.packages[0].type if self.packages else "deb"


def split_sections(output: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    cur = None
    buf: list[str] = []
    for line in output.splitlines():
        if line.startswith(SEP):
            if cur is not None:
                sections[cur] = "\n".join(buf)
            cur, buf = line[len(SEP):].strip(), []
        else:
            buf.append(line)
    if cur is not None:
        sections[cur] = "\n".join(buf)
    return sections


def parse_os_release(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        k, v = line.split("=", 1)
        try:
            v = shlex.split(v)[0] if v.strip() else ""
        except ValueError:
            v = v.strip().strip('"')
        out[k.strip()] = v
    return out


def parse_dpkg(text: str) -> list[Package]:
    pkgs = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 2 or not parts[0]:
            continue
        name, version = parts[0], parts[1]
        arch = parts[2] if len(parts) > 2 else ""
        source = parts[3] if len(parts) > 3 else ""
        status = parts[4] if len(parts) > 4 else "installed"
        if status and status not in ("installed", "half-configured", "unpacked"):
            continue  # removed packages with leftover config ("config-files")
        src_name, src_ver = name, version
        if source:
            m = re.match(r"^(\S+)(?:\s+\((.+)\))?$", source.strip())
            if m:
                src_name = m.group(1)
                src_ver = m.group(2) or version
        pkgs.append(Package(name, version, arch, src_name, src_ver, "deb"))
    return pkgs


def _srpm_name(srpm: str) -> str:
    # bash-5.1.8-6.el9.src.rpm -> bash
    s = re.sub(r"\.(no)?src\.rpm$", "", srpm)
    parts = s.rsplit("-", 2)
    return parts[0] if len(parts) == 3 else s


def parse_rpm(text: str) -> list[Package]:
    pkgs = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 4 or parts[0] == "gpg-pubkey":
            continue
        name, epoch, ver, rel = parts[:4]
        arch = parts[4] if len(parts) > 4 else ""
        srpm = parts[5] if len(parts) > 5 else ""
        full = f"{ver}-{rel}"
        if epoch and epoch not in ("0", "(none)"):
            full = f"{epoch}:{full}"
        src = _srpm_name(srpm) if srpm and srpm != "(none)" else name
        pkgs.append(Package(name, full, arch, src, full, "rpm"))
    return pkgs


def parse_apk_db(text: str) -> list[Package]:
    """Parse /lib/apk/db/installed or APKINDEX (same stanza format)."""
    pkgs = []
    cur: dict[str, str] = {}

    def flush():
        if cur.get("P") and cur.get("V"):
            pkgs.append(Package(cur["P"], cur["V"], cur.get("A", ""), cur.get("o", cur["P"]), cur["V"], "apk"))

    for line in text.splitlines():
        if not line.strip():
            flush()
            cur = {}
            continue
        if len(line) > 2 and line[1] == ":":
            cur.setdefault(line[0], line[2:])
    flush()
    return pkgs


def parse_apt_sources(text: str) -> list[Repo]:
    repos = []
    fname = ""
    for raw in text.splitlines():
        if raw.startswith("#FILE "):
            fname = raw[6:].strip()
            continue
        line = raw.split("#", 1)[0].strip()
        if not line.startswith("deb ") and not line.startswith("deb\t"):
            continue
        line = re.sub(r"\[[^\]]*\]", "", line)  # drop [arch=amd64 signed-by=...]
        parts = line.split()
        if len(parts) < 3:
            continue
        repos.append(Repo("apt", parts[1].rstrip("/"), parts[2], parts[3:], file=fname))
    return repos


def parse_deb822(text: str) -> list[Repo]:
    repos = []
    fname = ""
    stanza: dict[str, str] = {}
    last_key = None

    def flush():
        if not stanza:
            return
        if "deb" not in stanza.get("types", "").split():
            return
        if stanza.get("enabled", "yes").lower() == "no":
            return
        for uri in stanza.get("uris", "").split():
            for suite in stanza.get("suites", "").split():
                comps = stanza.get("components", "").split()
                repos.append(Repo("apt", uri.rstrip("/"), suite, comps, file=fname))

    for raw in text.splitlines() + [""]:
        if raw.startswith("#FILE "):
            flush()
            stanza, fname = {}, raw[6:].strip()
            continue
        if raw.startswith("#"):
            continue
        if not raw.strip():
            flush()
            stanza = {}
            continue
        if raw[0] in " \t" and last_key:
            stanza[last_key] += " " + raw.strip()
            continue
        if ":" in raw:
            k, v = raw.split(":", 1)
            last_key = k.strip().lower()
            stanza[last_key] = v.strip()
    return repos


def parse_yum_repos(text: str) -> list[Repo]:
    repos = []
    fname = ""
    cur: dict[str, str] | None = None
    section = ""

    def flush():
        if cur is None:
            return
        url = cur.get("baseurl", "").split()[0] if cur.get("baseurl") else ""
        enabled = cur.get("enabled", "1").strip() not in ("0", "false", "no")
        if url or cur.get("mirrorlist") or cur.get("metalink"):
            repos.append(Repo("yum", url.rstrip("/") or cur.get("mirrorlist") or cur.get("metalink", ""),
                              name=cur.get("name", section), file=fname, enabled=enabled,
                              suite=section))

    for raw in text.splitlines():
        if raw.startswith("#FILE "):
            flush()
            cur, fname = None, raw[6:].strip()
            continue
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            flush()
            section = line[1:-1]
            cur = {}
            continue
        if cur is not None and "=" in line:
            k, v = line.split("=", 1)
            cur[k.strip().lower()] = v.strip()
    flush()
    return repos


def parse_apk_repos(text: str) -> list[Repo]:
    repos = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        tag = ""
        if line.startswith("@"):
            tag, line = line.split(None, 1)
        repos.append(Repo("apk", line.rstrip("/"), name=tag))
    return repos


def parse_apache(text: str, packages: list[Package]) -> list[dict]:
    """LoadModule lines -> [{"name", "path", "owner", "version", "managed"}], plus the server binary itself.

    A module (or httpd) that belongs to an OS package gets that package's version, and its CVEs come with that
    package. One that no package owns was built or copied by hand: diysca lists it but can't check it."""
    versions = {p.name: p.version for p in packages}
    out = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 3 or parts[0] not in ("M", "S"):
            continue
        kind, a, path, owner = (parts + [""])[:4]
        owner = owner.strip() if owner.strip() in versions else ""  # else: not owned by any package
        name = "httpd" if kind == "S" else a
        version = versions.get(owner) or (a.split("/", 1)[-1].split()[0] if kind == "S" and "/" in a else "")
        out.append({"name": name, "path": path, "owner": owner, "version": version or "unknown",
                    "managed": bool(owner), "server": a if kind == "S" else ""})
    return out


def parse_mirror_lists(text: str) -> dict[str, list[str]]:
    """Mirror list files (apt's mirror method) -> {path: [url, ...]}. A line is a URL, optionally followed by
    metadata such as `priority:1`; apt tries them in order."""
    out: dict[str, list[str]] = {}
    cur = None
    for raw in text.splitlines():
        if raw.startswith("#FILE "):
            cur = out.setdefault(raw[6:].strip(), [])
            continue
        line = raw.split("#", 1)[0].split()
        if cur is not None and line and line[0].startswith(("http://", "https://")):
            cur.append(line[0].rstrip("/"))
    return out


def resolve_mirror_files(repos: list[Repo], lists: dict[str, list[str]]) -> list[Repo]:
    """`mirror+file:///etc/apt/mirrors/debian.list` (the default on Debian cloud images) names a file with the real
    repo URLs. Use the first one, as apt does. A list that could not be read leaves the repo as it is, so the scan
    shows it as an error instead of dropping it."""
    for r in repos:
        if r.kind == "apt" and r.url.startswith("mirror+file:"):
            urls = lists.get("/" + r.url[len("mirror+file:"):].lstrip("/"))
            if urls:
                r.url = urls[0]
    return repos


def parse_collect_output(output: str) -> HostFacts:
    s = split_sections(output)
    osr = parse_os_release(s.get("os-release", ""))
    facts = HostFacts(
        os_id=osr.get("ID", "").lower(),
        os_version=osr.get("VERSION_ID", ""),
        os_pretty=osr.get("PRETTY_NAME", ""),
        os_codename=osr.get("VERSION_CODENAME", "") or osr.get("UBUNTU_CODENAME", ""),
        hostname=s.get("hostname", "").strip(),
        arch=s.get("arch", "").strip(),
        deb_arch=s.get("dpkg-arch", "").strip(),
        kernel=s.get("kernel", "").strip(),
    )
    facts.packages = parse_dpkg(s.get("dpkg", "")) or parse_rpm(s.get("rpm", "")) or parse_apk_db(s.get("apk", ""))
    facts.apache = parse_apache(s.get("apache", ""), facts.packages)
    facts.repos = (resolve_mirror_files(parse_apt_sources(s.get("apt-sources", "")) + parse_deb822(s.get("apt-deb822", "")),
                                        parse_mirror_lists(s.get("apt-mirrors", "")))
                   + parse_yum_repos(s.get("yum-repos", "")) + parse_apk_repos(s.get("apk-repos", "")))
    return facts
