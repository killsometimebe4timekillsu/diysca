"""Language packages: PyPI, npm, RubyGems, Maven, Packagist (Composer), crates.io, Go.

Two sources on each host (or container):
* installed artifacts: *.dist-info / *.egg-info, node_modules/*/package.json,
  specifications/*.gemspec, META-INF/maven/**/pom.properties inside *.jar
* lockfiles: package-lock.json, yarn.lock, Gemfile.lock, poetry.lock,
  Pipfile.lock, requirements*.txt (== pins), composer.lock, Cargo.lock, go.mod
* PHP: vendor/composer/installed.json, which Composer writes on every install, so PHP applications deployed
  with their vendor/ directory but without composer.lock are covered too

Only the paths in `lang_scan_paths` are searched (default: where apps and
pip/npm/gem installs usually live, not the distro's own /usr/lib), so OS
packages are not reported twice.
"""
from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass, field

LOCK_NAMES = ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "Gemfile.lock", "poetry.lock",
              "Pipfile.lock", "requirements.txt", "requirements-*.txt", "composer.lock", "Cargo.lock", "go.mod"]
MARK = "@@DIYSCA-LANG@@"
PRUNE = ["proc", "sys", "dev", "run", ".git", ".cache", ".npm", ".cargo/registry", "go/pkg/mod", ".m2", "__pycache__"]


def lang_script(paths: list[str], max_lock_bytes: int = 4_000_000, max_entries: int = 50000) -> str:
    """One /bin/sh script that prints everything we need, tagged per line.

    File names and file contents on the scanned system are written by its users, so the script never puts
    them into a program (sed, awk, sh -c) or an unquoted expansion, and it uses no temporary files: the
    scan often runs with more rights than the users who can write below the scan paths."""
    p = " ".join(shlex.quote(x) for x in paths)
    prune = " -o ".join(f"-path '*/{d}'" for d in PRUNE)
    locks = " -o ".join(f"-name '{n}'" for n in LOCK_NAMES)
    return f"""
set --
for r in {p}; do [ -d "$r" ] && set -- "$@" "$r"; done
[ $# -eq 0 ] && exit 0
find "$@" -xdev \\( {prune} \\) -prune -o \\( \\
    \\( -type d \\( -name '*.dist-info' -o -name '*.egg-info' \\) -print \\) -o \\
    \\( -type f -name '*.gemspec' -path '*/specifications/*' -print \\) -o \\
    \\( -type f -name package.json -path '*/node_modules/*' -print \\) -o \\
    \\( -type f -name '*.jar' -print \\) -o \\
    \\( -type f \\( {locks} \\) -not -path '*/node_modules/*' -print \\) -o \\
    \\( -type f -name installed.json -path '*/vendor/composer/*' -print \\) \\
  \\) 2>/dev/null | head -n {max_entries} | while IFS= read -r f; do
  case "$f" in
    *.dist-info|*.egg-info) printf 'D\\t%s\\n' "$f" ;;
    *.gemspec) printf 'G\\t%s\\n' "$f" ;;
    */package.json)
      n=$(grep -m1 '"name"' "$f" 2>/dev/null | sed 's/.*"name" *: *"\\([^"]*\\)".*/\\1/')
      v=$(grep -m1 '"version"' "$f" 2>/dev/null | sed 's/.*"version" *: *"\\([^"]*\\)".*/\\1/')
      [ -n "$n" ] && [ -n "$v" ] && printf 'N\\t%s\\t%s\\t%s\\n' "$f" "$n" "$v" ;;
    *.jar)
      if command -v unzip >/dev/null 2>&1; then
        unzip -p "$f" 'META-INF/maven/*/pom.properties' 2>/dev/null | tr -d '\\r' | grep -E '^(groupId|artifactId|version)=' | while IFS= read -r l; do printf 'P\\t%s\\t%s\\n' "$f" "$l"; done
      fi
      printf 'J\\t%s\\n' "$f" ;;
    *) printf '{MARK} %s\\n' "$f"; head -c {max_lock_bytes} "$f" 2>/dev/null; printf '\\n{MARK}END\\n' ;;
  esac
done
"""


@dataclass
class LangPackage:
    ecosystem: str
    name: str
    version: str
    locations: list[str] = field(default_factory=list)


def _norm_pypi(n: str) -> str:
    return re.sub(r"[-_.]+", "-", n).lower()


def _split_name_version(stem: str) -> tuple[str, str] | None:
    """foo-bar-1.2.3[-x86_64-linux] -> (foo-bar, 1.2.3[-x86_64-linux])"""
    m = re.match(r"^(.+?)-(\d[^-]*)(?:-.*)?$", stem)
    return (m.group(1), m.group(2)) if m else None


# ------------------------------------------------------------- lockfiles
def parse_package_lock(text: str) -> list[tuple[str, str]]:
    d = json.loads(text)
    out = []
    for path, info in (d.get("packages") or {}).items():
        if not path or "node_modules/" not in path or not isinstance(info, dict) or not info.get("version"):
            continue
        if info.get("link"):
            continue
        name = info.get("name") or path.rsplit("node_modules/", 1)[1]
        out.append((name, info["version"]))
    if not out:
        def walk(deps):
            for name, info in (deps or {}).items():
                if isinstance(info, dict) and info.get("version"):
                    out.append((name, info["version"]))
                    walk(info.get("dependencies"))
        walk(d.get("dependencies"))
    return out


def parse_yarn_lock(text: str) -> list[tuple[str, str]]:
    out = []
    names: list[str] = []
    for line in text.splitlines():
        if line and not line.startswith((" ", "#")) and line.rstrip().endswith(":"):
            names = []
            for spec in line.rstrip(":").split(","):
                spec = spec.strip().strip('"')
                m = re.match(r"^(@?[^@]+)@", spec)
                if m:
                    names.append(m.group(1))
        else:
            m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line)
            if m and names:
                out.append((names[0], m.group(1)))
                names = []
    return out


def parse_gemfile_lock(text: str) -> list[tuple[str, str]]:
    out, in_specs = [], False
    for line in text.splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs:
            m = re.match(r"^    ([A-Za-z0-9_.\-]+) \(([^)]+)\)$", line)
            if m:
                out.append((m.group(1), m.group(2).split("-")[0]))
            elif line and not line.startswith("     "):
                in_specs = line.startswith("  ") and not line.startswith("    ") and False
    return out


def _toml_packages(text: str) -> list[tuple[str, str, str]]:
    try:
        import tomllib
    except ImportError:  # pragma: no cover (python < 3.11)
        return []
    d = tomllib.loads(text)
    return [(p.get("name", ""), p.get("version", ""), p.get("source", "")) for p in d.get("package", [])]


def parse_requirements(text: str) -> list[tuple[str, str]]:
    out = []
    for line in text.splitlines():
        m = re.match(r"^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9_.!+\-]+)", line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def parse_lockfile(path: str, text: str) -> list[LangPackage]:
    base = path.rsplit("/", 1)[-1]
    res: list[tuple[str, str, str]] = []
    try:
        if base in ("package-lock.json", "npm-shrinkwrap.json"):
            res = [("npm", n, v) for n, v in parse_package_lock(text)]
        elif base == "yarn.lock":
            res = [("npm", n, v) for n, v in parse_yarn_lock(text)]
        elif base == "Gemfile.lock":
            res = [("RubyGems", n, v) for n, v in parse_gemfile_lock(text)]
        elif base == "poetry.lock":
            res = [("PyPI", n, v) for n, v, _ in _toml_packages(text)]
        elif base == "Cargo.lock":
            res = [("crates.io", n, v) for n, v, src in _toml_packages(text) if src.startswith("registry+")]
        elif base == "Pipfile.lock":
            d = json.loads(text)
            for sec in ("default", "develop"):
                for n, info in (d.get(sec) or {}).items():
                    v = (info or {}).get("version", "")
                    if v.startswith("=="):
                        res.append(("PyPI", n, v[2:]))
        elif base.startswith("requirements") and base.endswith(".txt"):
            res = [("PyPI", n, v) for n, v in parse_requirements(text)]
        elif base == "composer.lock":
            d = json.loads(text)
            for sec in ("packages", "packages-dev"):
                for p in d.get(sec) or []:
                    if p.get("name") and p.get("version"):
                        res.append(("Packagist", p["name"], p["version"].lstrip("v")))
        elif base == "installed.json" and "/vendor/composer/" in path:
            d = json.loads(text)
            pkgs = d.get("packages", []) if isinstance(d, dict) else d  # Composer 2 | Composer 1
            for p in pkgs or []:
                v = str(p.get("version") or "")
                if p.get("name") and v and not v.startswith("dev-"):
                    res.append(("Packagist", p["name"], v.lstrip("v")))
            path = path.split("/vendor/composer/", 1)[0]
        elif base == "go.mod":
            for m in re.finditer(r"^\s*(?:require\s+)?([a-zA-Z0-9.\-_/]+\.[a-z]+/[^\s]+)\s+(v[^\s]+)", text, re.M):
                res.append(("Go", m.group(1), m.group(2)))
    except Exception:
        return []
    return [LangPackage(e, n, v, [path]) for e, n, v in res if n and v]


def parse_lang_output(output: str) -> list[LangPackage]:
    found: dict[tuple[str, str, str], LangPackage] = {}
    poms: dict[str, dict[str, str]] = {}

    def add(p: LangPackage):
        if p.ecosystem == "PyPI":
            p.name = _norm_pypi(p.name)
        key = (p.ecosystem, p.name, p.version)
        if key in found:
            for loc in p.locations:
                if loc not in found[key].locations and len(found[key].locations) < 5:
                    found[key].locations.append(loc)
        else:
            found[key] = p

    lines = output.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith(MARK + " "):
            path = line[len(MARK) + 1:]
            buf = []
            i += 1
            while i < len(lines) and lines[i] != MARK + "END":
                buf.append(lines[i])
                i += 1
            for p in parse_lockfile(path, "\n".join(buf)):
                add(p)
        elif "\t" in line:
            kind, rest = line.split("\t", 1)
            if kind == "D":
                stem = rest.rsplit("/", 1)[-1].rsplit(".", 1)[0]
                if rest.endswith(".dist-info") and "-" in stem:
                    n, v = stem.rsplit("-", 1)
                else:
                    nv = _split_name_version(stem)
                    n, v = nv if nv else (None, None)
                if n and v:
                    site = rest.rsplit("/", 1)[0]
                    add(LangPackage("PyPI", n, v, [site]))
            elif kind == "G":
                nv = _split_name_version(rest.rsplit("/", 1)[-1][:-len(".gemspec")])
                if nv:
                    add(LangPackage("RubyGems", nv[0], nv[1], [rest.split("/specifications/")[0]]))
            elif kind == "N":
                f, n, v = (rest.split("\t") + ["", ""])[:3]
                if n and v and re.match(r"^\d", v):
                    add(LangPackage("npm", n, v, [f.rsplit("/node_modules/", 1)[0]]))
            elif kind == "P":
                jar, kv = rest.split("\t", 1)
                k, _, v = kv.partition("=")
                poms.setdefault(jar, {})
                if k in poms[jar] and k == "groupId":  # next pom in the same (fat) jar
                    _flush_pom(poms, jar, add)
                poms.setdefault(jar, {})[k] = v.strip()
            elif kind == "J":
                _flush_pom(poms, rest, add)
        i += 1
    return list(found.values())


def _flush_pom(poms, jar, add):
    p = poms.pop(jar, None)
    if p and p.get("groupId") and p.get("artifactId") and p.get("version"):
        add(LangPackage("Maven", f"{p['groupId']}:{p['artifactId']}", p["version"], [jar]))
