"""Go and Rust programs: the modules compiled into them.

A Go program carries its build information: the Go version it was built with (so the standard library
version) and every module with its version. A Rust program built with cargo-auditable carries its crate list
in a `.dep-v0` section, compressed JSON. Programs installed by copying a binary (`/usr/local/bin/gh`, a
release tarball in `/opt`) are invisible to the package manager and have no lock file, so this is the only
way to see what is inside them.

How it is read on the scanned system, without an agent and with only od, head, tr and find (BusyBox works):
1. One script lists ELF executables below the scan paths whose section names include `.go.buildinfo` or
   `.dep-v0`, with their section headers.
2. The scanner works out where that section is and reads exactly that range in a second call.

File names and contents come from the scanned system: the scripts never put them into a program or an
unquoted expansion. File names that the second call needs are passed as quoted arguments.
"""
from __future__ import annotations

import json
import re
import shlex
import struct
import zlib

from diysca.scanning.langpkgs import PRUNE, LangPackage

GO_MAGIC = b"\xff Go buildinf:"
MAX_SECTION = 4 << 20  # bytes read at most per program


def candidates_script(paths: list[str], max_files: int = 20000) -> str:
    """ELF executables whose section names include `.go.buildinfo` or `.dep-v0`: one line each with the section
    headers and the section name table (hex), then the path. Only od, head, tr and find are used, so it works
    with BusyBox too (Alpine, many container images)."""
    p = " ".join(shlex.quote(x) for x in paths)
    prune = " -o ".join(f"-path '*/{d}'" for d in PRUNE)
    return f"""
command -v od >/dev/null 2>&1 || exit 0
set --
for r in {p}; do [ -d "$r" ] && set -- "$@" "$r"; done
[ $# -eq 0 ] && exit 0
find "$@" -xdev \\( {prune} \\) -prune -o -type f -perm -100 -size +100k -print 2>/dev/null \\
  | head -n {max_files} | while IFS= read -r f; do
  m=$(od -An -N 6 -tx1 "$f" 2>/dev/null | tr -d ' \\n')
  [ "$m" = 7f454c460201 ] || continue  # ELF, 64-bit, little-endian
  so=$(od -An -j 40 -N 8 -tu8 "$f" 2>/dev/null | tr -d ' \\n')
  se=$(od -An -j 58 -N 2 -tu2 "$f" 2>/dev/null | tr -d ' \\n')
  sn=$(od -An -j 60 -N 2 -tu2 "$f" 2>/dev/null | tr -d ' \\n')
  si=$(od -An -j 62 -N 2 -tu2 "$f" 2>/dev/null | tr -d ' \\n')
  case "$so$se$sn$si" in ''|*[!0-9]*) continue ;; esac
  [ "$se" -eq 64 ] && [ "$sn" -gt 0 ] && [ "$sn" -lt 4096 ] && [ "$si" -lt "$sn" ] || continue
  t=$((so + si * 64))
  stro=$(od -An -j $((t + 24)) -N 8 -tu8 "$f" 2>/dev/null | tr -d ' \\n')
  strn=$(od -An -j $((t + 32)) -N 8 -tu8 "$f" 2>/dev/null | tr -d ' \\n')
  case "$stro$strn" in ''|*[!0-9]*) continue ;; esac
  [ "$strn" -lt 65536 ] || continue
  names=$(od -An -v -j "$stro" -N "$strn" -tx1 "$f" 2>/dev/null | tr -d ' \\n')
  case "$names" in
    *2e676f2e6275696c64696e666f*|*2e6465702d7630*)
      printf 'E\\t%s\\t%s\\t%s\\n' "$(od -An -v -j "$so" -N $((sn * 64)) -tx1 "$f" 2>/dev/null | tr -d ' \\n')" \\
        "$names" "$f" ;;
  esac
done
"""


def _uvarint(b: bytes, pos: int) -> tuple[int, int]:
    n = shift = 0
    while pos < len(b):
        c = b[pos]
        pos += 1
        n |= (c & 0x7F) << shift
        if not c & 0x80:
            return n, pos
        shift += 7
    raise ValueError("truncated varint")


def go_modules(lines: list[str]) -> list[tuple[str, str]]:
    """`mod`/`dep` lines (and `=>` replacements, which apply to the line before) -> [(module, version)]."""
    out: list[list[str]] = []
    for line in lines:
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        kind, mod, ver = parts[0], parts[1], parts[2]
        if kind in ("mod", "dep"):
            out.append([mod, ver])
        elif kind == "=>" and out:
            out[-1] = [mod, ver]  # replaced: what is compiled in is the replacement
    return [(m, v) for m, v in out if m and re.match(r"^v\d", v)]


def _sections(table: bytes, strtab: bytes) -> dict[str, tuple[int, int]]:
    out = {}
    for i in range(len(table) // 64):
        name, _type, _flags, _addr, off, size = struct.unpack_from("<IIQQQQ", table, i * 64)
        end = strtab.find(b"\0", name)
        out[strtab[name:end if end >= 0 else None].decode("ascii", "replace")] = (off, size)
    return out


def wanted_section(table_hex: str, strtab_hex: str) -> tuple[str, int, int] | None:
    """(".go.buildinfo" or ".dep-v0", offset, size) from the section headers, or None."""
    try:
        sec = _sections(bytes.fromhex(table_hex), bytes.fromhex(strtab_hex))
    except (ValueError, struct.error):
        return None
    for name in (".go.buildinfo", ".dep-v0"):
        off, size = sec.get(name, (0, 0))
        if 0 < size <= MAX_SECTION and off > 0:
            return name, off, size
    return None


def go_buildinfo(data: bytes) -> tuple[str | None, list[tuple[str, str]]]:
    """`.go.buildinfo` section -> (Go version, [(module, version)]). Go 1.18 and newer keep both inline."""
    if not data.startswith(GO_MAGIC) or len(data) < 33 or not data[15] & 2:
        return None, []
    try:
        n, pos = _uvarint(data, 32)
        ver = data[pos:pos + n].decode("ascii", "replace")
        n, pos = _uvarint(data, pos + n)
        mod = data[pos:pos + n]
    except ValueError:
        return None, []
    if len(mod) >= 33 and mod[-17:-16] == b"\n":
        mod = mod[16:-16]  # sentinels around the module list
    m = re.match(r"go(\d+\.\d+(?:\.\d+)?)", ver)
    return (m.group(1) if m else None), go_modules(mod.decode("utf-8", "replace").splitlines())


def rust_crates(compressed: bytes) -> list[tuple[str, str]]:
    """cargo-auditable data -> [(crate, version)] of crates.io packages compiled in (build-only ones left out)."""
    try:
        d = json.loads(zlib.decompressobj().decompress(compressed, 16 << 20))
    except (zlib.error, ValueError):
        return []
    out = []
    for p in d.get("packages") or [] if isinstance(d, dict) else []:
        if not isinstance(p, dict) or p.get("kind") == "build" or p.get("source") != "crates.io":
            continue
        if p.get("name") and p.get("version"):
            out.append((str(p["name"]), str(p["version"])))
    return out


def parse_candidates(output: str) -> list[tuple[str, str, int, int]]:
    """-> [(path, section name, offset, size)] still to read."""
    out = []
    for line in output.splitlines():
        parts = line.split("\t", 3)
        if len(parts) == 4 and parts[0] == "E" and "\n" not in parts[3]:
            sec = wanted_section(parts[1], parts[2])
            if sec:
                out.append((parts[3], *sec))
    return out


def section_script(items: list[tuple[str, str, int, int]]) -> str:
    """Print each section as one hex line, tagged with its index. Paths are quoted arguments."""
    return "".join(f"printf 'S\\t{i}\\t'; od -An -v -j {int(off)} -N {int(size)} -tx1 {shlex.quote(path)} "
                   "2>/dev/null | tr -d ' \\n'; printf '\\n'\n" for i, (path, _n, off, size) in enumerate(items))


def parse_sections(output: str, items: list[tuple[str, str, int, int]]) -> list[LangPackage]:
    pkgs = []
    for line in output.splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3 or parts[0] != "S" or not parts[1].isdigit() or int(parts[1]) >= len(items):
            continue
        try:
            data = bytes.fromhex(parts[2])
        except ValueError:
            continue
        path, name = items[int(parts[1])][:2]
        if name == ".go.buildinfo":
            ver, mods = go_buildinfo(data)
            if ver:
                pkgs.append(LangPackage("Go", "stdlib", ver, [path]))
            pkgs += [LangPackage("Go", m, v, [path]) for m, v in mods]
        else:
            pkgs += [LangPackage("crates.io", n, v, [path]) for n, v in rust_crates(data)]
    return pkgs


async def scan(t, paths: list[str], timeout: int) -> list[LangPackage]:
    """Go modules (and the Go standard library) and Rust crates compiled into the programs below `paths`."""
    items = parse_candidates(await t.run(candidates_script(paths), timeout=timeout))
    pkgs: list[LangPackage] = []
    for i in range(0, len(items), 50):
        chunk = items[i:i + 50]
        pkgs += parse_sections(await t.run(section_script(chunk), timeout=timeout), chunk)
    return pkgs
