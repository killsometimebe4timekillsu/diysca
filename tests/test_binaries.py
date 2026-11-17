"""Go and Rust programs: modules read from the ELF sections, with the shell tools a scanned system has."""
import asyncio
import json
import struct
import zlib

from diysca.core.versions import compare
from diysca.scanning import binaries
from diysca.scanning.correlate import evaluate
from diysca.scanning.transport import LocalTransport

SENT_A = bytes.fromhex("3077af0c9274080241e1c107e6d618e6")
SENT_B = bytes.fromhex("f932433186182072008242104116d8f2")


def _uv(n: int) -> bytes:
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


def go_buildinfo(version: str, modinfo: str) -> bytes:
    head = binaries.GO_MAGIC + bytes([8, 2]) + b"\0" * 16
    mod = SENT_A + modinfo.encode() + SENT_B
    return head + _uv(len(version)) + version.encode() + _uv(len(mod)) + mod


def elf(sections: dict[str, bytes], pad: int = 120_000) -> bytes:
    """A minimal ELF64 little-endian file with the given sections (big enough for the size filter)."""
    names = b"\0" + b"".join(n.encode() + b"\0" for n in [*sections, ".shstrtab"])
    body = b"\0" * pad
    offsets, data = {}, b""
    base = 64 + len(body)
    for n, d in sections.items():
        offsets[n] = base + len(data)
        data += d
    str_off = base + len(data)
    data += names
    shoff = base + len(data)
    sh = b"\0" * 64  # SHT_NULL
    for n in [*sections, ".shstrtab"]:
        off, size = (str_off, len(names)) if n == ".shstrtab" else (offsets[n], len(sections[n]))
        sh += struct.pack("<IIQQQQIIQQ", names.index(n.encode() + b"\0"), 1, 0, 0, off, size, 0, 0, 1, 0)
    shnum = len(sections) + 2
    ident = b"\x7fELF" + bytes([2, 1, 1]) + b"\0" * 9
    hdr = ident + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64, shnum, shnum - 1)
    return hdr + body + data + sh


def test_go_and_rust_programs_are_read(tmp_path):
    mods = ("path\texample.com/tool\nmod\texample.com/tool\tv1.4.0\th1:x=\n"
            "dep\tgolang.org/x/net\tv0.20.0\th1:y=\n"
            "dep\tgithub.com/old/lib\tv1.0.0\th1:z=\n=>\tgithub.com/fork/lib\tv1.0.3\th1:w=\n"
            "dep\texample.com/local\t(devel)\t\nbuild\tGOOS=linux\n")
    crates = {"packages": [{"name": "demo", "version": "0.1.0", "source": "local"},
                           {"name": "smallvec", "version": "1.6.0", "source": "crates.io"},
                           {"name": "cc", "version": "1.0.0", "source": "crates.io", "kind": "build"}]}
    (tmp_path / "bin").mkdir()
    for name, content in {"gotool": elf({".text": b"\x90" * 64, ".go.buildinfo": go_buildinfo("go1.22.4", mods)}),
                          "rusttool": elf({".text": b"\x90" * 64, ".dep-v0": zlib.compress(json.dumps(crates).encode())}),
                          "plain": elf({".text": b"\x90" * 64}),
                          "script": b"#!/bin/sh\n" + b"#" * 200_000}.items():
        f = tmp_path / "bin" / name
        f.write_bytes(content)
        f.chmod(0o755)
    (tmp_path / "bin" / "not-executable").write_bytes(elf({".go.buildinfo": go_buildinfo("go1.1.0", "")}))
    got = asyncio.run(binaries.scan(LocalTransport(), [str(tmp_path)], 60))
    found = {(p.ecosystem, p.name, p.version, p.locations[0].rsplit("/", 1)[1]) for p in got}
    assert found == {
        ("Go", "stdlib", "1.22.4", "gotool"), ("Go", "example.com/tool", "v1.4.0", "gotool"),
        ("Go", "golang.org/x/net", "v0.20.0", "gotool"), ("Go", "github.com/fork/lib", "v1.0.3", "gotool"),
        ("crates.io", "smallvec", "1.6.0", "rusttool")}


def test_odd_section_data_is_ignored():
    assert binaries.go_buildinfo(b"not go") == (None, [])
    assert binaries.go_buildinfo(binaries.GO_MAGIC + bytes([8, 0]) + b"\0" * 40) == (None, [])  # Go < 1.18
    assert binaries.rust_crates(b"\x78\x9cgarbage") == []
    assert binaries.rust_crates(zlib.compress(b"[1, 2]")) == []
    assert binaries.wanted_section("zz", "00") is None
    # a path with a newline can't be asked for again safely: dropped
    assert binaries.parse_candidates("E\tab\tcd\tx\ny") == []


def test_semver_prereleases_in_osv_ranges():
    # Go standard library record GO-2023-1987: 1.26.2 is not affected; "1.21.0-0" is the lowest 1.21 pre-release
    rng = {"ranges": [{"type": "SEMVER", "events": [
        {"introduced": "0"}, {"fixed": "1.19.12"}, {"introduced": "1.20.0-0"}, {"fixed": "1.20.7"},
        {"introduced": "1.21.0-0"}, {"fixed": "1.21.0-rc.4"}]}]}
    assert evaluate(rng, "1.26.2", "Go") == (False, None)
    assert evaluate(rng, "1.20.3", "Go") == (True, "1.20.7")
    assert evaluate(rng, "1.21.0-rc.1", "Go")[0]
    nix = {"ranges": [{"type": "SEMVER", "events": [{"introduced": "0.23.0-0"}, {"fixed": "0.23.0"}]}]}
    assert not evaluate(nix, "0.30.1", "crates.io")[0]
    for a, b in [("1.21.0-0", "1.21.0-rc.4"), ("1.0.0-alpha", "1.0.0-alpha.1"), ("1.0.0-beta.2", "1.0.0-beta.11"),
                 ("1.0.0-rc.1", "1.0.0"), ("v0.0.0-20211030160813-b3129d9d1021", "v0.1.0"), ("1.2", "1.2.1")]:
        assert compare("Go", a, b) < 0 and compare("npm", b, a) > 0, (a, b)
    assert compare("crates.io", "0.20.5+deprecated", "0.20.5") == 0
