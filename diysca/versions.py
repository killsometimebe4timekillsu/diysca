"""Version comparison for dpkg, rpm and apk package versions.

These are faithful re-implementations of the algorithms used by the package
managers themselves, so "is 16.6-1 < 16.7-1~deb12u1" gives the same answer
dpkg would.
"""
from __future__ import annotations

import re
from functools import cmp_to_key


# --------------------------------------------------------------------- dpkg
def _dpkg_order(c: str) -> int:
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if not c:
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _dpkg_verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dpkg_order(a[i]) if i < len(a) else 0
            bc = _dpkg_order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _dpkg_split(v: str) -> tuple[int, str, str]:
    v = v.strip()
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    if "-" in v:
        upstream, rev = v.rsplit("-", 1)
    else:
        upstream, rev = v, ""
    return epoch, upstream, rev


def dpkg_compare(a: str, b: str) -> int:
    ea, ua, ra = _dpkg_split(a)
    eb, ub, rb = _dpkg_split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    r = _dpkg_verrevcmp(ua, ub)
    if r:
        return -1 if r < 0 else 1
    r = _dpkg_verrevcmp(ra, rb)
    return 0 if r == 0 else (-1 if r < 0 else 1)


# ---------------------------------------------------------------------- rpm
_RPM_SEG = re.compile(r"(\d+|[a-zA-Z]+|~|\^)")


def _rpmvercmp(a: str, b: str) -> int:
    if a == b:
        return 0
    sa = _RPM_SEG.findall(a)
    sb = _RPM_SEG.findall(b)
    while sa or sb:
        x = sa.pop(0) if sa else None
        y = sb.pop(0) if sb else None
        if x == "~" or y == "~":
            if x != "~":
                return 1
            if y != "~":
                return -1
            continue
        if x == "^" or y == "^":
            if x is None:
                return -1
            if y is None:
                return 1
            if x != "^":
                return 1
            if y != "^":
                return -1
            continue
        if x is None:
            return -1
        if y is None:
            return 1
        if x.isdigit() and y.isdigit():
            xi, yi = int(x), int(y)
            if xi != yi:
                return -1 if xi < yi else 1
        elif x.isdigit():
            return 1
        elif y.isdigit():
            return -1
        elif x != y:
            return -1 if x < y else 1
    return 0


def _rpm_split(v: str) -> tuple[int, str, str]:
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    if "-" in v:
        ver, rel = v.rsplit("-", 1)
    else:
        ver, rel = v, ""
    return epoch, ver, rel


def rpm_compare(a: str, b: str) -> int:
    ea, va, ra = _rpm_split(a)
    eb, vb, rb = _rpm_split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    r = _rpmvercmp(va, vb)
    if r:
        return r
    if ra and rb:
        return _rpmvercmp(ra, rb)
    return 0


# ---------------------------------------------------------------------- apk
_APK_SUFFIX = {"alpha": -4, "beta": -3, "pre": -2, "rc": -1, "": 0, "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5}
_APK_RE = re.compile(r"^([0-9.]+)([a-z]?)((?:_[a-z]+[0-9]*)*)(?:-r([0-9]+))?$")


def _apk_key(v: str):
    m = _APK_RE.match(v.strip())
    if not m:
        return None
    nums = [int(x) for x in m.group(1).split(".") if x != ""]
    letter = m.group(2) or ""
    suffixes = []
    for s in filter(None, m.group(3).split("_")):
        sm = re.match(r"([a-z]+)([0-9]*)", s)
        name, n = sm.group(1), int(sm.group(2) or 0)
        suffixes.append((_APK_SUFFIX.get(name, 0), n))
    rel = int(m.group(4) or 0)
    return nums, letter, suffixes, rel


def apk_compare(a: str, b: str) -> int:
    ka, kb = _apk_key(a), _apk_key(b)
    if ka is None or kb is None:  # unparseable: fall back to dpkg-ish ordering
        return dpkg_compare(a, b)
    na, la, sa, ra = ka
    nb, lb, sb, rb = kb
    for x, y in zip(na, nb):
        if x != y:
            return -1 if x < y else 1
    if len(na) != len(nb):
        return -1 if len(na) < len(nb) else 1
    if la != lb:
        return -1 if la < lb else 1
    sa = sa + [(0, 0)] * (len(sb) - len(sa))
    sb = sb + [(0, 0)] * (len(sa) - len(sb))
    for x, y in zip(sa, sb):
        if x != y:
            return -1 if x < y else 1
    if ra != rb:
        return -1 if ra < rb else 1
    return 0


COMPARATORS = {"deb": dpkg_compare, "rpm": rpm_compare, "apk": apk_compare}


def compare(pkg_type: str, a: str, b: str) -> int:
    """pkg_type: deb | rpm | apk, or an OSV language ecosystem (PyPI, npm, Maven, ...)."""
    if pkg_type in COMPARATORS:
        return COMPARATORS[pkg_type](a, b)
    return lang_compare(pkg_type, a, b)


def max_version(pkg_type: str, versions):
    versions = [v for v in versions if v]
    if not versions:
        return None
    return sorted(versions, key=cmp_to_key(lambda a, b: compare(pkg_type, a, b)))[-1]


# ------------------------------------------------- language ecosystems
_PRE_ORDER = {"dev": -6, "snapshot": -6, "alpha": -5, "a": -5, "beta": -4, "b": -4, "milestone": -3, "m": -3,
              "pre": -2, "preview": -2, "rc": -2, "cr": -2, "c": -2, "": 0, "ga": 0, "final": 0, "release": 0,
              "sp": 1, "post": 1, "p": 1}


def _generic_key(v: str):
    """Ordering that works for semver (npm, crates, Go, Packagist), RubyGems and most Maven versions."""
    v = v.strip().lstrip("vV").split("+", 1)[0]
    main, pre = v, ""
    m = re.match(r"^([0-9]+(?:\.[0-9]+)*)(.*)$", v)
    if m:
        main, pre = m.group(1), m.group(2).lstrip("-._")
    nums = [int(x) for x in main.split(".") if x.isdigit()]
    while nums and nums[-1] == 0:
        nums.pop()
    parts = []
    for tok in re.findall(r"[0-9]+|[A-Za-z]+", pre):
        if tok.isdigit():
            parts.append((1, int(tok), ""))
        else:
            parts.append((0, _PRE_ORDER.get(tok.lower(), -1), tok.lower()))
    # no suffix ranks above pre-releases but below post-releases
    rank = 0 if not parts else (parts[0][1] if parts[0][0] == 0 else 1)
    return nums, rank, parts


def _pypi_compare(a: str, b: str) -> int | None:
    try:
        from packaging.version import InvalidVersion, Version
    except ImportError:
        return None
    try:
        va, vb = Version(a), Version(b)
    except InvalidVersion:
        return None
    return (va > vb) - (va < vb)


def lang_compare(ecosystem: str, a: str, b: str) -> int:
    if ecosystem == "PyPI":
        r = _pypi_compare(a, b)
        if r is not None:
            return r
    ka, kb = _generic_key(a), _generic_key(b)
    na, nb = ka[0], kb[0]
    for x, y in zip(na, nb):
        if x != y:
            return -1 if x < y else 1
    if len(na) != len(nb):
        return -1 if len(na) < len(nb) else 1
    if ka[1] != kb[1]:
        return -1 if ka[1] < kb[1] else 1
    if ka[2] != kb[2]:
        return -1 if ka[2] < kb[2] else 1
    return 0
