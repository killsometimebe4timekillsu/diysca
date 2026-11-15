"""Extra vulnerability sources, on top of OSV / NVD / CISA KEV.

Sources are configured in config.yml (`sources:`) or added in the web UI
(Sources page). Every source is downloaded on its own schedule, converted to
OSV records and matched locally, with the same version logic as OSV data.

Types
-----
debian-tracker  Debian security tracker JSON. Adds CVEs that have no DSA/DLA
                yet (status "open"), with Debian's urgency.
alpine-secdb    secdb.alpinelinux.org/<release>/<repo>.json
osv             any feed in OSV format: a .zip of records, a JSON record,
                a JSON list, NDJSON, or a local directory. Use it for a GHSA
                export, a Go vulndb dump, or your own advisories.
custom          your own JSON / YAML / CSV feed, mapped to fields with `fields:`.
epss            FIRST EPSS scores (probability of exploitation). Enrichment
                only: shown on findings, usable in filters.

Records from a source keep their own id, prefixed with the source name
("debian-tracker/CVE-2025-1234"), so they never collide with OSV ids.
"""
from __future__ import annotations

import asyncio
import csv
import gzip
import io
import json
import re
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import yaml

from diysca.core import db
from diysca.core.config import settings
from diysca.scanning.feeds import eco_matches, eco_pkg_type, norm_sev, score_to_sev

TYPES = {
    "debian-tracker": "Debian security tracker",
    "alpine-secdb": "Alpine secdb",
    "osv": "OSV-format feed",
    "custom": "Custom JSON / YAML / CSV",
    "epss": "FIRST EPSS scores",
}
DEFAULT_URLS = {
    "debian-tracker": "https://security-tracker.debian.org/tracker/data/json",
    "alpine-secdb": "https://secdb.alpinelinux.org/v3.20/main.json",
    "epss": "https://epss.cyentia.com/epss_scores-current.csv.gz",
}
DEBIAN_RELEASES = {"buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13", "forky": "14"}
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.\-]{0,62}$")


# ------------------------------------------------------------- definitions
def sync_config_sources():
    """config.yml is the source of truth for sources it defines."""
    names = []
    for s in settings.sources or []:
        if not isinstance(s, dict) or not s.get("name") or not s.get("type"):
            continue
        cfg = {k: v for k, v in s.items() if k not in ("name", "type", "enabled")}
        names.append(s["name"])
        db.x("""INSERT INTO feed_sources(name, type, config, origin, enabled) VALUES (?,?,?,'config',?)
                ON CONFLICT(name) DO UPDATE SET type=excluded.type, config=excluded.config, origin='config',
                  enabled=excluded.enabled""",
             (s["name"], s["type"], json.dumps(cfg), int(s.get("enabled", True))))
    for r in db.q("SELECT name FROM feed_sources WHERE origin='config'"):
        if r["name"] not in names:
            remove(r["name"])


def all_sources() -> list[dict]:
    out = []
    for r in db.q("SELECT * FROM feed_sources ORDER BY name"):
        d = dict(r)
        d["cfg"] = json.loads(d["config"] or "{}")
        out.append(d)
    return out


def public(s: dict) -> dict:
    """A source without secrets (header values), for the UI and the API."""
    cfg = dict(s["cfg"])
    if cfg.get("headers"):
        cfg["headers"] = {k: "***" for k in cfg["headers"]}
    return {**{k: v for k, v in s.items() if k not in ("config", "cfg")}, "cfg": cfg}


def get(name: str) -> dict | None:
    r = db.q1("SELECT * FROM feed_sources WHERE name=?", (name,))
    if not r:
        return None
    d = dict(r)
    d["cfg"] = json.loads(d["config"] or "{}")
    return d


def validate(name: str, typ: str, cfg: dict) -> str | None:
    if not NAME_RE.match(name or ""):
        return "Name: use lower-case letters, digits, '-', '_' or '.'."
    if typ not in TYPES:
        return f"Unknown type '{typ}'. Use one of: {', '.join(TYPES)}."
    if not (cfg.get("url") or cfg.get("path") or DEFAULT_URLS.get(typ)):
        return "Give a url or a local path."
    if typ == "custom":
        f = cfg.get("fields") or {}
        if not isinstance(f, dict) or "package" not in f or not ({"fixed", "versions", "last_affected"} & set(f)):
            return "Custom feeds need fields.package and at least one of fields.fixed, fields.versions, fields.last_affected."
        if "ecosystem" not in f and not (cfg.get("defaults") or {}).get("ecosystem"):
            return "Custom feeds need fields.ecosystem or defaults.ecosystem (e.g. 'Debian:12', 'PyPI')."
    return None


def save(name: str, typ: str, cfg: dict, enabled: bool = True):
    err = validate(name, typ, cfg)
    if err:
        raise ValueError(err)
    if cfg.get("path") or not str(cfg.get("url") or "https://").startswith(("http://", "https://")):
        raise ValueError("Sources added in the web UI need an http(s) URL. Local files and directories go in config.yml.")
    row = db.q1("SELECT origin FROM feed_sources WHERE name=?", (name,))
    if row and row["origin"] == "config":
        raise ValueError(f"'{name}' is defined in config.yml. Change it there.")
    db.x("""INSERT INTO feed_sources(name, type, config, origin, enabled) VALUES (?,?,?,'ui',?)
            ON CONFLICT(name) DO UPDATE SET type=excluded.type, config=excluded.config, enabled=excluded.enabled,
              fetched_at=NULL""", (name, typ, json.dumps(cfg), int(enabled)))


def remove(name: str):
    with db.tx() as c:
        c.execute("DELETE FROM advisories WHERE source=?", (name,))
        c.execute("DELETE FROM feed_sources WHERE name=?", (name,))


# ------------------------------------------------------------- fetching
async def _download(src: dict) -> bytes:
    cfg = src["cfg"]
    if cfg.get("path"):
        p = Path(cfg["path"]).expanduser()
        if p.is_dir():
            return b""  # read file by file in _records_osv
        data = p.read_bytes()
        url = str(p)
    else:
        url = cfg.get("url") or DEFAULT_URLS[src["type"]]
        if url.startswith("file://"):
            data = Path(url[7:]).read_bytes()
        else:
            headers = {str(k): str(v) for k, v in (cfg.get("headers") or {}).items()}
            async with httpx.AsyncClient(timeout=max(settings.http_timeout, 300), follow_redirects=True,
                                         verify=settings.http_proxy_ca or True) as c:
                r = await c.get(url, headers=headers)
                r.raise_for_status()
                data = r.content
    if url.endswith(".gz") or data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    return data


def _norm_name(eco: str, name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if eco == "PyPI" else name


def _rows(source: str, records) -> list[tuple]:
    rows = {}
    for v in records:
        if not v.get("id") or v.get("withdrawn"):
            continue
        v = dict(v)
        v["id"] = f"{source}/{v['id']}"
        by: dict[tuple[str, str], list] = {}
        for a in v.get("affected") or []:
            pk = a.get("package") or {}
            if pk.get("ecosystem") and pk.get("name"):
                by.setdefault((pk["ecosystem"], _norm_name(pk["ecosystem"], pk["name"])), []).append(a)
        for (eco, name), affs in by.items():
            rec = dict(v, affected=affs)
            rows[(eco, name, v["id"])] = (source, eco, name, v["id"], json.dumps(rec))
    return list(rows.values())


# --- debian security tracker
def _records_debian(data: bytes, cfg: dict):
    releases = cfg.get("releases") or _debian_releases_in_use() or ["bookworm", "trixie"]
    keep_unimportant = bool(cfg.get("include_unimportant", False))
    tracker = json.loads(data)
    for pkg, cves in tracker.items():
        for cve, info in cves.items():
            if not cve.startswith("CVE-"):
                continue
            affected = []
            for rel in releases:
                r = (info.get("releases") or {}).get(rel)
                ver = DEBIAN_RELEASES.get(rel)
                if not r or not ver:
                    continue
                urgency = re.sub(r"[^a-z ]", "", (r.get("urgency") or "").lower()).strip()
                if urgency == "unimportant" and not keep_unimportant:
                    continue
                status, fixed = r.get("status"), r.get("fixed_version")
                if status == "resolved" and fixed and fixed != "0":
                    events = [{"introduced": "0"}, {"fixed": fixed}]
                elif status == "open":
                    events = [{"introduced": "0"}]
                else:
                    continue  # not affected / undetermined
                affected.append({"package": {"ecosystem": f"Debian:{ver}", "name": pkg},
                                 "ranges": [{"type": "ECOSYSTEM", "events": events}],
                                 "ecosystem_specific": {"urgency": urgency or "not yet assigned"}})
            if affected:
                yield {"id": cve, "aliases": [cve], "summary": (info.get("description") or "")[:300],
                       "affected": affected,
                       "references": [{"type": "WEB", "url": f"https://security-tracker.debian.org/tracker/{cve}"}]}


def _debian_releases_in_use() -> list[str]:
    rows = db.q("SELECT DISTINCT os_codename FROM hosts WHERE os_id='debian' AND os_codename IS NOT NULL")
    return [r["os_codename"] for r in rows if r["os_codename"] in DEBIAN_RELEASES]


# --- alpine secdb
def _records_alpine(data: bytes, cfg: dict):
    d = json.loads(data)
    rel = cfg.get("release") or d.get("distroversion") or ""
    eco = f"Alpine:{rel}" if rel.startswith("v") else f"Alpine:v{rel}"
    by_cve: dict[str, list] = {}
    for p in d.get("packages") or []:
        pk = p.get("pkg") or {}
        for fixed, ids in (pk.get("secfixes") or {}).items():
            if fixed in ("0", "", None):
                continue  # "0" = never affected in this release
            for i in ids or []:
                cve = str(i).split()[0]
                by_cve.setdefault(cve, []).append(
                    {"package": {"ecosystem": eco, "name": pk.get("name")},
                     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]})
    for cve, affs in by_cve.items():
        yield {"id": cve, "aliases": [cve] if cve.startswith("CVE-") else [], "affected": affs,
               "references": [{"type": "WEB", "url": f"https://security.alpinelinux.org/vuln/{cve}"}]}


# --- osv format
def _records_osv(data: bytes, cfg: dict):
    ecos = set(cfg.get("ecosystems") or [])

    def keep(v):
        if not ecos:
            return v
        v = dict(v)
        v["affected"] = [a for a in v.get("affected") or []
                         if any(eco_matches((a.get("package") or {}).get("ecosystem", ""), e) or
                                (a.get("package") or {}).get("ecosystem", "").split(":")[0] == e for e in ecos)]
        return v if v["affected"] else None

    def parse_blob(b: bytes):
        txt = b.decode("utf-8", "replace").strip()
        if not txt:
            return
        if txt[0] == "[":
            yield from json.loads(txt)
        elif txt[0] == "{" and "\n{" not in txt:
            obj = json.loads(txt)
            yield from (obj.get("vulns") or obj.get("advisories") or [obj]) if "id" not in obj else [obj]
        else:  # NDJSON
            for line in txt.splitlines():
                if line.strip():
                    yield json.loads(line)

    blobs = []
    if cfg.get("path") and Path(cfg["path"]).expanduser().is_dir():
        blobs = (f.read_bytes() for f in sorted(Path(cfg["path"]).expanduser().rglob("*.json")))
    elif data[:2] == b"PK":
        zf = zipfile.ZipFile(io.BytesIO(data))
        blobs = (zf.read(i) for i in zf.infolist() if i.filename.endswith(".json"))
    else:
        blobs = [data]
    for b in blobs:
        try:
            for v in parse_blob(b):
                v = keep(v)
                if v:
                    yield v
        except ValueError:
            continue


# --- custom json / yaml / csv with field mapping
def _dig(obj, path: str):
    for part in str(path).split("."):
        if obj is None:
            return None
        if isinstance(obj, list):
            try:
                obj = obj[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            obj = obj.get(part) if isinstance(obj, dict) else None
    return obj


def _as_list(v) -> list[str]:
    if v is None or v == "":
        return []
    if isinstance(v, list):
        return [str(x) for x in v if str(x)]
    return [x.strip() for x in re.split(r"[,; ]+", str(v)) if x.strip()]


def _records_custom(data: bytes, cfg: dict):
    fmt = (cfg.get("format") or "").lower()
    path = cfg.get("url") or cfg.get("path") or ""
    if not fmt:
        fmt = "csv" if path.removesuffix(".gz").endswith(".csv") else "yaml" if path.endswith((".yml", ".yaml")) else "json"
    if fmt == "csv":
        items = list(csv.DictReader(io.StringIO(data.decode("utf-8-sig", "replace")),
                                    delimiter=cfg.get("delimiter") or ","))
    else:
        doc = yaml.safe_load(data) if fmt == "yaml" else json.loads(data)
        items = _dig(doc, cfg["records"]) if cfg.get("records") else doc
        if isinstance(items, dict):
            items = list(items.values())
    fields = cfg.get("fields") or {}
    defaults = cfg.get("defaults") or {}

    def val(item, key):
        v = _dig(item, fields[key]) if key in fields else None
        return defaults.get(key) if v in (None, "") else v

    for n, it in enumerate(items or []):
        if not isinstance(it, dict):
            continue
        pkg, eco = val(it, "package"), val(it, "ecosystem")
        if not pkg or not eco:
            continue
        aliases = _as_list(val(it, "aliases"))
        vid = str(val(it, "id") or (aliases[0] if aliases else f"{pkg}-{n}"))
        events = [{"introduced": str(val(it, "introduced") or "0")}]
        if val(it, "fixed"):
            events.append({"fixed": str(val(it, "fixed"))})
        elif val(it, "last_affected"):
            events.append({"last_affected": str(val(it, "last_affected"))})
        aff = {"package": {"ecosystem": str(eco), "name": str(pkg)}}
        versions = _as_list(val(it, "versions"))
        if versions:
            aff["versions"] = versions
        if len(events) > 1 or not versions:
            aff["ranges"] = [{"type": "ECOSYSTEM", "events": events}]
        rec = {"id": vid, "aliases": aliases or ([vid] if vid.startswith("CVE-") else []), "affected": [aff],
               "summary": str(val(it, "summary") or "")[:500], "details": str(val(it, "details") or "")[:2000]}
        ds = {}
        cvss = val(it, "cvss")
        if cvss not in (None, ""):
            if str(cvss).startswith("CVSS:3"):
                rec["severity"] = [{"type": "CVSS_V3", "score": str(cvss)}]
            else:
                try:
                    ds["cvss_score"] = float(cvss)
                    ds["severity"] = score_to_sev(float(cvss))
                except ValueError:
                    pass
        if val(it, "severity"):
            ds["severity"] = norm_sev(str(val(it, "severity")))
        if ds:
            rec["database_specific"] = ds
        refs = _as_list(val(it, "references"))
        if refs:
            rec["references"] = [{"type": "WEB", "url": u} for u in refs]
        yield rec


# --- epss
def _load_epss(data: bytes) -> int:
    lines = [ln for ln in data.decode("utf-8", "replace").splitlines() if ln and not ln.startswith("#")]
    rows = []
    for r in csv.DictReader(lines):
        try:
            rows.append((r["cve"], float(r["epss"]), float(r.get("percentile") or 0)))
        except (KeyError, ValueError):
            continue
    with db.tx() as c:
        c.execute("DELETE FROM epss")
        for i in range(0, len(rows), 5000):
            c.executemany("INSERT INTO epss VALUES (?,?,?) ON CONFLICT(cve) DO NOTHING", rows[i:i + 5000])
    return len(rows)


CONVERTERS = {"debian-tracker": _records_debian, "alpine-secdb": _records_alpine,
              "osv": _records_osv, "custom": _records_custom}


def _store(name: str, rows: list[tuple]) -> int:
    with db.tx() as c:
        c.execute("DELETE FROM advisories WHERE source=?", (name,))
        for i in range(0, len(rows), 5000):
            c.executemany("""INSERT INTO advisories VALUES (?,?,?,?,?)
                             ON CONFLICT(source, ecosystem, package, id) DO NOTHING""", rows[i:i + 5000])
    db.x("DELETE FROM vulns WHERE id LIKE ?", (name + "/%",))  # drop cached copies of old records
    return len(rows)


async def refresh(name: str, force: bool = True) -> dict:
    src = get(name)
    if src is None:
        raise KeyError(name)
    hours = float(src["cfg"].get("refresh_hours") or 24)
    if not force and src["fetched_at"]:
        age = datetime.now(UTC) - datetime.fromisoformat(src["fetched_at"])
        if age < timedelta(hours=hours):
            return {"name": name, "skipped": True, "count": src["count"]}
    try:
        data = await _download(src)
        if src["type"] == "epss":
            n = await asyncio.to_thread(_load_epss, data)
        else:
            conv = CONVERTERS[src["type"]]
            rows = await asyncio.to_thread(lambda: _rows(name, conv(data, src["cfg"])))
            n = await asyncio.to_thread(_store, name, rows)
        db.x("UPDATE feed_sources SET fetched_at=?, count=?, status='ok', error=NULL WHERE name=?", (db.now(), n, name))
        db.event("feed", f"source {name}: {n} {'scores' if src['type'] == 'epss' else 'package advisories'} loaded")
        return {"name": name, "count": n}
    except Exception as e:
        db.x("UPDATE feed_sources SET fetched_at=?, status='error', error=? WHERE name=?",
             (db.now(), str(e)[:500], name))
        db.event("feed", f"source {name}: FAILED {e}")
        return {"name": name, "error": str(e)}


async def refresh_all(force: bool = False) -> list[dict]:
    sync_config_sources()
    out = []
    for s in all_sources():
        if s["enabled"]:
            out.append(await refresh(s["name"], force=force))
    return out


# ------------------------------------------------------------- matching
class SourcesClient:
    """Matches packages against the advisories of all enabled extra sources."""

    local_match = True

    def __init__(self):
        self.names = {s["name"] for s in all_sources() if s["enabled"] and s["type"] != "epss"}

    async def close(self):
        pass

    async def query_ids(self, queries: list[dict]) -> list[list[str]]:
        from diysca.scanning.correlate import evaluate
        out = []
        for q in queries:
            eco, ver = q["package"]["ecosystem"], q["version"]
            name = _norm_name(eco, q["package"]["name"])
            t = eco_pkg_type(eco)
            ids = []
            if self.names:
                for r in db.q("SELECT source, ecosystem, id, raw FROM advisories WHERE package=?", (name,)):
                    if r["source"] not in self.names or not eco_matches(r["ecosystem"], eco) or r["id"] in ids:
                        continue
                    v = json.loads(r["raw"])
                    if any(evaluate(a, ver, t)[0] for a in v.get("affected") or []):
                        ids.append(r["id"])
            out.append(ids)
        return out

    async def get_vuln(self, vid: str) -> dict:
        rows = db.q("SELECT raw FROM advisories WHERE id=?", (vid,))
        if not rows:
            return {}
        v = json.loads(rows[0]["raw"])
        for r in rows[1:]:
            v["affected"] += json.loads(r["raw"])["affected"]
        return v

    def owns(self, vid: str) -> bool:
        return vid.split("/", 1)[0] in self.names if "/" in vid else False


class MultiClient:
    """OSV (api or bulk) plus the extra sources, behind the one client interface."""

    def __init__(self, primary, extra: SourcesClient):
        self.primary, self.extra = primary, extra
        self.local_match = getattr(primary, "local_match", False)

    async def close(self):
        await self.primary.close()

    async def query_ids(self, queries):
        a = await self.primary.query_ids(queries)
        b = await self.extra.query_ids(queries)
        return [x + [i for i in y if i not in x] for x, y in zip(a, b)]

    async def get_vuln(self, vid):
        return await (self.extra if self.extra.owns(vid) else self.primary).get_vuln(vid)
