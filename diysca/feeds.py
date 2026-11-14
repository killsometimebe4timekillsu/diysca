"""Public vulnerability sources.

* OSV.dev  - primary source. Aggregates the Debian, Ubuntu, Alpine,
             AlmaLinux, Rocky, SUSE/openSUSE, Red Hat security trackers with
             exact affected/fixed versions per distro release.
* NVD      - CVSS scores/descriptions for CVEs the distro feed didn't score.
* CISA KEV - "known exploited" flag.
"""
from __future__ import annotations

import asyncio
import json
import math
import re
import time
from datetime import datetime, timedelta, timezone

import httpx

from . import db
from .config import settings

SEVERITY_ORDER = ["UNKNOWN", "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")


def sev_rank(s: str | None) -> int:
    s = (s or "UNKNOWN").upper()
    if s in ("MODERATE",):
        s = "MEDIUM"
    if s in ("IMPORTANT",):
        s = "HIGH"
    if s in ("NEGLIGIBLE", "UNIMPORTANT"):
        s = "LOW"
    return SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else 0


def norm_sev(s: str | None) -> str:
    return SEVERITY_ORDER[sev_rank(s)]


def score_to_sev(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score == 0:
        return "NONE"
    if score < 4:
        return "LOW"
    if score < 7:
        return "MEDIUM"
    if score < 9:
        return "HIGH"
    return "CRITICAL"


# ---------------------------------------------------------------- CVSS v3
_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0}, "I": {"H": 0.56, "L": 0.22, "N": 0}, "A": {"H": 0.56, "L": 0.22, "N": 0},
}


def _roundup(x: float) -> float:
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    try:
        m = dict(p.split(":") for p in vector.split("/")[1:])
        scope_changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _W["C"][m["C"]]) * (1 - _W["I"][m["I"]]) * (1 - _W["A"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
        if impact <= 0:
            return 0.0
        if scope_changed:
            return _roundup(min(1.08 * (impact + expl), 10))
        return _roundup(min(impact + expl, 10))
    except Exception:
        return None


def vuln_severity(v: dict) -> tuple[float | None, str, str]:
    """(score, label, vector) from an OSV record."""
    score, label, vector = None, "UNKNOWN", ""
    for s in v.get("severity") or []:
        t, val = s.get("type", ""), str(s.get("score", ""))
        if t == "CVSS_V3" and val.startswith("CVSS:3"):
            sc = cvss3_base_score(val)
            if sc is not None and (score is None or sc > score):
                score, vector = sc, val
        elif t in ("Ubuntu", "Debian") or not val.startswith("CVSS"):
            if sev_rank(val) > sev_rank(label):
                label = norm_sev(val)
    if score is not None:
        label = score_to_sev(score)
    ds = v.get("database_specific") or {}
    if label == "UNKNOWN" and isinstance(ds.get("severity"), str):
        label = norm_sev(ds["severity"])
    for a in v.get("affected") or []:
        eco_s, db_s = a.get("ecosystem_specific") or {}, a.get("database_specific") or {}
        es = eco_s.get("severity") or eco_s.get("ubuntu_priority") or eco_s.get("urgency") or db_s.get("severity")
        if label == "UNKNOWN" and isinstance(es, str):
            label = norm_sev(es)
    return score, label, vector


def vuln_cves(v: dict) -> list[str]:
    ids = [v["id"]] + list(v.get("aliases") or []) + list(v.get("upstream") or []) + list(v.get("related") or [])
    cves = []
    for i in ids:
        m = re.search(r"CVE-\d{4}-\d+", i)
        if m and m.group(0) not in cves:
            cves.append(m.group(0))
    return cves


# --------------------------------------------------------- ecosystems
def osv_ecosystem(os_id: str, version: str, pretty: str = "") -> str | None:
    os_id = (os_id or "").lower()
    major = (version or "").split(".")[0]
    if os_id == "debian" and major:
        return f"Debian:{major}"
    if os_id == "ubuntu" and version:
        lts = version.endswith(".04") and int(version.split(".")[0]) % 2 == 0
        return f"Ubuntu:{version}:LTS" if lts else f"Ubuntu:{version}"
    if os_id == "alpine" and version:
        return "Alpine:v" + ".".join(version.split(".")[:2])
    if os_id == "rocky" and major:
        return f"Rocky Linux:{major}"
    if os_id == "almalinux" and major:
        return f"AlmaLinux:{major}"
    if os_id in ("opensuse-leap",) and version:
        return f"openSUSE:Leap {version}"
    if os_id in ("sles", "sled", "sles_sap") and version:
        v = version.split(".")
        if int(v[0]) >= 16:  # SLE 16+: "SUSE:Linux Enterprise Server 16.0"
            return f"SUSE:Linux Enterprise Server {v[0]}.{v[1] if len(v) > 1 else 0}"
        return f"SUSE:Linux Enterprise Server {v[0]}" + (f" SP{v[1]}" if len(v) > 1 and v[1] != "0" else "")
    if os_id in ("rhel", "centos") and major:
        if int(major) >= 10:  # RHEL 10 advisories are per minor release: "Red Hat:enterprise_linux:10.1"
            return f"Red Hat:enterprise_linux:{version if '.' in version else major}"
        return f"Red Hat:enterprise_linux:{major}::baseos"
    if os_id == "mageia" and major:
        return f"Mageia:{major}"
    return None


# ----------------------------------------------------------------- OSV
class OSVClient:
    def __init__(self, base: str | None = None):
        self.base = (base or settings.osv_url).rstrip("/")
        self.client = httpx.AsyncClient(timeout=settings.http_timeout, verify=settings.http_proxy_ca or True)

    async def close(self):
        await self.client.aclose()

    async def _post(self, path, body, tries=4):
        for i in range(tries):
            try:
                r = await self.client.post(self.base + path, json=body)
                if r.status_code == 200:
                    return r.json()
                if r.status_code < 500 and r.status_code != 429:
                    raise RuntimeError(f"OSV {path}: HTTP {r.status_code} {r.text[:200]}")
            except httpx.TransportError:
                if i == tries - 1:
                    raise
            await asyncio.sleep(2 ** i)
        raise RuntimeError(f"OSV {path}: giving up")

    async def query_ids(self, queries: list[dict]) -> list[list[str]]:
        """queries: [{'package': {'name','ecosystem'}, 'version'}] -> list of vuln ids per query."""
        results: list[list[str]] = []
        for i in range(0, len(queries), 1000):
            chunk = queries[i:i + 1000]
            data = await self._post("/v1/querybatch", {"queries": chunk})
            for q, res in zip(chunk, data.get("results", [])):
                ids = [v["id"] for v in res.get("vulns") or []]
                token = res.get("next_page_token")
                while token:  # rare: >1000 vulns for one package version
                    more = await self._post("/v1/query", {**q, "page_token": token})
                    ids += [v["id"] for v in more.get("vulns") or []]
                    token = more.get("next_page_token")
                results.append(ids)
        return results

    async def get_vuln(self, vid: str) -> dict:
        for i in range(4):
            r = await self.client.get(f"{self.base}/v1/vulns/{vid}")
            if r.status_code == 200:
                return r.json()
            if r.status_code == 404:
                return {}
            await asyncio.sleep(2 ** i)
        raise RuntimeError(f"OSV vuln {vid}: HTTP {r.status_code}")


def store_vuln(v: dict):
    if not v.get("id"):
        return
    score, label, vector = vuln_severity(v)
    cves = vuln_cves(v)
    refs = [r.get("url") for r in v.get("references") or [] if r.get("url")][:20]
    db.x("""INSERT INTO vulns(id,cve,aliases,summary,details,cvss_score,severity,cvss_vector,published,modified,refs,raw,fetched_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET cve=excluded.cve, aliases=excluded.aliases, summary=excluded.summary,
              details=excluded.details, cvss_score=COALESCE(excluded.cvss_score, vulns.cvss_score),
              severity=CASE WHEN excluded.severity='UNKNOWN' THEN vulns.severity ELSE excluded.severity END,
              cvss_vector=excluded.cvss_vector, published=excluded.published, modified=excluded.modified,
              refs=excluded.refs, raw=excluded.raw, fetched_at=excluded.fetched_at""",
         (v["id"], cves[0] if cves else None, json.dumps(cves), (v.get("summary") or "")[:500],
          (v.get("details") or "")[:4000], score, label, vector, v.get("published"), v.get("modified"),
          json.dumps(refs), json.dumps(v), db.now()))


def cached_vuln(vid: str) -> dict | None:
    row = db.q1("SELECT raw, fetched_at FROM vulns WHERE id=?", (vid,))
    if not row:
        return None
    try:
        age = datetime.now(timezone.utc) - datetime.fromisoformat(row["fetched_at"])
    except Exception:
        return None
    if age > timedelta(hours=settings.vuln_cache_hours):
        return None
    return json.loads(row["raw"])


async def fetch_vulns(client: OSVClient, ids: set[str]) -> dict[str, dict]:
    out, missing = {}, []
    for vid in ids:
        c = cached_vuln(vid)
        if c is not None:
            out[vid] = c
        else:
            missing.append(vid)
    sem = asyncio.Semaphore(16)

    async def one(vid):
        async with sem:
            try:
                v = await client.get_vuln(vid)
            except Exception:
                row = db.q1("SELECT raw FROM vulns WHERE id=?", (vid,))  # stale cache beats nothing
                v = json.loads(row["raw"]) if row else {}
            if v:
                store_vuln(v)
                out[vid] = v

    await asyncio.gather(*(one(v) for v in missing))
    return out


# ----------------------------------------------------------------- NVD
async def nvd_enrich(limit: int = 200) -> int:
    """Fill CVSS for CVEs where the distro feed gave none. Respects NVD rate limits."""
    if not settings.nvd_enabled:
        return 0
    rows = db.q("""SELECT DISTINCT f.cve FROM findings f LEFT JOIN nvd_cache n ON n.cve=f.cve
                   WHERE f.cve IS NOT NULL AND f.status='open' AND n.cve IS NULL LIMIT ?""", (limit,))
    if not rows:
        return 0
    delay = 0.7 if settings.nvd_api_key else 6.5
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    n = 0
    async with httpx.AsyncClient(timeout=settings.http_timeout, headers=headers,
                                 verify=settings.http_proxy_ca or True) as c:
        for r in rows:
            cve = r["cve"]
            try:
                resp = await c.get(settings.nvd_url, params={"cveId": cve})
                if resp.status_code == 200:
                    items = resp.json().get("vulnerabilities") or []
                    score = sev = vector = desc = None
                    if items:
                        cv = items[0]["cve"]
                        desc = next((d["value"] for d in cv.get("descriptions", []) if d.get("lang") == "en"), "")
                        metrics = cv.get("metrics", {})
                        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                            if metrics.get(key):
                                d = metrics[key][0]["cvssData"]
                                score, vector = d.get("baseScore"), d.get("vectorString")
                                sev = d.get("baseSeverity") or metrics[key][0].get("baseSeverity") or score_to_sev(score)
                                break
                    db.x("""INSERT INTO nvd_cache VALUES (?,?,?,?,?,?) ON CONFLICT(cve) DO UPDATE SET score=excluded.score,
                            severity=excluded.severity, vector=excluded.vector, description=excluded.description,
                            fetched_at=excluded.fetched_at""",
                         (cve, score, norm_sev(sev) if sev else "UNKNOWN", vector, desc, db.now()))
                    n += 1
                elif resp.status_code in (403, 429):
                    await asyncio.sleep(30)
            except httpx.HTTPError:
                break
            await asyncio.sleep(delay)
    apply_enrichment()
    return n


def apply_enrichment():
    """Use NVD/KEV data on findings that lack a distro severity."""
    db.x("""UPDATE findings SET
              cvss_score = COALESCE(cvss_score, (SELECT score FROM nvd_cache n WHERE n.cve=findings.cve)),
              severity = CASE WHEN severity IS NULL OR severity='UNKNOWN'
                         THEN COALESCE((SELECT severity FROM nvd_cache n WHERE n.cve=findings.cve), 'UNKNOWN')
                         ELSE severity END,
              kev = CASE WHEN EXISTS(SELECT 1 FROM kev k WHERE k.cve=findings.cve) THEN 1 ELSE 0 END""")


# ----------------------------------------------------------------- KEV
_kev_loaded = 0.0


async def refresh_kev(force=False) -> int:
    global _kev_loaded
    if not settings.kev_enabled or (not force and time.time() - _kev_loaded < 86400):
        return 0
    try:
        async with httpx.AsyncClient(timeout=settings.http_timeout, verify=settings.http_proxy_ca or True) as c:
            r = await c.get(settings.kev_url)
            r.raise_for_status()
            items = r.json().get("vulnerabilities", [])
    except Exception as e:
        db.event("feed", f"KEV refresh failed: {e}")
        return 0
    with db.tx() as c:
        c.execute("DELETE FROM kev")
        c.executemany("INSERT INTO kev VALUES (?,?,?,?,?) ON CONFLICT(cve) DO NOTHING",
                      [(i["cveID"], i.get("vulnerabilityName"), i.get("dateAdded"), i.get("dueDate"),
                        i.get("knownRansomwareCampaignUse")) for i in items])
    _kev_loaded = time.time()
    return len(items)


# ------------------------------------------------------- OSV bulk mirror
LANG_ECOSYSTEMS = {"PyPI", "npm", "RubyGems", "Maven", "Packagist", "crates.io", "Go"}


def rh_prefix(eco: str) -> str:
    """Red Hat:enterprise_linux:10.1 / Red Hat:enterprise_linux:9::baseos -> Red Hat:enterprise_linux:<major>"""
    parts = eco.split(":")
    return ":".join(parts[:2] + [parts[2].split(".")[0]]) if len(parts) >= 3 else eco


def eco_matches(aff_eco: str, eco: str) -> bool:
    if aff_eco == eco:
        return True
    if eco.startswith("Red Hat:"):
        p = rh_prefix(eco)
        return aff_eco == p or (aff_eco.startswith(p) and aff_eco[len(p)] in ":.")
    return False


def eco_pkg_type(eco: str) -> str:
    if eco in LANG_ECOSYSTEMS:
        return eco
    if eco.startswith(("Debian", "Ubuntu")):
        return "deb"
    if eco.startswith("Alpine"):
        return "apk"
    return "rpm"


def _trim(v: dict, affected: list[dict]) -> dict:
    keep = {k: v.get(k) for k in ("id", "aliases", "upstream", "related", "summary", "severity", "published", "modified",
                                  "withdrawn", "database_specific", "references") if v.get(k)}
    keep["details"] = (v.get("details") or "")[:2000]
    keep["references"] = (keep.get("references") or [])[:10]
    slim = []
    for a in affected:
        a = dict(a)
        if isinstance(a.get("ecosystem_specific"), dict):
            a["ecosystem_specific"] = {k: x for k, x in a["ecosystem_specific"].items() if k != "binaries"}
        slim.append(a)
    keep["affected"] = slim
    return keep


class BulkOSVClient:
    """OSV data mirrored from the public GCS bucket, matched locally.

    Each distro release is one zip (e.g. Debian:12/all.zip). Good for
    air-gapped scanners: point osv_bulk_url at your own mirror of it.
    """

    local_match = True  # versions are matched here, not by the OSV server

    def __init__(self, base: str | None = None):
        self.base = (base or settings.osv_bulk_url).rstrip("/")
        self.client = httpx.AsyncClient(timeout=600, follow_redirects=True, verify=settings.http_proxy_ca or True)
        self._locks: dict[str, asyncio.Lock] = {}

    async def close(self):
        await self.client.aclose()

    async def ensure(self, eco: str, force: bool = False) -> int:
        lock = self._locks.setdefault(eco, asyncio.Lock())
        async with lock:
            meta = db.q1("SELECT * FROM osv_bulk_meta WHERE ecosystem=?", (eco,))
            if meta and not force:
                age = datetime.now(timezone.utc) - datetime.fromisoformat(meta["fetched_at"])
                if age < timedelta(hours=settings.osv_bulk_hours):
                    return meta["count"]
            from pathlib import Path
            from urllib.parse import quote
            d = Path(settings.data_dir) / "osv"
            d.mkdir(parents=True, exist_ok=True)
            zpath = d / (eco.replace(":", "_").replace(" ", "_") + ".zip")
            headers = {"If-None-Match": meta["etag"]} if meta and meta["etag"] and zpath.exists() else {}
            # per-release zip (e.g. "Debian:12") when the bucket has one, else the whole ecosystem ("Red Hat", "SUSE")
            base_eco = eco.split(":")[0]
            url = f"{self.base}/{quote(eco)}/all.zip"
            if not self.base.startswith("file://") and eco != base_eco:
                head = await self.client.head(url)
                if head.status_code == 404:
                    url = f"{self.base}/{quote(base_eco)}/all.zip"
            if self.base.startswith("file://"):
                root = Path(self.base[7:])
                src = root / eco / "all.zip"
                if not src.exists():
                    src = root / base_eco / "all.zip"
                zpath.write_bytes(src.read_bytes())
                etag = None
            else:
                async with self.client.stream("GET", url, headers=headers) as r:
                    if r.status_code == 304:
                        db.x("UPDATE osv_bulk_meta SET fetched_at=? WHERE ecosystem=?", (db.now(), eco))
                        return meta["count"]
                    if r.status_code != 200:
                        raise RuntimeError(f"OSV bulk {url}: HTTP {r.status_code}")
                    tmp = zpath.with_suffix(".part")
                    with open(tmp, "wb") as fh:
                        async for chunk in r.aiter_bytes(1 << 20):
                            fh.write(chunk)
                    tmp.replace(zpath)
                    etag = r.headers.get("etag")
            n = await asyncio.to_thread(self._load_zip, eco, zpath)
            db.x("""INSERT INTO osv_bulk_meta VALUES (?,?,?,?) ON CONFLICT(ecosystem) DO UPDATE SET
                    fetched_at=excluded.fetched_at, etag=excluded.etag, count=excluded.count""", (eco, db.now(), etag, n))
            db.event("feed", f"OSV bulk {eco}: {n} package advisories loaded")
            return n

    @staticmethod
    def _load_zip(eco: str, zpath) -> int:
        import zipfile
        rows = []
        with zipfile.ZipFile(zpath) as zf:
            for info in zf.infolist():
                if not info.filename.endswith(".json"):
                    continue
                try:
                    v = json.loads(zf.read(info))
                except Exception:
                    continue
                by_pkg: dict[str, list] = {}
                for a in v.get("affected") or []:
                    pk = a.get("package") or {}
                    if eco_matches(pk.get("ecosystem", ""), eco):
                        name = pk.get("name") or ""
                        if eco == "PyPI":
                            name = re.sub(r"[-_.]+", "-", name).lower()
                        by_pkg.setdefault(name, []).append(a)
                for name, affs in by_pkg.items():
                    if name:
                        rows.append((eco, name, v["id"], json.dumps(_trim(v, affs))))
        with db.tx() as c:
            c.execute("DELETE FROM osv_bulk WHERE ecosystem=?", (eco,))
            c.executemany("INSERT INTO osv_bulk VALUES (?,?,?,?) ON CONFLICT(ecosystem, package, id) DO NOTHING", rows)
        return len(rows)

    async def query_ids(self, queries: list[dict]) -> list[list[str]]:
        from .correlate import evaluate
        out = []
        for eco in {q["package"]["ecosystem"] for q in queries}:
            await self.ensure(eco)
        for q in queries:
            eco, name, ver = q["package"]["ecosystem"], q["package"]["name"], q["version"]
            t = eco_pkg_type(eco)
            ids = []
            for r in db.q("SELECT id, raw FROM osv_bulk WHERE ecosystem=? AND package=?", (eco, name)):
                v = json.loads(r["raw"])
                if v.get("withdrawn"):
                    continue
                if any(evaluate(a, ver, t)[0] for a in v.get("affected") or []):
                    ids.append(r["id"])
            out.append(ids)
        return out

    async def get_vuln(self, vid: str) -> dict:
        rows = db.q("SELECT raw FROM osv_bulk WHERE id=?", (vid,))
        if not rows:
            return {}
        v = json.loads(rows[0]["raw"])
        for r in rows[1:]:
            v["affected"] += json.loads(r["raw"])["affected"]
        return v


def make_osv_client():
    return BulkOSVClient() if settings.osv_mode == "bulk" else OSVClient()
