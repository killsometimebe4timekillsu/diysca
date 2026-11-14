"""Patching, part 2: update self-hosted repositories.

When a fix is released upstream but your hosts can't install it yet, the
local mirror is behind. diysca can bring it forward through the manager's
API and roll the new content out to a stage:

* aptly          update mirror(s) -> snapshot -> switch the published distribution
* Pulp 3         sync repository -> new publication -> point the distribution at it
* Foreman/Katello sync repositories -> publish content view (+ composite) -> promote
                  the new version to lifecycle environment(s) (Test, Prod, ...)

Configured in config.yml under `repo_managers` (see config.example.yml).
`match` lists the URL prefixes hosts use for that manager's content, which is
how a finding is tied to the manager that can fix it. Every run is logged as
an event; `dry_run` only resolves names and lists the steps.
"""
from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field

import httpx

from . import db, repos
from .config import settings


@dataclass
class Step:
    action: str
    detail: str
    status: str = "planned"  # planned | ok | failed | skipped
    info: str = ""


@dataclass
class RunResult:
    manager: str
    dry_run: bool
    steps: list[Step] = field(default_factory=list)
    ok: bool = True

    def add(self, action, detail, status="planned", info=""):
        s = Step(action, detail, status, info)
        self.steps.append(s)
        return s


def managers() -> list[dict]:
    return [m for m in (settings.repo_managers or []) if isinstance(m, dict) and m.get("name")]


def get_manager(name: str) -> dict:
    for m in managers():
        if m["name"] == name:
            return m
    raise KeyError(name)


def _secret(m: dict, key: str) -> str | None:
    """Read `password` / `token` either inline or from the env var named in `<key>_env`."""
    if m.get(f"{key}_env"):
        return os.environ.get(m[f"{key}_env"])
    return m.get(key)


def pending_for(m: dict) -> list:
    """Open findings whose fix is released upstream but missing from a repo served by this manager."""
    prefixes = [p.rstrip("/") for p in (m.get("match") or [])] if isinstance(m.get("match"), list) \
        else [str(m.get("match") or "").rstrip("/")]
    prefixes = [p for p in prefixes if p]
    if not prefixes:
        return []
    likes = " OR ".join("r.url LIKE ?" for _ in prefixes)
    return db.q(f"""SELECT DISTINCT f.id, f.vuln_id, f.package, f.version, f.fixed_version, f.repo_version,
                           f.severity, h.name host_name
                    FROM findings f JOIN hosts h ON h.id=f.host_id JOIN repos r ON r.host_id=h.id
                    WHERE f.status='open' AND f.ecosystem='' AND f.fixed_version IS NOT NULL AND f.fix_in_repo=0
                      AND ({likes})
                    ORDER BY f.severity, h.name""", [p + "%" for p in prefixes])


class _Api:
    def __init__(self, m: dict, transport: httpx.AsyncBaseTransport | None = None):
        auth = None
        if m.get("username"):
            auth = (m["username"], _secret(m, "password") or "")
        headers = {}
        if _secret(m, "token"):
            headers["Authorization"] = f"Bearer {_secret(m, 'token')}"
        verify = m.get("ca_cert") or (False if m.get("verify_tls") is False else True)
        self.c = httpx.AsyncClient(base_url=m["url"].rstrip("/"), auth=auth, headers=headers, verify=verify,
                                   timeout=m.get("timeout", 120), transport=transport)
        self.poll = m.get("poll_seconds", 3)
        self.task_timeout = m.get("task_timeout", 3600)

    async def req(self, method: str, path: str, **kw):
        r = await self.c.request(method, path, **kw)
        if r.status_code >= 400:
            raise RuntimeError(f"{method} {path}: HTTP {r.status_code} {r.text[:300]}")
        return r.json() if r.content and "json" in r.headers.get("content-type", "") else {}

    async def close(self):
        await self.c.aclose()


# --------------------------------------------------------------------- aptly
async def run_aptly(m: dict, res: RunResult, api: _Api):
    stamp = time.strftime("%Y%m%d-%H%M%S")
    pub = m.get("publish") or {}
    prefix, dist = pub.get("prefix", ":."), pub.get("distribution")
    if not dist:
        raise RuntimeError("aptly: publish.distribution is required")
    snaps = []
    for mirror in m.get("mirrors") or []:
        name = mirror["name"] if isinstance(mirror, dict) else mirror
        comp = mirror.get("component", "main") if isinstance(mirror, dict) else "main"
        snap = f"{name}-diysca-{stamp}"
        s1 = res.add("aptly: update mirror", name)
        s2 = res.add("aptly: create snapshot", f"{snap} from mirror {name}")
        snaps.append({"Component": comp, "Name": snap})
        if res.dry_run:
            await api.req("GET", f"/api/mirrors/{name}")
            continue
        await api.req("PUT", f"/api/mirrors/{name}", json={"IgnoreSignatures": bool(m.get("ignore_signatures"))})
        s1.status = "ok"
        await api.req("POST", f"/api/mirrors/{name}/snapshots", json={"Name": snap, "Description": "diysca"})
        s2.status = "ok"
    s3 = res.add("aptly: switch published repo", f"{prefix}/{dist} -> " + ", ".join(s["Name"] for s in snaps))
    if res.dry_run:
        return
    body = {"Snapshots": snaps, "ForceOverwrite": bool(pub.get("force_overwrite"))}
    if pub.get("signing"):
        body["Signing"] = pub["signing"]
    await api.req("PUT", f"/api/publish/{prefix.replace('/', '_')}/{dist}", json=body)
    s3.status = "ok"


# ------------------------------------------------------------------- Pulp 3
_PULP_PATHS = {"deb": ("deb/apt", "deb/apt", "deb/apt"), "rpm": ("rpm/rpm", "rpm/rpm", "rpm/rpm")}


async def _pulp_wait(api: _Api, task_href: str) -> dict:
    deadline = time.time() + api.task_timeout
    while time.time() < deadline:
        t = await api.req("GET", task_href)
        if t.get("state") == "completed":
            return t
        if t.get("state") in ("failed", "canceled"):
            raise RuntimeError(f"Pulp task {task_href} {t.get('state')}: {(t.get('error') or {}).get('description', '')}")
        await asyncio.sleep(api.poll)
    raise RuntimeError(f"Pulp task {task_href} timed out")


async def _pulp_find(api: _Api, kind: str, ptype: str, name: str) -> dict:
    data = await api.req("GET", f"/pulp/api/v3/{kind}/{ptype}/", params={"name": name})
    if not data.get("results"):
        raise RuntimeError(f"Pulp {kind} '{name}' not found")
    return data["results"][0]


async def run_pulp(m: dict, res: RunResult, api: _Api):
    for r in m.get("repositories") or []:
        ptype = _PULP_PATHS[r.get("type", "deb")][0]
        repo = await _pulp_find(api, "repositories", ptype, r["name"])
        remote_href = repo.get("remote")
        if r.get("remote"):
            remote_href = (await _pulp_find(api, "remotes", ptype, r["remote"]))["pulp_href"]
        if not remote_href:
            raise RuntimeError(f"Pulp repository {r['name']} has no remote")
        dist_name = r.get("distribution")
        s1 = res.add("pulp: sync repository", f"{r['name']} from {remote_href}")
        s2 = res.add("pulp: publish", f"new publication of {r['name']}")
        s3 = res.add("pulp: update distribution", dist_name or "(none configured)")
        if res.dry_run:
            if dist_name:
                await _pulp_find(api, "distributions", ptype, dist_name)
            continue
        t = await _pulp_wait(api, (await api.req("POST", f"{repo['pulp_href']}sync/",
                                                 json={"remote": remote_href, "mirror": bool(r.get("mirror", False))}))["task"])
        s1.status = "ok"
        version = next((h for h in t.get("created_resources", []) if "/versions/" in h), None)
        repo = await api.req("GET", repo["pulp_href"])
        version = version or repo.get("latest_version_href")
        s1.info = version or ""
        body = {"repository_version": version}
        if r.get("type", "deb") == "deb":
            body.update({"simple": bool(r.get("simple", True)), "structured": bool(r.get("structured", True))})
        t = await _pulp_wait(api, (await api.req("POST", f"/pulp/api/v3/publications/{ptype}/", json=body))["task"])
        pub_href = next((h for h in t.get("created_resources", []) if "/publications/" in h), None)
        s2.status, s2.info = "ok", pub_href or ""
        if dist_name and pub_href:
            dist = await _pulp_find(api, "distributions", ptype, dist_name)
            t = await api.req("PATCH", dist["pulp_href"], json={"publication": pub_href})
            if t.get("task"):
                await _pulp_wait(api, t["task"])
            s3.status = "ok"
        else:
            s3.status = "skipped"


# ---------------------------------------------------------- Foreman/Katello
async def _fm_wait(api: _Api, task_id: str) -> dict:
    deadline = time.time() + api.task_timeout
    while time.time() < deadline:
        t = await api.req("GET", f"/foreman_tasks/api/tasks/{task_id}")
        if t.get("state") in ("stopped", "paused"):
            if t.get("result") not in ("success", "warning"):
                raise RuntimeError(f"Foreman task {task_id} {t.get('state')}/{t.get('result')}: "
                                   f"{'; '.join(t.get('humanized', {}).get('errors', []) or [])}")
            return t
        await asyncio.sleep(api.poll)
    raise RuntimeError(f"Foreman task {task_id} timed out")


async def _fm_one(api: _Api, path: str, params: dict, what: str) -> dict:
    data = await api.req("GET", path, params=params)
    results = data.get("results") or []
    exact = [r for r in results if r.get("name") == params.get("name")] or results
    if not exact:
        raise RuntimeError(f"Foreman {what} '{params.get('name')}' not found")
    return exact[0]


async def run_foreman(m: dict, res: RunResult, api: _Api, stages: list[str] | None = None):
    org = await _fm_one(api, "/katello/api/organizations", {"name": m["organization"], "search": f'name="{m["organization"]}"'},
                        "organization")
    oid = org["id"]
    # 1. sync the repositories / products behind the content view
    for rname in m.get("repositories") or []:
        repo = await _fm_one(api, "/katello/api/repositories", {"organization_id": oid, "name": rname}, "repository")
        s = res.add("foreman: sync repository", f"{rname} (id {repo['id']})")
        if not res.dry_run:
            await _fm_wait(api, (await api.req("POST", f"/katello/api/repositories/{repo['id']}/sync", json={}))["id"])
            s.status = "ok"
    # 2. publish the content view, then (optionally) the composite that includes it
    cv_names = [m["content_view"]] + ([m["composite_content_view"]] if m.get("composite_content_view") else [])
    last_version = None
    for cvn in cv_names:
        cv = await _fm_one(api, "/katello/api/content_views", {"organization_id": oid, "name": cvn}, "content view")
        s = res.add("foreman: publish content view", f"{cvn} (id {cv['id']})")
        if res.dry_run:
            continue
        body = {"description": "diysca: published to pick up security fixes"}
        await _fm_wait(api, (await api.req("POST", f"/katello/api/content_views/{cv['id']}/publish", json=body))["id"])
        cv = await api.req("GET", f"/katello/api/content_views/{cv['id']}")
        versions = sorted(cv.get("versions") or [], key=lambda v: float(v.get("version", 0)))
        last_version = versions[-1] if versions else None
        s.status, s.info = "ok", f"version {last_version.get('version') if last_version else '?'}"
    # 3. promote the newest version through the configured lifecycle stages
    wanted = stages if stages is not None else (m.get("promote_to") or [])
    if not wanted:
        return
    envs = (await api.req("GET", f"/katello/api/organizations/{oid}/environments")).get("results") or []
    by_name = {e["name"]: e["id"] for e in envs}
    for stage in wanted:
        if stage not in by_name:
            raise RuntimeError(f"Foreman lifecycle environment '{stage}' not found")
        s = res.add("foreman: promote", f"{cv_names[-1]} -> {stage}")
        if res.dry_run:
            continue
        await _fm_wait(api, (await api.req("POST", f"/katello/api/content_view_versions/{last_version['id']}/promote",
                                           json={"environment_ids": [by_name[stage]], "force": False}))["id"])
        s.status = "ok"


RUNNERS = {"aptly": run_aptly, "pulp": run_pulp, "foreman": run_foreman, "katello": run_foreman}


async def run(name: str, dry_run: bool = True, stages: list[str] | None = None,
              transport: httpx.AsyncBaseTransport | None = None) -> RunResult:
    m = get_manager(name)
    res = RunResult(name, dry_run)
    kind = m.get("type", "").lower()
    if kind not in RUNNERS:
        res.ok = False
        res.add("config", f"unknown repo manager type '{kind}'", "failed")
        return res
    api = _Api(m, transport)
    try:
        if kind in ("foreman", "katello"):
            await run_foreman(m, res, api, stages)
        else:
            await RUNNERS[kind](m, res, api)
    except Exception as e:
        res.ok = False
        res.add("error", str(e), "failed")
    finally:
        await api.close()
    if not dry_run:
        repos._CACHE.clear()  # next scan re-reads the repo indexes
        db.event("repo", f"{name}: {'ok' if res.ok else 'FAILED'} - "
                         + "; ".join(f"{s.action} {s.detail} [{s.status}]" for s in res.steps)[:900])
        if res.ok:
            db.patch_run("repo", f"{name} ({kind}) updated" + (f", promoted to {', '.join(stages)}" if stages else ""))
    return res
