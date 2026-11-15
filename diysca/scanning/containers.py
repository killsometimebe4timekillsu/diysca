"""Container images running on scanned hosts.

On every host scan diysca lists running containers of the runtimes it finds
(podman, docker, nerdctl, crictl), picks one container per distinct image and
scans it like a system: OS packages, configured repos, language packages.
Each image shows up as its own system "<host>/<container>" (kind=container)
with its own findings and SBOM.

The scan runs `<runtime> exec <container> sh -c ...` through the host's SSH
session, so the SSH user needs access to the runtime (rootless podman of that
user, the docker group, or `container_sudo: true` with a sudo rule for the
runtime binary). Images without /bin/sh (distroless, scratch) are reported
as not scannable.
"""
from __future__ import annotations

import json
import re
import shlex

from diysca.core import db
from diysca.core.config import settings
from diysca.scanning.transport import Transport

SEP = "@@DIYSCA-CT@@"


def discover_script() -> str:
    sudo = "sudo -n " if settings.container_sudo else ""
    rts = " ".join(shlex.quote(r) for r in settings.container_runtimes)
    fmt = "{{.ID}}\t{{.Names}}\t{{.Image}}"
    return f"""
for rt in {rts}; do
  command -v "$rt" >/dev/null 2>&1 || continue
  if [ "$rt" = crictl ]; then
    echo "{SEP}crictl"; {sudo}crictl ps -o json 2>/dev/null
    continue
  fi
  {sudo}"$rt" ps --no-trunc --format '{fmt}' 2>/dev/null | while IFS="$(printf '\\t')" read -r id name image; do
    iid=$({sudo}"$rt" inspect --format '{{{{.Image}}}}' "$id" 2>/dev/null)
    printf '%s\\t%s\\t%s\\t%s\\t%s\\n' "$rt" "$id" "$name" "$image" "$iid"
  done
done
"""


def parse_discovery(output: str) -> list[dict]:
    found = []
    lines = output.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line == SEP + "crictl":
            buf = []
            i += 1
            while i < len(lines) and not lines[i].startswith(SEP) and "\t" not in lines[i]:
                buf.append(lines[i])
                i += 1
            try:
                for c in json.loads("\n".join(buf) or "{}").get("containers", []):
                    found.append({"runtime": "crictl", "id": c["id"],
                                  "name": (c.get("metadata") or {}).get("name") or c["id"][:12],
                                  "image": (c.get("image") or {}).get("image") or c.get("imageRef", ""),
                                  "image_id": c.get("imageRef", "")})
            except (ValueError, KeyError):
                pass
            continue
        parts = line.split("\t")
        if len(parts) >= 4 and parts[0] in ("podman", "docker", "nerdctl"):
            found.append({"runtime": parts[0], "id": parts[1], "name": parts[2].split(",")[0],
                          "image": parts[3], "image_id": parts[4] if len(parts) > 4 else parts[3]})
        i += 1
    # one container per image is enough
    seen, uniq = set(), []
    for c in found:
        key = c["image_id"] or c["image"]
        if key not in seen:
            seen.add(key)
            uniq.append(c)
    return uniq


async def discover_containers(t: Transport) -> list[dict]:
    return parse_discovery(await t.run(discover_script(), timeout=120))


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.\-]", "_", name)


def sync_container_hosts(parent, containers: list[dict]) -> list[int]:
    """Create/update one system per image on this host; drop the ones that are gone."""
    ids = []
    groups = ",".join(sorted({g for g in (parent["groups"] or "").split(",") if g} | {"container"}))
    for c in containers:
        name = f"{parent['name']}/{_safe(c['name'])}"
        db.x("""INSERT INTO hosts(name,address,port,ssh_user,key_file,connection,groups,source,kind,parent_id,
                                  container_runtime,container_id,image)
                VALUES (?,?,?,?,?,?,?,'container','container',?,?,?,?)
                ON CONFLICT(name) DO UPDATE SET address=excluded.address, groups=excluded.groups,
                  parent_id=excluded.parent_id, container_runtime=excluded.container_runtime,
                  container_id=excluded.container_id, image=excluded.image""",
             (name, parent["address"], parent["port"], parent["ssh_user"], parent["key_file"], parent["connection"],
              groups, parent["id"], c["runtime"], c["id"], c["image"]))
        row = db.q1("SELECT id, enabled FROM hosts WHERE name=?", (name,))
        if row["enabled"]:
            ids.append(row["id"])
    keep = [f"{parent['name']}/{_safe(c['name'])}" for c in containers]
    for row in db.q("SELECT id, name FROM hosts WHERE parent_id=? AND kind='container'", (parent["id"],)):
        if row["name"] not in keep:
            db.x("DELETE FROM hosts WHERE id=?", (row["id"],))
            db.event("scan", f"{row['name']}: container gone, removed")
    return ids


class ContainerTransport(Transport):
    """Runs commands inside a container through the host's transport."""

    def __init__(self, parent: Transport, runtime: str, container_id: str):
        self.parent, self.runtime, self.cid = parent, runtime, container_id

    def _wrap(self, cmd: str) -> str:
        sudo = "sudo -n " if settings.container_sudo else ""
        user = "" if self.runtime == "crictl" else "-u 0 "
        return f"{sudo}{shlex.quote(self.runtime)} exec {user}{shlex.quote(self.cid)} sh -c {shlex.quote(cmd)}"

    async def run(self, cmd: str, binary: bool = False, timeout: int = 300):
        return await self.parent.run(self._wrap(cmd), binary=binary, timeout=timeout)

    async def close(self):
        await self.parent.close()
