"""Run commands on a host: locally or over SSH (agentless)."""
from __future__ import annotations

import asyncio
import os

import asyncssh

from .config import settings


class Transport:
    async def run(self, cmd: str, binary: bool = False, timeout: int = 300):
        raise NotImplementedError

    async def close(self):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        await self.close()


class LocalTransport(Transport):
    async def run(self, cmd: str, binary: bool = False, timeout: int = 300):
        proc = await asyncio.create_subprocess_exec(
            "/bin/sh", "-c", cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
        if proc.returncode not in (0, None) and not out:
            raise RuntimeError(err.decode(errors="replace").strip() or f"exit {proc.returncode}")
        return out if binary else out.decode(errors="replace")


class SSHTransport(Transport):
    def __init__(self, host: str, port: int = 22, user: str | None = None, key_file: str | None = None,
                 password: str | None = None):
        self.host, self.port, self.user, self.key_file, self.password = host, port, user, key_file, password
        self.conn = None

    async def connect(self):
        kw = dict(host=self.host, port=self.port, username=self.user or settings.ssh_user or None,
                  connect_timeout=settings.ssh_timeout)
        key = self.key_file or settings.ssh_key
        if key:
            kw["client_keys"] = [os.path.expanduser(key)]
        if self.password:
            kw["password"] = self.password
        if settings.ssh_known_hosts == "ignore":
            kw["known_hosts"] = None
        elif settings.ssh_known_hosts:
            kw["known_hosts"] = os.path.expanduser(settings.ssh_known_hosts)
        self.conn = await asyncssh.connect(**kw)
        return self

    async def run(self, cmd: str, binary: bool = False, timeout: int = 300):
        if self.conn is None:
            await self.connect()
        res = await asyncio.wait_for(
            self.conn.run(cmd, check=False, encoding=None if binary else "utf-8", errors="replace"), timeout)
        if res.exit_status not in (0, None) and not res.stdout:
            err = res.stderr if isinstance(res.stderr, str) else (res.stderr or b"").decode(errors="replace")
            raise RuntimeError(err.strip() or f"exit {res.exit_status}")
        return res.stdout

    async def close(self):
        if self.conn is not None:
            self.conn.close()
            await self.conn.wait_closed()
            self.conn = None


def transport_for(host_row) -> Transport:
    if host_row["connection"] == "local":
        return LocalTransport()
    return SSHTransport(host_row["address"], host_row["port"] or 22, host_row["ssh_user"], host_row["key_file"])
