"""Run commands on a host: locally or over SSH (agentless)."""
from __future__ import annotations

import asyncio
import os
import signal

import asyncssh

from diysca.core.config import settings


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
            "/bin/sh", "-c", cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            start_new_session=True)  # its own process group, so a timeout can stop what the shell started too
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout)
        except (asyncio.TimeoutError, asyncio.CancelledError) as e:
            # don't leave the shell (a long `find`, a hanging package manager) running after we gave up
            try:
                os.killpg(proc.pid, signal.SIGKILL)  # the shell and its children (`sh -c "find ..."` forks)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                await asyncio.wait_for(proc.wait(), 5)
            except (asyncio.TimeoutError, ProcessLookupError):
                pass
            if isinstance(e, asyncio.TimeoutError):
                raise RuntimeError(f"command timed out after {timeout} s") from None
            raise
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
        try:
            res = await asyncio.wait_for(
                self.conn.run(cmd, check=False, encoding=None if binary else "utf-8", errors="replace"), timeout)
        except asyncio.TimeoutError:
            await self.close()  # ends the remote command with the session, and the next run reconnects
            raise RuntimeError(f"command timed out after {timeout} s") from None
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
    if host_row["kind"] == "container":
        from diysca.core import db
        from diysca.scanning.containers import ContainerTransport
        parent = db.q1("SELECT * FROM hosts WHERE id=?", (host_row["parent_id"],))
        if parent is None:
            raise RuntimeError("parent host of this container no longer exists")
        return ContainerTransport(transport_for(parent), host_row["container_runtime"], host_row["container_id"])
    if host_row["connection"] == "local":
        return LocalTransport()
    port = host_row["port"] or 22
    if host_row["connection"] in ("winrm", "psrp") and port in (5985, 5986):
        port = 22  # Windows hosts from an Ansible WinRM inventory: diysca uses their OpenSSH server
    return SSHTransport(host_row["address"], port, host_row["ssh_user"], host_row["key_file"])
