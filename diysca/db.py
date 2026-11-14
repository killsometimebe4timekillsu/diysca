"""SQLite storage. One file, no server."""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
  id INTEGER PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  address TEXT, port INTEGER DEFAULT 22, ssh_user TEXT, key_file TEXT,
  connection TEXT DEFAULT 'ssh',
  groups TEXT DEFAULT '',            -- comma separated ansible groups
  source TEXT DEFAULT 'manual',      -- inventory path or 'manual'
  enabled INTEGER DEFAULT 1,
  os_id TEXT, os_version TEXT, os_pretty TEXT, os_codename TEXT, arch TEXT, kernel TEXT,
  ecosystem TEXT, pkg_type TEXT,
  last_scan TEXT, last_status TEXT, last_error TEXT
);
CREATE TABLE IF NOT EXISTS packages (
  id INTEGER PRIMARY KEY,
  host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  name TEXT NOT NULL, version TEXT NOT NULL, arch TEXT,
  source_name TEXT, source_version TEXT, type TEXT,
  repo_version TEXT                  -- newest version offered by the host's repos
);
CREATE INDEX IF NOT EXISTS ix_pkg_host ON packages(host_id);
CREATE INDEX IF NOT EXISTS ix_pkg_name ON packages(name);
CREATE TABLE IF NOT EXISTS repos (
  id INTEGER PRIMARY KEY,
  host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  kind TEXT, url TEXT, suite TEXT, components TEXT, name TEXT, file TEXT,
  enabled INTEGER DEFAULT 1, status TEXT, error TEXT, pkg_count INTEGER DEFAULT 0, fetched_at TEXT
);
CREATE TABLE IF NOT EXISTS vulns (
  id TEXT PRIMARY KEY,               -- OSV id (DSA-..., USN-..., CVE-..., ALSA-...)
  cve TEXT,                          -- primary CVE alias
  aliases TEXT, summary TEXT, details TEXT,
  cvss_score REAL, severity TEXT,    -- CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN
  cvss_vector TEXT, kev INTEGER DEFAULT 0,
  published TEXT, modified TEXT, refs TEXT, raw TEXT, fetched_at TEXT
);
CREATE TABLE IF NOT EXISTS osv_bulk (       -- offline OSV mirror (osv_mode: bulk)
  ecosystem TEXT NOT NULL, package TEXT NOT NULL, id TEXT NOT NULL, raw TEXT NOT NULL,
  PRIMARY KEY (ecosystem, package, id)
);
CREATE INDEX IF NOT EXISTS ix_osv_bulk_id ON osv_bulk(id);
CREATE TABLE IF NOT EXISTS osv_bulk_meta (ecosystem TEXT PRIMARY KEY, fetched_at TEXT, etag TEXT, count INTEGER);
CREATE TABLE IF NOT EXISTS nvd_cache (cve TEXT PRIMARY KEY, score REAL, severity TEXT, vector TEXT, description TEXT, fetched_at TEXT);
CREATE TABLE IF NOT EXISTS kev (cve TEXT PRIMARY KEY, name TEXT, date_added TEXT, due_date TEXT, ransomware TEXT);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY,
  host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  package TEXT NOT NULL, version TEXT NOT NULL, source_name TEXT,
  binaries TEXT,                     -- installed binary packages built from this source
  osv_ids TEXT,                      -- distro advisories (DSA/USN/ALSA...) reporting it
  summary TEXT,
  vuln_id TEXT NOT NULL, cve TEXT,
  fixed_version TEXT, repo_version TEXT, fix_in_repo INTEGER DEFAULT 0,
  severity TEXT, cvss_score REAL, kev INTEGER DEFAULT 0,
  status TEXT DEFAULT 'open',        -- open | resolved | ignored
  first_seen TEXT, last_seen TEXT, resolved_at TEXT,
  UNIQUE(host_id, package, vuln_id)
);
CREATE INDEX IF NOT EXISTS ix_find_status ON findings(status);
CREATE TABLE IF NOT EXISTS channels (
  id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL,
  url TEXT NOT NULL,                 -- Apprise URL, e.g. ntfy://ntfy.sh/mytopic
  enabled INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS subscriptions (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL,
  channel_id INTEGER NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  host_pattern TEXT DEFAULT '*',     -- glob(s), comma separated; matches host name or group:<g>
  package_pattern TEXT DEFAULT '*',  -- glob(s), comma separated
  min_severity TEXT DEFAULT 'LOW',
  only_kev INTEGER DEFAULT 0, only_fixable INTEGER DEFAULT 0,
  enabled INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS notifications (
  finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  channel_id INTEGER NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  sent_at TEXT, ok INTEGER, error TEXT,
  PRIMARY KEY (finding_id, channel_id)
);
CREATE TABLE IF NOT EXISTS saved_filters (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, page TEXT NOT NULL, query TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, at TEXT, kind TEXT, message TEXT
);
"""

_lock = threading.RLock()
_conn: sqlite3.Connection | None = None
_conn_path: str | None = None


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def connect() -> sqlite3.Connection:
    global _conn, _conn_path
    with _lock:
        if _conn is None or _conn_path != settings.database:
            if settings.database != ":memory:":
                Path(settings.database).parent.mkdir(parents=True, exist_ok=True)
            _conn = sqlite3.connect(settings.database, check_same_thread=False, isolation_level=None)
            _conn.row_factory = sqlite3.Row
            _conn.execute("PRAGMA foreign_keys=ON")
            _conn.execute("PRAGMA journal_mode=WAL")
            _conn.executescript(SCHEMA)
            _conn_path = settings.database
        return _conn


def q(sql: str, params=()) -> list[sqlite3.Row]:
    with _lock:
        return connect().execute(sql, params).fetchall()


def q1(sql: str, params=()):
    rows = q(sql, params)
    return rows[0] if rows else None


def x(sql: str, params=()) -> int:
    with _lock:
        cur = connect().execute(sql, params)
        return cur.lastrowid


def xmany(sql: str, seq):
    with _lock:
        connect().executemany(sql, seq)


@contextmanager
def tx():
    with _lock:
        c = connect()
        c.execute("BEGIN")
        try:
            yield c
            c.execute("COMMIT")
        except BaseException:
            c.execute("ROLLBACK")
            raise


def event(kind: str, message: str):
    x("INSERT INTO events(at, kind, message) VALUES (?,?,?)", (now(), kind, message))
    x("DELETE FROM events WHERE id < (SELECT MAX(id) - 1000 FROM events)")


def reset_for_tests():
    global _conn, _conn_path
    with _lock:
        if _conn is not None:
            _conn.close()
        _conn, _conn_path = None, None
