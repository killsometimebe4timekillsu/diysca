"""Storage: PostgreSQL (recommended for servers) or SQLite (single-user/desktop, tests).

Set `database_url: postgresql://user:pass@host:5432/diysca` to use PostgreSQL.
Without it a SQLite file in the data dir is used. All SQL in diysca is written
once with `?` placeholders and portable `ON CONFLICT` upserts; this module
translates it for PostgreSQL.
"""
from __future__ import annotations

import re
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .config import settings

try:  # optional at import time so SQLite-only installs work without libpq
    import psycopg
    from psycopg.rows import dict_row
except ImportError:  # pragma: no cover
    psycopg = None

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
  last_scan TEXT, last_status TEXT, last_error TEXT,
  kind TEXT DEFAULT 'host',          -- host | container
  parent_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
  container_runtime TEXT, container_id TEXT, image TEXT
);
CREATE TABLE IF NOT EXISTS packages (
  id INTEGER PRIMARY KEY,
  host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  name TEXT NOT NULL, version TEXT NOT NULL, arch TEXT,
  source_name TEXT, source_version TEXT, type TEXT,
  repo_version TEXT,                 -- newest version offered by the host's repos
  ecosystem TEXT DEFAULT '',         -- '' = OS package, else PyPI, npm, Maven, ...
  location TEXT                      -- where a language package was found
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
  ecosystem TEXT NOT NULL DEFAULT '',  -- '' = OS package, else PyPI, npm, Maven, ...
  location TEXT,
  binaries TEXT,                     -- installed binary packages built from this source
  osv_ids TEXT,                      -- distro advisories (DSA/USN/ALSA...) reporting it
  summary TEXT,
  vuln_id TEXT NOT NULL, cve TEXT,
  fixed_version TEXT, repo_version TEXT, fix_in_repo INTEGER DEFAULT 0,
  severity TEXT, cvss_score REAL, kev INTEGER DEFAULT 0,
  status TEXT DEFAULT 'open',        -- open | resolved | ignored
  first_seen TEXT, last_seen TEXT, resolved_at TEXT,
  resolved_version TEXT,             -- installed version when the finding went away
  resolution TEXT,                   -- upgraded | removed | not-affected
  epss REAL,                         -- EPSS probability (0..1), when an epss source is configured
  mitigation_id BIGINT,              -- latest mitigation the finding was approved in
  UNIQUE(host_id, ecosystem, package, vuln_id)
);
CREATE INDEX IF NOT EXISTS ix_find_status ON findings(status);
CREATE INDEX IF NOT EXISTS ix_find_resolved ON findings(resolved_at);
CREATE TABLE IF NOT EXISTS mitigations (  -- approved findings handed to someone (agent, CI/CD, person) to fix
  id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, approved_by TEXT, note TEXT,
  status TEXT NOT NULL DEFAULT 'approved',  -- approved | claimed | running | done | failed | cancelled
  handoff TEXT,                      -- hand-off target name, NULL = pull (agents fetch it via API / MCP)
  handoff_result TEXT,               -- delivery result of the hand-off
  claimed_by TEXT, claimed_at TEXT, updated_at TEXT,
  playbook TEXT, summary TEXT, log TEXT, rescan INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS mitigation_findings (
  mitigation_id BIGINT NOT NULL REFERENCES mitigations(id) ON DELETE CASCADE,
  finding_id BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  PRIMARY KEY(mitigation_id, finding_id)
);
CREATE TABLE IF NOT EXISTS handoffs (     -- where approved mitigations are sent: webhook, github, gitlab
  name TEXT PRIMARY KEY, type TEXT NOT NULL, url TEXT NOT NULL, token TEXT, config TEXT,
  enabled INTEGER DEFAULT 1, auto INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS patch_runs (    -- annotations: playbooks generated, repos updated
  id INTEGER PRIMARY KEY, at TEXT NOT NULL, kind TEXT NOT NULL, summary TEXT
);
CREATE TABLE IF NOT EXISTS feed_sources (  -- extra vulnerability sources (config.yml or web UI)
  name TEXT PRIMARY KEY, type TEXT NOT NULL, config TEXT NOT NULL,
  origin TEXT DEFAULT 'ui',          -- config | ui
  enabled INTEGER DEFAULT 1,
  fetched_at TEXT, count INTEGER DEFAULT 0, status TEXT, error TEXT
);
CREATE TABLE IF NOT EXISTS advisories (    -- records from extra sources, stored in OSV format
  source TEXT NOT NULL, ecosystem TEXT NOT NULL, package TEXT NOT NULL, id TEXT NOT NULL, raw TEXT NOT NULL,
  PRIMARY KEY (source, ecosystem, package, id)
);
CREATE INDEX IF NOT EXISTS ix_adv_pkg ON advisories(package);
CREATE INDEX IF NOT EXISTS ix_adv_id ON advisories(id);
CREATE TABLE IF NOT EXISTS epss (cve TEXT PRIMARY KEY, score REAL, percentile REAL);
CREATE TABLE IF NOT EXISTS channels (
  id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL,
  url TEXT NOT NULL,                 -- Apprise URL, e.g. ntfy://ntfy.sh/mytopic
  enabled INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS subscriptions (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL,
  channel_id INTEGER NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  host_pattern TEXT DEFAULT '*',     -- glob(s), comma separated, matches host name or group:<g>
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

SCHEMA_VERSION = 4

# columns added after a release: (table, column, type). Applied on SQLite and PostgreSQL.
ADDED_COLUMNS = [
    ("findings", "resolved_version", "TEXT"),
    ("findings", "resolution", "TEXT"),
    ("findings", "epss", "REAL"),
    ("findings", "mitigation_id", "BIGINT"),  # latest mitigation the finding was approved in
]


def _cols(c: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in c.execute(f"PRAGMA table_info({table})")}


def _migrate(c: sqlite3.Connection):
    """Bring databases created by older versions up to date."""
    if not _cols(c, "hosts"):
        return  # fresh database
    if c.execute("PRAGMA user_version").fetchone()[0] >= SCHEMA_VERSION:
        return
    for col, typ in (("kind", "TEXT DEFAULT 'host'"), ("parent_id", "INTEGER REFERENCES hosts(id) ON DELETE CASCADE"),
                     ("container_runtime", "TEXT"), ("container_id", "TEXT"), ("image", "TEXT")):
        if col not in _cols(c, "hosts"):
            c.execute(f"ALTER TABLE hosts ADD COLUMN {col} {typ}")
    for col, typ in (("ecosystem", "TEXT DEFAULT ''"), ("location", "TEXT")):
        if col not in _cols(c, "packages"):
            c.execute(f"ALTER TABLE packages ADD COLUMN {col} {typ}")
    if _cols(c, "findings") and "ecosystem" not in _cols(c, "findings"):
        # the UNIQUE key changes, so the table is rebuilt
        c.execute("PRAGMA foreign_keys=OFF")
        c.execute("PRAGMA legacy_alter_table=ON")  # keep notifications' FK pointing at "findings"
        c.execute("ALTER TABLE findings RENAME TO findings_v1")
        c.execute("PRAGMA legacy_alter_table=OFF")
        start = SCHEMA.index("CREATE TABLE IF NOT EXISTS findings")
        c.execute(SCHEMA[start:SCHEMA.index(");", start) + 2])
        old = _cols(c, "findings_v1")
        cols = ",".join(x for x in _cols(c, "findings") if x in old)
        c.execute(f"INSERT INTO findings({cols}) SELECT {cols} FROM findings_v1")
        c.execute("DROP TABLE findings_v1")
        c.execute("PRAGMA foreign_keys=ON")
    for table, col, typ in ADDED_COLUMNS:
        if _cols(c, table) and col not in _cols(c, table):
            c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")


_lock = threading.RLock()
_conn = None
_conn_key: str | None = None


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def is_postgres() -> bool:
    return settings.database_url.startswith(("postgres://", "postgresql://"))


def pg_schema() -> str:
    s = SCHEMA.replace("INTEGER PRIMARY KEY,", "BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,")
    s = re.sub(r"\bREAL\b", "DOUBLE PRECISION", s)
    s = s.replace("host_id INTEGER NOT NULL", "host_id BIGINT NOT NULL").replace("parent_id INTEGER", "parent_id BIGINT")
    s = s.replace("finding_id INTEGER NOT NULL", "finding_id BIGINT NOT NULL").replace("channel_id INTEGER NOT NULL", "channel_id BIGINT NOT NULL")
    return s


_PH = re.compile(r"\?")


def to_pg(sql: str) -> str:
    sql = sql.replace("%", "%%")
    sql = _PH.sub("%s", sql)
    return re.sub(r"\bLIKE\b", "ILIKE", sql)


class _PgCursor:
    def __init__(self, cur):
        self._cur = cur

    def fetchall(self):
        return self._cur.fetchall() if self._cur.description else []

    def fetchone(self):
        return self._cur.fetchone() if self._cur.description else None

    def __iter__(self):
        return iter(self.fetchall())


class _PgConn:
    """Gives a psycopg connection the small sqlite3-like surface diysca uses."""

    def __init__(self, url: str):
        if psycopg is None:
            raise RuntimeError("PostgreSQL support needs the 'psycopg' package")
        self.raw = psycopg.connect(url, autocommit=True, row_factory=dict_row)

    def execute(self, sql: str, params=()):
        if sql.strip().upper() in ("BEGIN", "COMMIT", "ROLLBACK"):
            return _PgCursor(self.raw.execute(sql))
        return _PgCursor(self.raw.execute(to_pg(sql), tuple(params)))

    def executemany(self, sql: str, seq):
        with self.raw.cursor() as cur:
            cur.executemany(to_pg(sql), [tuple(r) for r in seq])

    def close(self):
        self.raw.close()


def _connect_sqlite():
    if settings.database != ":memory:":
        Path(settings.database).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(settings.database, check_same_thread=False, isolation_level=None)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA busy_timeout=10000")
    _migrate(c)
    c.executescript(SCHEMA)
    c.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
    return c


def _connect_pg():
    c = _PgConn(settings.database_url)
    c.raw.execute("SELECT pg_advisory_lock(4242)")  # one migrator at a time
    try:
        c.raw.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
        for table, col, typ in ADDED_COLUMNS:  # before the schema, whose indexes may need them
            exists = c.raw.execute("SELECT 1 FROM information_schema.tables WHERE table_name=%s", (table,)).fetchone()
            if exists:
                typ = "DOUBLE PRECISION" if typ == "REAL" else typ
                c.raw.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col} {typ}")
        for stmt in pg_schema().split(";"):
            if stmt.strip():
                c.raw.execute(stmt)
        row = c.raw.execute("SELECT MAX(version) v FROM schema_version").fetchone()
        if not row or row["v"] is None:
            c.raw.execute("INSERT INTO schema_version VALUES (%s)", (SCHEMA_VERSION,))
    finally:
        c.raw.execute("SELECT pg_advisory_unlock(4242)")
    return c


def connect():
    global _conn, _conn_key
    with _lock:
        key = settings.database_url or settings.database
        if _conn is None or _conn_key != key:
            _conn = _connect_pg() if is_postgres() else _connect_sqlite()
            _conn_key = key
        return _conn


def _reconnect_on_failure(fn):
    def wrapper(*a, **kw):
        global _conn
        try:
            return fn(*a, **kw)
        except Exception as e:  # a restarted PostgreSQL drops the connection: retry once
            if psycopg is not None and isinstance(e, psycopg.OperationalError) and is_postgres():
                with _lock:
                    try:
                        _conn.close()
                    except Exception:
                        pass
                    _conn = None
                return fn(*a, **kw)
            raise
    return wrapper


@_reconnect_on_failure
def q(sql: str, params=()) -> list:
    with _lock:
        return connect().execute(sql, params).fetchall()


def q1(sql: str, params=()):
    rows = q(sql, params)
    return rows[0] if rows else None


@_reconnect_on_failure
def x(sql: str, params=()) -> int | None:
    """Execute a write. For INSERTs, returns the new row id."""
    with _lock:
        c = connect()
        if not is_postgres():
            return c.execute(sql, params).lastrowid
        if sql.lstrip().upper().startswith("INSERT") and "RETURNING" not in sql.upper() and _has_id(sql):
            row = c.execute(sql.rstrip().rstrip(";") + " RETURNING id", params).fetchone()
            return row["id"] if row else None
        c.execute(sql, params)
        return None


_ID_TABLES = {"hosts", "packages", "repos", "findings", "channels", "subscriptions", "saved_filters", "events", "patch_runs", "mitigations"}


def _has_id(sql: str) -> bool:
    m = re.match(r"\s*INSERT\s+INTO\s+(\w+)", sql, re.I)
    return bool(m and m.group(1).lower() in _ID_TABLES)


@_reconnect_on_failure
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


def patch_run(kind: str, summary: str):
    """Remember a patch action (playbook generated, repo updated); shown as an annotation on the Patched view."""
    x("INSERT INTO patch_runs(at, kind, summary) VALUES (?,?,?)", (now(), kind, summary[:500]))


def reset_for_tests():
    global _conn, _conn_key
    with _lock:
        if _conn is not None:
            _conn.close()
        _conn, _conn_key = None, None


def drop_all_for_tests():
    """PostgreSQL test helper: start every test from an empty schema."""
    if is_postgres():
        c = psycopg.connect(settings.database_url, autocommit=True)
        c.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        c.close()
