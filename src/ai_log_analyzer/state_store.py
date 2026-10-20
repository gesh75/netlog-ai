"""Process-safe shared state on SQLite in WAL mode.

One database file backs everything multiple Gunicorn workers must agree on
and that must survive a restart:

* ``syslog_spool``: durable syslog ingest. One worker owns the listener
  socket; every worker reads the same spool.
* ``incidents``: the incident-memory journal (replaces unlocked JSONL rewrites).
* ``kv``: runtime toggles (LLM provider / enabled / cloud-fallback policy).
* ``audit_log``: append-only, hash-chained record of privileged actions
  (UPDATE and DELETE are rejected by triggers).
* ``triage_tickets``: per-incident ticket state and cooldowns for the
  streaming triage worker.

WAL lets readers proceed while one writer commits. Writes use
``BEGIN IMMEDIATE`` with a busy timeout so concurrent workers serialize
instead of failing. Connections are per thread and re-opened after
``fork()`` (Gunicorn pre-fork), because SQLite handles must not cross a fork.

Every connection is also closed just before ``fork()``. A child that
inherits an open handle (for example one that is unreachable but not yet
garbage-collected) eventually closes it, and closing any descriptor of a
file drops all of that process's POSIX locks on it, including the locks
held by the child's own live connection. Sibling processes then commit
over each other's WAL frames and committed rows are silently lost.
Closing first leaves nothing to inherit; each thread reopens lazily on its
next call.

Enable with ``AI_LOG_ANALYZER_STATE_DB=/var/lib/netlog-ai/state.db``.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
import weakref
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS kv (
    namespace  TEXT NOT NULL,
    key        TEXT NOT NULL,
    value      TEXT NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY (namespace, key)
);
CREATE TABLE IF NOT EXISTS incidents (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    description     TEXT NOT NULL,
    severity        TEXT,
    category        TEXT,
    devices         TEXT,
    count           INTEGER,
    sample_messages TEXT,
    generated_at    TEXT
);
CREATE INDEX IF NOT EXISTS incidents_description ON incidents (description);
CREATE TABLE IF NOT EXISTS syslog_spool (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source      TEXT NOT NULL,
    received_at REAL NOT NULL,
    sender      TEXT,
    line        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS syslog_spool_source_id ON syslog_spool (source, id);
CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL NOT NULL,
    actor      TEXT NOT NULL,
    role       TEXT NOT NULL,
    action     TEXT NOT NULL,
    target     TEXT,
    outcome    TEXT,
    remote     TEXT,
    detail     TEXT,
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TABLE IF NOT EXISTS triage_tickets (
    fingerprint   TEXT PRIMARY KEY,
    first_seen    REAL NOT NULL,
    last_seen     REAL NOT NULL,
    last_sent     REAL NOT NULL,
    severity      TEXT,
    event_count   INTEGER,
    last_event_at REAL,
    sends         INTEGER NOT NULL DEFAULT 0,
    held          INTEGER NOT NULL DEFAULT 0,
    state         TEXT,
    title         TEXT,
    refs          TEXT
);
"""

# Columns added after the first release; applied with ALTER TABLE when missing.
_MIGRATIONS = {
    "incidents": (("resolution", "TEXT"), ("resolved_at", "TEXT"), ("resolved_by", "TEXT")),
}

_BUSY_TIMEOUT_MS = 10_000


class _TrackedConnection(sqlite3.Connection):
    """A plain sqlite3 connection that supports weak references (fork guard)."""


# Every open connection, including ones whose StateDB is already gone but that
# the garbage collector has not finalized yet; closed before fork().
_LIVE_CONNS: weakref.WeakSet[_TrackedConnection] = weakref.WeakSet()
_fork_generation = 0


class StateDB:
    """Thin, thread- and fork-safe wrapper around one SQLite WAL database."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._prune_counter: dict[str, int] = {}
        conn = self.conn()
        conn.executescript(_SCHEMA)
        for table, columns in _MIGRATIONS.items():
            have = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
            for name, decl in columns:
                if name not in have:
                    try:
                        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
                    except sqlite3.OperationalError:  # another process added it first
                        pass

    # ── connections ─────────────────────────────────────────────────────────
    def conn(self) -> sqlite3.Connection:
        pid = os.getpid()
        conn = getattr(self._local, "conn", None)
        if (conn is None or getattr(self._local, "pid", None) != pid
                or getattr(self._local, "generation", None) != _fork_generation):
            conn = sqlite3.connect(str(self.path), timeout=_BUSY_TIMEOUT_MS / 1000,
                                   isolation_level=None, check_same_thread=False,
                                   factory=_TrackedConnection)
            _LIVE_CONNS.add(conn)
            conn.execute("PRAGMA journal_mode=WAL").fetchall()
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
            self._local.conn = conn
            self._local.pid = pid
            self._local.generation = _fork_generation
        return conn

    @contextmanager
    def write(self) -> Iterator[sqlite3.Connection]:
        conn = self.conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        conn.execute("COMMIT")

    def journal_mode(self) -> str:
        return str(self.conn().execute("PRAGMA journal_mode").fetchone()[0]).lower()

    # ── kv ──────────────────────────────────────────────────────────────────
    def kv_set(self, namespace: str, key: str, value: Any) -> None:
        with self.write() as c:
            c.execute(
                "INSERT INTO kv(namespace, key, value, updated_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(namespace, key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                (namespace, key, json.dumps(value), time.time()),
            )

    def kv_get_all(self, namespace: str) -> dict[str, Any]:
        rows = self.conn().execute("SELECT key, value FROM kv WHERE namespace=?", (namespace,)).fetchall()
        out: dict[str, Any] = {}
        for key, value in rows:
            try:
                out[key] = json.loads(value)
            except (TypeError, ValueError):
                continue
        return out

    # ── incidents ───────────────────────────────────────────────────────────
    def incidents_append(self, records: Iterable[dict[str, Any]], cap: int) -> int:
        rows = [(
            str(r.get("description", "")), str(r.get("severity", "")), str(r.get("category", "")),
            json.dumps(list(r.get("devices") or [])), int(r.get("count") or 0),
            json.dumps(list(r.get("sample_messages") or [])), str(r.get("generated_at", "")),
        ) for r in records if r.get("description")]
        if not rows:
            return 0
        with self.write() as c:
            c.executemany(
                "INSERT INTO incidents(description, severity, category, devices, count, sample_messages, "
                "generated_at) VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
            c.execute("DELETE FROM incidents WHERE id <= (SELECT id FROM incidents ORDER BY id DESC "
                      "LIMIT 1 OFFSET ?)", (cap,))
        return len(rows)

    def incidents_all(self, limit: int) -> list[dict[str, Any]]:
        rows = self.conn().execute(
            "SELECT id, description, severity, category, devices, count, sample_messages, generated_at, "
            "resolution, resolved_at, resolved_by FROM incidents ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for row_id, desc, sev, cat, devices, count, samples, gen, res, res_at, res_by in reversed(rows):
            rec = {"id": row_id, "description": desc, "severity": sev, "category": cat,
                   "devices": json.loads(devices or "[]"), "count": count,
                   "sample_messages": json.loads(samples or "[]"), "generated_at": gen}
            if res:
                rec.update(resolution=res, resolved_at=res_at or "", resolved_by=res_by or "")
            out.append(rec)
        return out

    def incidents_resolve(self, row_id: int, resolution: str, resolved_at: str, resolved_by: str) -> bool:
        with self.write() as c:
            cur = c.execute("UPDATE incidents SET resolution=?, resolved_at=?, resolved_by=? WHERE id=?",
                            (resolution, resolved_at, resolved_by, int(row_id)))
        return cur.rowcount > 0

    def incidents_count(self) -> int:
        return int(self.conn().execute("SELECT COUNT(*) FROM incidents").fetchone()[0])

    # ── syslog spool ────────────────────────────────────────────────────────
    def spool_append(self, source: str, rows: list[tuple[float, str, str]], cap: int) -> int:
        """Append (received_at, sender, line) rows; prune to ``cap`` rows per source."""
        if not rows:
            return 0
        with self.write() as c:
            c.executemany("INSERT INTO syslog_spool(source, received_at, sender, line) VALUES (?, ?, ?, ?)",
                          [(source, ts, sender, line) for ts, sender, line in rows])
            # Prune at most every ~1000 rows so storms do not pay a DELETE per batch.
            pending = self._prune_counter.get(source, 0) + len(rows)
            if pending >= 1000 or pending >= cap:
                c.execute(
                    "DELETE FROM syslog_spool WHERE source=? AND id <= (SELECT id FROM syslog_spool "
                    "WHERE source=? ORDER BY id DESC LIMIT 1 OFFSET ?)", (source, source, cap))
                pending = 0
            self._prune_counter[source] = pending
        return len(rows)

    def spool_tail(self, source: str, limit: int) -> list[tuple[int, str, str]]:
        rows = self.conn().execute(
            "SELECT id, sender, line FROM syslog_spool WHERE source=? ORDER BY id DESC LIMIT ?",
            (source, limit)).fetchall()
        return list(reversed(rows))

    def spool_after(self, source: str, after_id: int, limit: int) -> list[tuple[int, str, str]]:
        """Newest ``limit`` rows with id > after_id, oldest first."""
        rows = self.conn().execute(
            "SELECT id, sender, line FROM syslog_spool WHERE source=? AND id > ? ORDER BY id DESC LIMIT ?",
            (source, after_id, limit)).fetchall()
        return list(reversed(rows))

    def spool_read(self, source: str, after_id: int, limit: int) -> list[tuple[int, float, str, str]]:
        """Oldest ``limit`` rows with id > after_id as (id, received_at, sender, line).

        Unlike ``spool_after`` (live tail, newest wins) this never skips rows,
        so a consumer that falls behind catches up instead of losing events.
        """
        return self.conn().execute(
            "SELECT id, received_at, sender, line FROM syslog_spool WHERE source=? AND id > ? "
            "ORDER BY id LIMIT ?", (source, int(after_id), int(limit))).fetchall()

    def spool_sources(self) -> list[str]:
        return [r[0] for r in self.conn().execute("SELECT DISTINCT source FROM syslog_spool")]

    def spool_min_id(self, source: str) -> int:
        row = self.conn().execute("SELECT MIN(id) FROM syslog_spool WHERE source=?", (source,)).fetchone()
        return int(row[0] or 0)

    # ── leases (single active consumer across workers) ──────────────────────
    def lease_acquire(self, name: str, owner: str, ttl_s: float, now: float | None = None) -> bool:
        """Take or renew lease ``name`` for ``owner``; False while another owner holds it."""
        now = time.time() if now is None else now
        with self.write() as c:
            row = c.execute("SELECT value FROM kv WHERE namespace='lease' AND key=?", (name,)).fetchone()
            if row is not None:
                try:
                    held = json.loads(row[0])
                except (TypeError, ValueError):
                    held = {}
                if held.get("owner") != owner and float(held.get("expires", 0)) > now:
                    return False
            c.execute(
                "INSERT INTO kv(namespace, key, value, updated_at) VALUES ('lease', ?, ?, ?) "
                "ON CONFLICT(namespace, key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                (name, json.dumps({"owner": owner, "expires": now + ttl_s}), now))
        return True

    def lease_release(self, name: str, owner: str) -> None:
        with self.write() as c:
            row = c.execute("SELECT value FROM kv WHERE namespace='lease' AND key=?", (name,)).fetchone()
            if row is not None and json.loads(row[0]).get("owner") == owner:
                c.execute("DELETE FROM kv WHERE namespace='lease' AND key=?", (name,))

    def spool_max_id(self, source: str) -> int:
        row = self.conn().execute("SELECT MAX(id) FROM syslog_spool WHERE source=?", (source,)).fetchone()
        return int(row[0] or 0)


    # ── audit log (append-only, hash-chained) ───────────────────────────────
    _AUDIT_FIELDS = ("ts", "actor", "role", "action", "target", "outcome", "remote", "detail")

    @staticmethod
    def _audit_digest(prev_hash: str, row: dict[str, Any]) -> str:
        canon = json.dumps([prev_hash] + [row.get(k) for k in StateDB._AUDIT_FIELDS],
                           separators=(",", ":"), default=str)
        return hashlib.sha256(canon.encode("utf-8")).hexdigest()

    def audit_append(self, entry: dict[str, Any]) -> dict[str, Any]:
        row = {
            "ts": round(float(entry.get("ts") or time.time()), 6),
            "actor": str(entry.get("actor") or "unknown")[:200],
            "role": str(entry.get("role") or "")[:40],
            "action": str(entry.get("action") or "")[:200],
            "target": str(entry.get("target") or "")[:500],
            "outcome": str(entry.get("outcome") or "")[:40],
            "remote": str(entry.get("remote") or "")[:100],
            "detail": json.dumps(entry.get("detail") or {}, sort_keys=True, default=str)[:8000],
        }
        with self.write() as c:
            last = c.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            prev = last[0] if last else ""
            digest = self._audit_digest(prev, row)
            cur = c.execute(
                "INSERT INTO audit_log(ts, actor, role, action, target, outcome, remote, detail, prev_hash, hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (*[row[k] for k in self._AUDIT_FIELDS], prev, digest))
        return {"id": cur.lastrowid, **row, "hash": digest}

    def audit_query(self, *, limit: int = 100, actor: str = "", action: str = "",
                    since: float = 0.0) -> list[dict[str, Any]]:
        sql = ("SELECT id, ts, actor, role, action, target, outcome, remote, detail, hash "
               "FROM audit_log WHERE ts >= ?")
        args: list[Any] = [float(since)]
        if actor:
            sql += " AND actor = ?"
            args.append(actor)
        if action:
            sql += " AND action LIKE ?"
            args.append(action.replace("*", "%"))
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(int(limit))
        out = []
        for row in self.conn().execute(sql, args).fetchall():
            rec = dict(zip(("id", "ts", "actor", "role", "action", "target", "outcome", "remote",
                            "detail", "hash"), row))
            try:
                rec["detail"] = json.loads(rec["detail"] or "{}")
            except ValueError:
                pass
            out.append(rec)
        return out

    def audit_verify(self) -> dict[str, Any]:
        """Recompute the hash chain; reports the first row that does not match."""
        prev = ""
        checked = 0
        for row in self.conn().execute(
                "SELECT id, ts, actor, role, action, target, outcome, remote, detail, prev_hash, hash "
                "FROM audit_log ORDER BY id"):
            rec = dict(zip(("id",) + self._AUDIT_FIELDS + ("prev_hash", "hash"), row))
            if rec["prev_hash"] != prev or self._audit_digest(prev, rec) != rec["hash"]:
                return {"ok": False, "checked": checked, "broken_at": rec["id"]}
            prev = rec["hash"]
            checked += 1
        return {"ok": True, "checked": checked, "broken_at": None}

    # ── triage ticket state ─────────────────────────────────────────────────
    _TRIAGE_COLS = ("fingerprint", "first_seen", "last_seen", "last_sent", "severity", "event_count",
                    "last_event_at", "sends", "held", "state", "title", "refs")

    def triage_get(self, fingerprint: str) -> dict[str, Any] | None:
        row = self.conn().execute(
            f"SELECT {', '.join(self._TRIAGE_COLS)} FROM triage_tickets WHERE fingerprint=?",
            (fingerprint,)).fetchone()
        if row is None:
            return None
        rec = dict(zip(self._TRIAGE_COLS, row))
        rec["refs"] = json.loads(rec["refs"] or "[]")
        return rec

    def triage_put(self, rec: dict[str, Any]) -> None:
        values = {**rec, "refs": json.dumps(rec.get("refs") or [])}
        with self.write() as c:
            c.execute(
                f"INSERT INTO triage_tickets({', '.join(self._TRIAGE_COLS)}) VALUES "
                f"({', '.join('?' * len(self._TRIAGE_COLS))}) ON CONFLICT(fingerprint) DO UPDATE SET "
                + ", ".join(f"{k}=excluded.{k}" for k in self._TRIAGE_COLS[1:]),
                [values.get(k) for k in self._TRIAGE_COLS])

    def triage_all(self, limit: int = 200) -> list[dict[str, Any]]:
        rows = self.conn().execute(
            f"SELECT {', '.join(self._TRIAGE_COLS)} FROM triage_tickets ORDER BY last_seen DESC LIMIT ?",
            (int(limit),)).fetchall()
        out = []
        for row in rows:
            rec = dict(zip(self._TRIAGE_COLS, row))
            rec["refs"] = json.loads(rec["refs"] or "[]")
            out.append(rec)
        return out


def _close_before_fork() -> None:
    """Close every connection this process opened (see the module docstring)."""
    global _fork_generation
    _fork_generation += 1
    for c in list(_LIVE_CONNS):
        try:
            c.close()
        except Exception:  # pragma: no cover - already closed / unusable
            pass


if hasattr(os, "register_at_fork"):  # POSIX
    os.register_at_fork(before=_close_before_fork)

_INSTANCES: dict[str, StateDB] = {}
_INSTANCES_LOCK = threading.Lock()


def open_db(path: str | Path) -> StateDB:
    """Shared StateDB instance per resolved path (per process)."""
    key = str(Path(path).expanduser().resolve())
    with _INSTANCES_LOCK:
        db = _INSTANCES.get(key)
        if db is None:
            db = StateDB(key)
            _INSTANCES[key] = db
        return db


def get_state_db() -> StateDB | None:
    """The configured shared state DB (``AI_LOG_ANALYZER_STATE_DB``), or None."""
    path = os.environ.get("AI_LOG_ANALYZER_STATE_DB", "").strip()
    return open_db(path) if path else None
