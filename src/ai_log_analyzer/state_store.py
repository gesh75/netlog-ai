"""Process-safe shared state on SQLite in WAL mode.

One database file backs everything multiple Gunicorn workers must agree on
and that must survive a restart:

* ``syslog_spool``: durable syslog ingest. One worker owns the listener
  socket; every worker reads the same spool.
* ``incidents``: the incident-memory journal (replaces unlocked JSONL rewrites).
* ``kv``: runtime toggles (LLM provider / enabled / cloud-fallback policy).

WAL lets readers proceed while one writer commits. Writes use
``BEGIN IMMEDIATE`` with a busy timeout so concurrent workers serialize
instead of failing. Connections are per thread and re-opened after
``fork()`` (Gunicorn pre-fork), because SQLite handles must not cross a fork.

Enable with ``AI_LOG_ANALYZER_STATE_DB=/var/lib/netlog-ai/state.db``.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
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
"""

_BUSY_TIMEOUT_MS = 10_000


class StateDB:
    """Thin, thread- and fork-safe wrapper around one SQLite WAL database."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._prune_counter: dict[str, int] = {}
        conn = self.conn()
        conn.executescript(_SCHEMA)

    # ── connections ─────────────────────────────────────────────────────────
    def conn(self) -> sqlite3.Connection:
        pid = os.getpid()
        conn = getattr(self._local, "conn", None)
        if conn is None or getattr(self._local, "pid", None) != pid:
            conn = sqlite3.connect(str(self.path), timeout=_BUSY_TIMEOUT_MS / 1000,
                                   isolation_level=None, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
            self._local.conn = conn
            self._local.pid = pid
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
            "SELECT description, severity, category, devices, count, sample_messages, generated_at "
            "FROM incidents ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for desc, sev, cat, devices, count, samples, gen in reversed(rows):
            out.append({"description": desc, "severity": sev, "category": cat,
                        "devices": json.loads(devices or "[]"), "count": count,
                        "sample_messages": json.loads(samples or "[]"), "generated_at": gen})
        return out

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

    def spool_max_id(self, source: str) -> int:
        row = self.conn().execute("SELECT MAX(id) FROM syslog_spool WHERE source=?", (source,)).fetchone()
        return int(row[0] or 0)


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
