"""State store reliability: spool pruning cost and loss accounting, lease clock
guard, SQLite sync mode and triage ticket retention."""
from __future__ import annotations

import sqlite3

import pytest

from ai_log_analyzer.state_store import LeaseLost, StateDB

pytestmark = pytest.mark.unit


@pytest.fixture
def db(tmp_path):
    return StateDB(tmp_path / "state.db")


def _rows(n: int, start: int = 0):
    return [(float(start + i), "1.1.1.1", f"line {start + i}") for i in range(n)]


def test_prune_keeps_exactly_cap_rows_per_source_with_interleaved_ids(db):
    for i in range(6):                      # global ids interleave across sources
        db.spool_append("a", _rows(5, i * 5), cap=12)
        db.spool_append("b", _rows(3, i * 3), cap=12)
    db.spool_append("a", _rows(12, 30), cap=12)   # pruning is lazy: a cap's worth of new rows triggers it
    db.spool_append("b", _rows(12, 18), cap=12)
    a = db.spool_tail("a", 100)
    assert len(a) == 12 and a[-1][2] == "line 41"
    assert [r[2] for r in db.spool_tail("b", 100)] == [f"line {i}" for i in range(18, 30)]


def test_prune_cost_does_not_grow_with_the_cap(tmp_path):
    """Regression: ``ORDER BY id DESC LIMIT 1 OFFSET cap`` walked ``cap`` rows on every prune."""
    db = StateDB(tmp_path / "big.db")
    db.spool_append("s", _rows(60_000), cap=10**9)
    steps = 0

    def tick() -> int:
        nonlocal steps
        steps += 1
        return 0

    conn = db.conn()
    conn.set_progress_handler(tick, 100)
    try:
        db.spool_append("s", _rows(1000), cap=60_000)    # triggers one prune
    finally:
        conn.set_progress_handler(None, 0)
    assert len(db.spool_tail("s", 10**6)) == 60_000
    assert steps * 100 < 150_000, f"prune walked the cap ({steps * 100} vm steps)"


def test_spool_stats_do_not_count_the_table(db, monkeypatch):
    db.spool_append("a", _rows(5), cap=100)
    db.spool_append("b", _rows(2), cap=100)
    seen: list[str] = []
    db.conn().set_trace_callback(seen.append)
    try:
        stats = db.spool_stats()
    finally:
        db.conn().set_trace_callback(None)
    assert [(s["source"], s["rows"]) for s in stats] == [("a", 5), ("b", 2)]
    assert not any("COUNT(*)" in s.upper() and "SYSLOG_SPOOL" in s.upper() for s in seen), seen


def test_legacy_spool_without_meta_is_backfilled(tmp_path):
    path = tmp_path / "old.db"
    db = StateDB(path)
    db.spool_append("a", _rows(7), cap=100)
    db.conn().execute("DELETE FROM spool_meta")          # a DB written before the stats table existed
    reopened = StateDB(path)
    assert [(s["source"], s["rows"]) for s in reopened.spool_stats()] == [("a", 7)]
    assert reopened.spool_sources() == ["a"]
    reopened.spool_append("a", _rows(10, 7), cap=10)
    assert len(reopened.spool_tail("a", 100)) == 10


def test_pruned_but_unread_rows_are_counted_when_a_consumer_is_registered(db):
    db.kv_set("triage", "cursor:a", 5)                   # triage has read ids 1..5
    db.spool_append("a", _rows(30), cap=10)              # keeps ids 21..30, deletes 1..20
    assert db.spool_gap("a")["lost_unread"] == 15        # ids 6..20 were never read
    assert db.spool_gap("a")["pruned"] == 20
    db.spool_append("b", _rows(30), cap=10)              # no consumer registered for b
    assert db.spool_gap("b")["lost_unread"] == 0


def test_lease_survives_neither_a_dead_owner_nor_a_backwards_clock_step(db):
    assert db.lease_acquire("l", "A", 60, now=1000.0)
    assert not db.lease_acquire("l", "B", 60, now=1010.0)
    assert db.lease_acquire("l", "B", 60, now=1061.0)                      # normal expiry
    assert db.lease_acquire("l", "A", 60, now=2000.0)
    # wall clock stepped back by an hour: expires_at is absurdly far ahead, so the lease is void
    assert db.lease_acquire("l", "B", 60, now=2000.0 - 3600)


def test_triage_put_is_fenced_by_the_lease(db):
    db.lease_acquire("triage-worker", "A", 60, now=1000.0)
    rec = {"fingerprint": "F", "first_seen": 1.0, "last_seen": 1.0, "last_sent": 1.0, "sends": 1, "held": 0,
           "state": "active"}
    db.triage_put(rec, fence=("triage-worker", "A"), now=1050.0)
    db.lease_acquire("triage-worker", "B", 60, now=1100.0)                 # A's lease lapsed, B took over
    with pytest.raises(LeaseLost):
        db.triage_put({**rec, "last_seen": 5.0}, fence=("triage-worker", "A"), now=1105.0)
    assert db.triage_get("F")["last_seen"] == 1.0


def test_sqlite_synchronous_mode_is_configurable(tmp_path, monkeypatch):
    assert StateDB(tmp_path / "a.db").conn().execute("PRAGMA synchronous").fetchone()[0] == 1   # NORMAL
    monkeypatch.setenv("AI_LOG_ANALYZER_SQLITE_SYNC", "full")
    assert StateDB(tmp_path / "b.db").conn().execute("PRAGMA synchronous").fetchone()[0] == 2
    monkeypatch.setenv("AI_LOG_ANALYZER_SQLITE_SYNC", "bogus; DROP TABLE kv")
    assert StateDB(tmp_path / "c.db").conn().execute("PRAGMA synchronous").fetchone()[0] == 1


def test_triage_retention_prunes_only_old_non_active_rows(db):
    def put(fp, state, last_seen):
        db.triage_put({"fingerprint": fp, "first_seen": last_seen, "last_seen": last_seen,
                       "last_sent": last_seen, "sends": 1, "held": 0, "state": state, "severity": "high"})
    now = 100 * 86400.0
    put("old-recovered", "recovered", now - 40 * 86400)
    put("old-active", "active", now - 40 * 86400)
    put("fresh-recovered", "recovered", now - 5 * 86400)
    assert db.triage_prune(30 * 86400, now=now) == 1
    assert {r["fingerprint"] for r in db.triage_all()} == {"old-active", "fresh-recovered"}
    plan = " ".join(str(r) for r in db.conn().execute(
        "EXPLAIN QUERY PLAN SELECT fingerprint FROM triage_tickets ORDER BY last_seen DESC LIMIT 5"))
    assert "triage_tickets_last_seen" in plan


def test_schema_upgrade_is_idempotent(tmp_path):
    StateDB(tmp_path / "s.db")
    StateDB(tmp_path / "s.db")
    with sqlite3.connect(tmp_path / "s.db") as c:
        assert c.execute("SELECT COUNT(*) FROM spool_meta").fetchone()[0] == 0
