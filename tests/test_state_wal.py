"""WAL discipline (P3 item 12): journal size limit and checkpointing."""
from __future__ import annotations

from pathlib import Path

import pytest

from ai_log_analyzer.state_store import StateDB, journal_size_limit

pytestmark = pytest.mark.unit


@pytest.fixture
def db(tmp_path):
    return StateDB(tmp_path / "state.db")


def _rows(n: int, start: int = 0):
    return [(float(start + i), "1.1.1.1", f"line {start + i}") for i in range(n)]


def test_journal_size_limit_default_is_64mib(monkeypatch):
    monkeypatch.delenv("AI_LOG_ANALYZER_SQLITE_JOURNAL_SIZE_LIMIT", raising=False)
    assert journal_size_limit() == 64 * 1024 * 1024


def test_journal_size_limit_env_override(monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_SQLITE_JOURNAL_SIZE_LIMIT", "1048576")
    assert journal_size_limit() == 1_048_576


def test_journal_size_limit_bad_value_falls_back(monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_SQLITE_JOURNAL_SIZE_LIMIT", "not-a-number")
    assert journal_size_limit() == 64 * 1024 * 1024


def test_journal_size_limit_applied_to_connections(db):
    assert db.conn().execute("PRAGMA journal_size_limit").fetchone()[0] == 64 * 1024 * 1024


def test_checkpoint_returns_page_counts(db):
    db.spool_append("s", _rows(100), cap=10**9)
    result = db.checkpoint("PASSIVE")
    assert set(result) == {"busy", "log", "checkpointed"}
    assert result["busy"] == 0
    assert result["checkpointed"] >= 0


def test_checkpoint_truncate_empties_wal(db, tmp_path):
    db.spool_append("s", _rows(5_000), cap=10**9)
    wal = Path(str(db.path) + "-wal")
    assert wal.exists() and wal.stat().st_size > 0
    db.checkpoint("TRUNCATE")
    assert wal.stat().st_size == 0


def test_checkpoint_rejects_unknown_mode(db):
    with pytest.raises(ValueError):
        db.checkpoint("BOGUS")


def test_storm_appends_stay_bounded_and_consistent(tmp_path):
    """20k rows in batches: the spool keeps every row and the WAL stays small
    after a checkpoint, instead of growing with the storm."""
    db = StateDB(tmp_path / "storm.db")
    for i in range(20):
        db.spool_append("s", _rows(1_000, i * 1_000), cap=10**9)
    assert len(db.spool_tail("s", 10**9)) == 20_000
    db.checkpoint("TRUNCATE")
    wal = Path(str(db.path) + "-wal")
    assert wal.stat().st_size == 0
    assert db.spool_stats()[0]["rows"] == 20_000
