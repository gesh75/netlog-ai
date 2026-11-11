"""Backup/restore: roundtrip, rotation, and the safety rules in backup.py."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from ai_log_analyzer.backup import (
    backup_database,
    list_backups,
    restore_database,
)
from ai_log_analyzer.state_store import StateDB

pytestmark = pytest.mark.unit


def _seed(db_path: Path) -> None:
    db = StateDB(db_path)
    db.spool_append("syslog", [(1.0, "1.1.1.1", "line one"), (2.0, "1.1.1.1", "line two")], cap=100)
    db.incidents_append([{"description": "BGP flap", "severity": "high", "category": "bgp",
                          "devices": ["r1"], "count": 3, "sample_messages": ["m"],
                          "generated_at": "2026-11-11"}], cap=100)
    db.kv_set("llm", "provider", "ollama")


def test_backup_restore_roundtrip_keeps_data(tmp_path):
    src = tmp_path / "state.db"
    _seed(src)
    dest = backup_database(src, tmp_path / "backups", keep=7)
    assert dest.is_file() and dest.name.startswith("state-") and dest.suffix == ".db"
    assert sqlite3.connect(str(dest)).execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    # Plan's test: backup → delete the database → restore → the data is there.
    src.unlink()
    for suffix in ("-wal", "-shm"):
        Path(str(src) + suffix).unlink(missing_ok=True)
    restored = restore_database(dest, src)
    assert restored == src
    db = StateDB(src)
    assert [line for _id, _sender, line in db.spool_tail("syslog", 10)] == ["line one", "line two"]
    assert db.incidents_all(10)[0]["description"] == "BGP flap"
    assert db.kv_get_all("llm")["provider"] == "ollama"


def test_backup_of_missing_database_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        backup_database(tmp_path / "nope.db", tmp_path / "backups")


def test_rotation_keeps_newest_n(tmp_path):
    src = tmp_path / "state.db"
    _seed(src)
    made = [backup_database(src, tmp_path / "backups", keep=3, now=1_700_000_000 + i)
            for i in range(5)]
    kept = list_backups(tmp_path / "backups", "state")
    assert [p.name for p in kept] == [p.name for p in made[-3:]][::-1]
    assert len(kept) == 3


def test_restore_refuses_overwrite_without_force(tmp_path):
    src = tmp_path / "state.db"
    _seed(src)
    dest = backup_database(src, tmp_path / "backups")
    with pytest.raises(FileExistsError):
        restore_database(dest, src, force=False)
    # The live database is untouched.
    assert StateDB(src).incidents_all(10)[0]["description"] == "BGP flap"


def test_restore_with_force_keeps_safety_copy(tmp_path):
    src = tmp_path / "state.db"
    _seed(src)
    dest = backup_database(src, tmp_path / "backups")
    db = StateDB(src)
    db.incidents_append([{"description": "newer incident", "severity": "low", "category": "x",
                          "devices": [], "count": 1, "sample_messages": [],
                          "generated_at": "2026-11-11"}], cap=100)
    restore_database(dest, src, force=True)
    safety = sorted(tmp_path.glob("state.db.pre-restore-*"))
    assert len(safety) == 1
    assert [r["description"] for r in StateDB(safety[0]).incidents_all(10)] == [
        "BGP flap", "newer incident"]
    assert StateDB(src).incidents_all(10)[0]["description"] == "BGP flap"


def test_restore_of_corrupt_backup_raises_and_leaves_target_alone(tmp_path):
    src = tmp_path / "state.db"
    _seed(src)
    corrupt = tmp_path / "bad.db"
    corrupt.write_bytes(b"this is not a sqlite database at all")
    with pytest.raises(ValueError):
        restore_database(corrupt, tmp_path / "other.db")
    assert not (tmp_path / "other.db").exists()


def test_restore_of_missing_backup_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        restore_database(tmp_path / "nope.db", tmp_path / "state.db")


# ── CLI ───────────────────────────────────────────────────────────────────

def test_cli_backup_and_restore_roundtrip(tmp_path, monkeypatch, capsys):
    from argparse import Namespace

    from ai_log_analyzer.cli import cmd_backup, cmd_restore

    src = tmp_path / "state.db"
    _seed(src)
    monkeypatch.setenv("AI_LOG_ANALYZER_STATE_DB", str(src))
    assert cmd_backup(Namespace(db=None, dest=str(tmp_path / "backups"), keep=7)) == 0
    out = capsys.readouterr().out
    assert "backup written:" in out
    backup_file = out.strip().removeprefix("backup written: ").strip()
    src.unlink()
    assert cmd_restore(Namespace(backup=backup_file, db=None, force=False)) == 0
    assert "restored:" in capsys.readouterr().out
    assert StateDB(src).incidents_all(10)[0]["description"] == "BGP flap"


def test_cli_backup_without_db_exits_2(monkeypatch, capsys):
    from argparse import Namespace

    from ai_log_analyzer.cli import cmd_backup

    monkeypatch.delenv("AI_LOG_ANALYZER_STATE_DB", raising=False)
    assert cmd_backup(Namespace(db=None, dest=None, keep=7)) == 2
    assert "AI_LOG_ANALYZER_STATE_DB" in capsys.readouterr().err
