"""Backup and restore for the shared SQLite state database.

A backup is a consistent snapshot taken with the SQLite online backup API
(``sqlite3.Connection.backup``), so it can run while workers are alive —
no stop-the-world copy of a live WAL file. The destination is verified with
``PRAGMA integrity_check`` before it is reported as a backup, and old
copies are rotated so the backup directory stays bounded.

Restore replaces the state database file. The web workers and the triage
worker must be stopped first: restoring under a live writer would let the
old process keep writing to the replaced file's inode. Restore therefore
refuses to overwrite an existing database unless ``--force`` is given, and
even then it keeps a ``.pre-restore-<timestamp>`` safety copy of the
database it replaces.
"""
from __future__ import annotations

import logging
import os
import shutil
import sqlite3
import time
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULT_KEEP = 7

BACKUP_DIR_ENV = "AI_LOG_ANALYZER_BACKUP_DIR"


def default_backup_dir(db_path: str | Path) -> Path:
    """Backup directory: ``AI_LOG_ANALYZER_BACKUP_DIR`` or ``<db dir>/backups``."""
    override = os.environ.get(BACKUP_DIR_ENV, "").strip()
    if override:
        return Path(override).expanduser()
    return Path(db_path).expanduser().parent / "backups"


def _integrity_ok(path: str | Path) -> bool:
    conn = sqlite3.connect(f"file:{Path(path)}?mode=ro", uri=True)
    try:
        row = conn.execute("PRAGMA integrity_check").fetchone()
        return row is not None and str(row[0]).lower() == "ok"
    except sqlite3.Error:
        return False
    finally:
        conn.close()


def _backup_name(db_path: str | Path, now: float | None = None) -> str:
    stem = Path(db_path).expanduser().stem
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(now if now is not None else time.time()))
    return f"{stem}-{stamp}.db"


def list_backups(dest_dir: str | Path, stem: str) -> list[Path]:
    """Backup files for ``stem``, newest first."""
    directory = Path(dest_dir)
    if not directory.is_dir():
        return []
    return sorted(directory.glob(f"{stem}-*.db"), key=lambda p: p.name, reverse=True)


def backup_database(db_path: str | Path, dest_dir: str | Path | None = None,
                    keep: int = DEFAULT_KEEP, now: float | None = None) -> Path:
    """Snapshot ``db_path`` into ``dest_dir``; rotate to the newest ``keep`` copies.

    Returns the backup file. Raises ``FileNotFoundError`` when the source
    database does not exist and ``ValueError`` when the snapshot fails its
    integrity check.
    """
    source = Path(db_path).expanduser()
    if not source.is_file():
        raise FileNotFoundError(f"state database not found: {source}")
    if keep < 1:
        raise ValueError(f"keep must be >= 1, got {keep}")
    directory = Path(dest_dir).expanduser() if dest_dir else default_backup_dir(source)
    directory.mkdir(parents=True, exist_ok=True)
    dest = directory / _backup_name(source, now)
    src_conn = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    try:
        dst_conn = sqlite3.connect(str(dest))
        try:
            src_conn.backup(dst_conn)
        finally:
            dst_conn.close()
    finally:
        src_conn.close()
    # A backup is a single self-contained file: drop WAL mode (inherited
    # from the source header) so no -wal/-shm sidecars linger beside it.
    plain = sqlite3.connect(str(dest))
    try:
        plain.execute("PRAGMA journal_mode=DELETE").fetchall()
    finally:
        plain.close()
    for suffix in ("-wal", "-shm"):
        Path(str(dest) + suffix).unlink(missing_ok=True)
    if not _integrity_ok(dest):
        dest.unlink(missing_ok=True)
        raise ValueError(f"backup failed integrity check: {dest}")
    for stale in list_backups(directory, source.stem)[keep:]:
        stale.unlink(missing_ok=True)
    return dest


def _checkpoint(path: str | Path) -> None:
    """Fold the WAL into ``path`` so the file is self-contained (best effort)."""
    try:
        conn = sqlite3.connect(str(path))
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        log.warning("could not checkpoint %s before restore; safety copy may lag", path)


def restore_database(backup_path: str | Path, db_path: str | Path,
                     force: bool = False) -> Path:
    """Replace ``db_path`` with the verified snapshot ``backup_path``.

    Raises ``FileNotFoundError`` when the backup is missing, ``ValueError``
    when it fails its integrity check, and ``FileExistsError`` when the
    target database already exists and ``force`` is False. With ``force`` the
    replaced database is first checkpointed (so the safety copy holds every
    committed row) and kept as a ``.pre-restore-<timestamp>`` safety copy
    next to the target.
    Returns the restored database path.
    """
    backup = Path(backup_path).expanduser()
    if not backup.is_file():
        raise FileNotFoundError(f"backup not found: {backup}")
    if not _integrity_ok(backup):
        raise ValueError(f"backup failed integrity check: {backup}")
    target = Path(db_path).expanduser()
    if target.exists() and not force:
        raise FileExistsError(
            f"state database already exists: {target} "
            "(stop the workers and pass --force to replace it)")
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        _checkpoint(target)
        stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime())
        target.rename(Path(f"{target}.pre-restore-{stamp}"))
        for suffix in ("-shm",):
            Path(str(target) + suffix).unlink(missing_ok=True)
    shutil.copyfile(backup, target)
    for suffix in ("-wal", "-shm"):
        Path(str(target) + suffix).unlink(missing_ok=True)
    if not _integrity_ok(target):
        raise ValueError(f"restored database failed integrity check: {target}")
    return target
