"""Incident memory — "this exact issue happened before, here's when and where."

Every analysis is ephemeral by default: close the tab and the incident is
gone. With `AI_LOG_ANALYZER_INCIDENT_STORE` set to a path, each analyze run
appends its action items to a local JSONL journal, and future runs annotate
every action item with its recurrence history:

    "recurrence": {"count": 3, "last_seen": "...", "devices": ["leaf-11"]}

That one line changes triage: a first-ever BGP flap and the fourth BGP flap
this month on the same leaf are different incidents, and now they read
differently. A token-overlap search (`find_similar`) additionally powers the
`/api/incidents/similar` endpoint for free-text lookups ("have we seen fan
failures on spine-02?"). Zero dependencies, bounded file size, and nothing
ever leaves the host.

Backends:

* JSONL (path not ending in .db/.sqlite): appends and cap rewrites hold an
  exclusive ``fcntl`` lock on ``<path>.lock`` and re-read the file before a
  rewrite, so concurrent workers neither interleave lines nor drop each
  other's records.
* SQLite WAL (path ending in .db/.sqlite/.sqlite3, or the shared
  ``AI_LOG_ANALYZER_STATE_DB``): process-safe, the recommended choice for
  multi-worker Gunicorn deployments.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:  # POSIX advisory locking; Windows falls back to unlocked writes.
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

_MAX_RECORDS = 5000          # journal is rewritten (oldest dropped) past this
_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._/-]{2,}")


def _tokens(text: str) -> set[str]:
    return set(_TOKEN_RE.findall(text.lower()))


def _parse_stamp(stamp: str) -> datetime | None:
    if not stamp:
        return None
    try:
        parsed = datetime.fromisoformat(stamp)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def incident_id(record: dict) -> str:
    """Stable citation id: ``INC-000042`` for SQLite rows, a content hash for JSONL."""
    row_id = record.get("id")
    if isinstance(row_id, int):
        return f"INC-{row_id:06d}"
    raw = "|".join([str(record.get("description", "")), str(record.get("generated_at", "")),
                    ",".join(record.get("devices") or [])])
    return "INC-" + hashlib.sha1(raw.encode("utf-8")).hexdigest()[:10].upper()


class IncidentStore:
    """Append-only JSONL journal of past action items, with recurrence lookup."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()
        self._records: list[dict] = []
        self._load()

    def _load(self) -> None:
        self._records = self._read_file()
        if len(self._records) > _MAX_RECORDS:
            self._records = self._records[-_MAX_RECORDS:]

    def _read_file(self) -> list[dict]:
        records: list[dict] = []
        if not self.path.is_file():
            return records
        try:
            for line in self.path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue  # a torn line never poisons the journal
                if isinstance(rec, dict) and rec.get("description"):
                    records.append(rec)
        except OSError as exc:
            logger.warning("incident store unreadable (%s) — starting fresh", exc)
        return records

    @contextmanager
    def _locked(self) -> Iterator[None]:
        """Exclusive cross-process lock for appends and rewrites."""
        if fcntl is None:
            yield
            return
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        with lock_path.open("a") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def __len__(self) -> int:
        return len(self._records)

    # ── recall ────────────────────────────────────────────────────────────

    def recurrence(self, description: str) -> dict | None:
        """History of this exact issue (KB descriptions are stable strings)."""
        matches = [r for r in self._records if r.get("description") == description]
        if not matches:
            return None
        devices: set[str] = set()
        for r in matches:
            devices.update(r.get("devices") or [])
        return {
            "count": len(matches),
            "last_seen": max(r.get("generated_at", "") for r in matches),
            "devices": sorted(devices)[:10],
        }

    def repeats(self, *, now: datetime, days: int = 7) -> list[dict]:
        """Host + category pairs seen at least twice inside ``days``.

        ``now`` is the clock for the window so tests can pin it. Counts include
        the current run when it has already been recorded.
        """
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        cutoff = now - timedelta(days=days)
        counts: dict[tuple[str, str], int] = {}
        last: dict[tuple[str, str], str] = {}
        for record in self._records:
            seen = _parse_stamp(str(record.get("generated_at") or ""))
            if seen is None or seen < cutoff:
                continue
            category = str(record.get("category") or "")
            for host in record.get("devices") or []:
                key = (str(host), category)
                counts[key] = counts.get(key, 0) + 1
                last[key] = str(record.get("generated_at") or "")
        rows = [
            {"hostname": host, "category": category, "count": count, "last_seen": last[(host, category)]}
            for (host, category), count in counts.items()
            if count >= 2
        ]
        rows.sort(key=lambda row: (-row["count"], row["hostname"]))
        return rows[:8]

    def find_similar(self, query: str, top_n: int = 5) -> list[dict]:
        """Free-text token-overlap search across the journal (Jaccard)."""
        q = _tokens(query)
        if not q:
            return []
        scored: list[tuple[float, dict]] = []
        for r in self._records:
            blob = f"{r.get('description', '')} {' '.join(r.get('devices') or [])} " \
                   f"{' '.join(r.get('sample_messages') or [])}"
            t = _tokens(blob)
            if not t:
                continue
            overlap = len(q & t)
            if overlap == 0:
                continue
            scored.append((overlap / len(q | t), r))
        scored.sort(key=lambda x: -x[0])
        return [
            {"score": round(s, 3), **{k: r.get(k) for k in
             ("description", "severity", "category", "devices", "count", "generated_at")}}
            for s, r in scored[:top_n]
        ]

    def records(self) -> list[dict]:
        """Snapshot of the journal, oldest first, each with its ``incident_id``."""
        return [{**r, "incident_id": incident_id(r)} for r in self._records]

    def get(self, inc_id: str) -> dict | None:
        for r in self._records:
            if incident_id(r) == inc_id:
                return {**r, "incident_id": inc_id}
        return None

    def resolve(self, inc_id: str, resolution: str, resolved_by: str = "") -> dict | None:
        """Attach the operator's resolution note to a past incident.

        Resolved incidents are what the RAG index cites as precedent
        ("INC-000042: fixed by replacing the optic on et-0/0/3").
        """
        stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        fields = {"resolution": resolution.strip()[:2000], "resolved_at": stamp,
                  "resolved_by": resolved_by[:200]}
        hit = None
        try:
            with self._locked():
                on_disk = self._read_file()
                for r in on_disk:
                    if incident_id(r) == inc_id:
                        r.update(fields)
                        hit = r
                if hit is None:
                    return None
                tmp = self.path.with_suffix(self.path.suffix + f".{os.getpid()}.tmp")
                tmp.write_text("\n".join(json.dumps(r) for r in on_disk) + "\n", encoding="utf-8")
                tmp.replace(self.path)
            self._records = on_disk[-_MAX_RECORDS:]
        except OSError as exc:
            logger.warning("could not resolve incident in %s: %s", self.path, exc)
            return None
        return {**hit, "incident_id": inc_id}

    # ── record ────────────────────────────────────────────────────────────

    def record(self, action_items: list[dict], generated_at: str) -> int:
        """Append this run's action items; rewrites the journal when it
        outgrows the cap.

        JSONL failures are logged, never raised. SQLite insert errors
        propagate after lock retries (swallowing them dropped concurrent
        writes); reload-after-write errors are logged only. Analysis
        callers catch persist errors so a finished run is not failed by
        the journal.
        """
        new = []
        for a in action_items:
            new.append({
                "description": a.get("description", ""),
                "severity": a.get("severity", ""),
                "category": a.get("category", ""),
                "devices": (a.get("devices") or [])[:10],
                "count": a.get("count", 0),
                "sample_messages": (a.get("sample_messages") or [])[:2],
                "generated_at": generated_at,
            })
        if not new:
            return 0
        return self._persist(new)

    def _persist(self, new: list[dict]) -> int:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self._locked():
                # Re-read under the lock: other workers may have appended since
                # this instance loaded, and a rewrite must not drop them.
                on_disk = self._read_file()
                if len(on_disk) + len(new) > _MAX_RECORDS:
                    merged = (on_disk + new)[-_MAX_RECORDS:]
                    tmp = self.path.with_suffix(self.path.suffix + f".{os.getpid()}.tmp")
                    tmp.write_text("\n".join(json.dumps(r) for r in merged) + "\n", encoding="utf-8")
                    tmp.replace(self.path)
                else:
                    merged = on_disk + new
                    with self.path.open("a", encoding="utf-8") as fh:
                        fh.write("".join(json.dumps(r) + "\n" for r in new))
                        fh.flush()
                        os.fsync(fh.fileno())
            self._records = merged
        except OSError as exc:
            logger.warning("could not persist incident store to %s: %s", self.path, exc)
            self._records = (self._records + new)[-_MAX_RECORDS:]
        return len(new)


class SqliteIncidentStore(IncidentStore):
    """Incident memory on the shared SQLite WAL database (multi-worker safe)."""

    def __init__(self, db: Any) -> None:  # db: state_store.StateDB
        self.db = db
        self.path = db.path
        self._records = []
        self._load()

    def _load(self) -> None:
        self._records = self.db.incidents_all(_MAX_RECORDS)

    def __len__(self) -> int:
        return self.db.incidents_count()

    def _persist(self, new: list[dict]) -> int:
        """Write through to SQLite. Insert errors are not swallowed — that
        is how concurrent workers lost rows. ``_load`` is best-effort: the
        append already committed, so a failed SELECT must not look like a
        lost write.
        """
        self.db.incidents_append(new, cap=_MAX_RECORDS)
        try:
            self._load()  # pick up row ids (citation ids) and other workers' rows
        except Exception:
            logger.exception("could not reload incident store from %s after persist", self.path)
        return len(new)

    def resolve(self, inc_id: str, resolution: str, resolved_by: str = "") -> dict | None:
        if not inc_id.startswith("INC-") or not inc_id[4:].isdigit():
            return None
        stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        if not self.db.incidents_resolve(int(inc_id[4:]), resolution.strip()[:2000], stamp,
                                         resolved_by[:200]):
            return None
        self._load()
        return self.get(inc_id)


_SQLITE_SUFFIXES = (".db", ".sqlite", ".sqlite3")


def get_store() -> IncidentStore | None:
    """Opt-in via AI_LOG_ANALYZER_INCIDENT_STORE (JSONL or *.db) or the shared
    AI_LOG_ANALYZER_STATE_DB; None when neither is set."""
    from ai_log_analyzer.state_store import get_state_db, open_db

    path = os.environ.get("AI_LOG_ANALYZER_INCIDENT_STORE", "").strip()
    if path:
        if path.lower().endswith(_SQLITE_SUFFIXES):
            return SqliteIncidentStore(open_db(path))
        return IncidentStore(path)
    db = get_state_db()
    return SqliteIncidentStore(db) if db is not None else None


def annotate_and_record(result_dict_items: list[dict], generated_at: str) -> None:
    """Stamp each action item with its recurrence history from prior runs,
    then append this run to the journal. No env var → no-op."""
    store = get_store()
    if store is None:
        return
    for a in result_dict_items:
        rec = store.recurrence(a.get("description", ""))
        if rec:
            a["recurrence"] = rec
    try:
        store.record(result_dict_items, generated_at)
    except Exception:
        logger.exception("could not persist incident store")
