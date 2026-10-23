"""Append-only audit trail: who ran what, when, from where.

Records privileged actions in the ``audit_log`` table of the shared SQLite
state DB (or ``AI_LOG_ANALYZER_AUDIT_DB``):

* ``/api/run`` command execution,
* configuration mutations (sources, classification rules, LLM provider and
  toggles, incident resolutions, triage worker start/stop),
* every external LLM call (provider and prompt size, never prompt content),
* tickets opened or updated by the streaming triage worker.

The table is append-only at the database level: triggers abort any UPDATE
or DELETE. Each row also stores ``prev_hash``/``hash`` (SHA-256 over the
previous hash and the row), so editing the file outside SQLite is caught by
``verify()``.

The acting principal comes from a context variable that the web layer sets
per request (``actor_scope``); background work records itself as a system
actor. Recording never raises: an unavailable audit store logs a warning
and the action proceeds.
"""
from __future__ import annotations

import contextvars
import logging
import os
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Actor:
    name: str
    role: str
    remote: str = ""


ANONYMOUS = Actor("anonymous", "none")
_ACTOR: contextvars.ContextVar[Actor] = contextvars.ContextVar("netlog_audit_actor", default=ANONYMOUS)


@contextmanager
def actor_scope(actor: Actor) -> Iterator[Actor]:
    token = _ACTOR.set(actor)
    try:
        yield actor
    finally:
        _ACTOR.reset(token)


def current_actor() -> Actor:
    return _ACTOR.get()


def get_audit_db() -> Any:
    """``AI_LOG_ANALYZER_AUDIT_DB`` or the shared state DB; None when neither is set."""
    from ai_log_analyzer.state_store import get_state_db, open_db

    path = os.environ.get("AI_LOG_ANALYZER_AUDIT_DB", "").strip()
    return open_db(path) if path else get_state_db()


def is_enabled() -> bool:
    return bool(os.environ.get("AI_LOG_ANALYZER_AUDIT_DB", "").strip()
                or os.environ.get("AI_LOG_ANALYZER_STATE_DB", "").strip())


def record(action: str, *, target: str = "", outcome: str = "ok", detail: dict[str, Any] | None = None,
           actor: Actor | None = None) -> dict[str, Any] | None:
    """Append one audit row; returns it, or None when auditing is unavailable."""
    who = actor or current_actor()
    try:
        db = get_audit_db()
        if db is None:
            return None
        return db.audit_append({"actor": who.name, "role": who.role, "remote": who.remote,
                                "action": action, "target": target, "outcome": outcome,
                                "detail": detail or {}})
    except Exception as exc:  # sqlite3.Error / OSError — never block the audited action
        log.warning("audit record failed for %s: %s", action, exc)
        return None


_THROTTLE_LOCK = threading.Lock()
_THROTTLE: dict[tuple[str, str], float] = {}
_THROTTLE_SUPPRESSED = [0]
_THROTTLE_WINDOW_S = 60.0
_THROTTLE_MAX_KEYS = 1024
_THROTTLE_GLOBAL_MAX = 120     # rows per window across all keys (spoofed-source floods)
_THROTTLE_GLOBAL = [0.0, 0]    # [window start, rows written in it]


def record_throttled(action: str, *, key: str, target: str = "", outcome: str = "denied",
                     detail: dict[str, Any] | None = None, actor: Actor | None = None,
                     window_s: float = _THROTTLE_WINDOW_S) -> dict[str, Any] | None:
    """``record`` for events an unauthenticated caller can generate at will (failed auth).

    At most one row per ``(action, key)`` per ``window_s``; the rows skipped in
    between are counted and reported as ``suppressed`` on the next row written,
    so a flood cannot bloat the append-only log yet is still visible in it.
    """
    now = time.monotonic()
    with _THROTTLE_LOCK:
        last = _THROTTLE.get((action, key))
        if last is not None and now - last < window_s:
            _THROTTLE_SUPPRESSED[0] += 1
            return None
        if now - _THROTTLE_GLOBAL[0] >= window_s:
            _THROTTLE_GLOBAL[:] = [now, 0]
        if _THROTTLE_GLOBAL[1] >= _THROTTLE_GLOBAL_MAX:
            _THROTTLE_SUPPRESSED[0] += 1
            return None
        _THROTTLE_GLOBAL[1] += 1
        if len(_THROTTLE) >= _THROTTLE_MAX_KEYS:   # bound memory under a spoofed-source flood
            _THROTTLE.clear()
        _THROTTLE[(action, key)] = now
        suppressed, _THROTTLE_SUPPRESSED[0] = _THROTTLE_SUPPRESSED[0], 0
    extra = dict(detail or {})
    if suppressed:
        extra["suppressed"] = suppressed
    return record(action, target=target, outcome=outcome, detail=extra, actor=actor)


def query(*, limit: int = 100, actor: str = "", action: str = "", since: float = 0.0) -> list[dict[str, Any]]:
    db = get_audit_db()
    if db is None:
        return []
    return db.audit_query(limit=max(1, min(int(limit), 1000)), actor=actor, action=action, since=since)


def verify() -> dict[str, Any]:
    db = get_audit_db()
    if db is None:
        return {"ok": False, "checked": 0, "broken_at": None, "error": "audit store not configured"}
    return db.audit_verify()
