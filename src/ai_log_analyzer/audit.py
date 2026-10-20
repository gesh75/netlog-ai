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
