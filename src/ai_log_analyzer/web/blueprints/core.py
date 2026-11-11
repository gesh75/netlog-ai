"""Flask Blueprint: core routes (moved verbatim from web/app.py).

Pure restructure — no behaviour change. Shared auth helpers and
app-module state (API_TOKEN, SAMPLES_DIR, ...) are reached through
`ai_log_analyzer.web.app` so tests that monkeypatch that module
keep working.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, send_from_directory

import ai_log_analyzer.web.app as web_app
from ai_log_analyzer import __version__, audit, llm, rbac
from ai_log_analyzer.adapters import network_tool
from ai_log_analyzer.sources.manager import manager as source_manager
from ai_log_analyzer.web.app import require_role

bp = Blueprint('core', __name__)


# ── UI ────────────────────────────────────────────────────────────────
@bp.route("/")
def index():
    return send_from_directory(str(web_app.STATIC_DIR), "index.html")

# ── Health + LLM control ──────────────────────────────────────────────
@bp.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "ok": True,
        "version": __version__,
        "network_tool_available": network_tool.is_available(),
        "auth": "rbac" if rbac.auth_enabled(web_app.API_TOKEN) else "dev",
        "audit": audit.is_enabled(),
    })

# ── Dashboard status bar ──────────────────────────────────────────────
@bp.route("/api/status/overview", methods=["GET"])
@require_role("viewer")
def api_status_overview():
    """One cheap poll for the header: spool depth, triage worker, LLM egress
    policy and vault stats, and who the caller is. No provider probing."""
    import time as _time

    from ai_log_analyzer.state_store import get_state_db
    from ai_log_analyzer.triage_worker import get_worker

    now = _time.time()
    db = get_state_db()
    spool: dict = {"enabled": db is not None, "sources": []}
    if db is not None:
        try:
            for row in db.spool_stats():
                row["age_s"] = round(now - row["last_received_at"], 1) if row["last_received_at"] else None
                spool["sources"].append(row)
            spool["rows"] = sum(r["rows"] for r in spool["sources"])
        except Exception as exc:   # sqlite3.Error — the bar must still render
            spool["error"] = str(exc)[:200]
    for sid in source_manager.list_ids():
        src = source_manager.get(sid)
        if hasattr(src, "stats"):
            try:
                spool.setdefault("listeners", []).append({"id": sid, **src.stats()})
            except Exception:
                pass
    worker = get_worker(create=False)
    triage: dict = {"configured": db is not None, "running": False}
    if worker is not None:
        st = worker.status()
        triage.update(running=st["running"], role=st["role"], sinks=st["sinks"],
                      window_events=st["window_events"], totals=st["totals"],
                      last_tick_at=(st.get("last_tick") or {}).get("at"),
                      spool_gap_rows=st.get("spool_gap_rows", {}),
                      pending_deliveries=st.get("pending_deliveries", 0),
                      sink_state=st.get("sink_state", {}))
    if db is not None:
        try:
            triage["tickets"] = db.triage_count()
        except Exception:
            pass
    backpressure: dict = {"enabled": False, "sources": [], "total_drops": 0, "warning": False}
    if db is not None:
        try:
            backpressure = db.backpressure_status()
        except Exception:
            pass
    actor = audit.current_actor()
    return jsonify({
        "generated_at": now,
        "spool": spool,
        "backpressure": backpressure,
        "triage": triage,
        "llm": llm.egress_policy(),
        "identity": {"name": actor.name, "role": actor.role,
                     "auth": "rbac" if rbac.auth_enabled(web_app.API_TOKEN) else "dev"},
        "audit": audit.is_enabled(),
    })
