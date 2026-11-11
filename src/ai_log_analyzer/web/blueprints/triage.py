"""Flask Blueprint: triage routes (moved verbatim from web/app.py).

Pure restructure — no behaviour change. Shared auth helpers and
app-module state (API_TOKEN, SAMPLES_DIR, ...) are reached through
`ai_log_analyzer.web.app` so tests that monkeypatch that module
keep working.
"""
from __future__ import annotations

from flask import Blueprint, abort, jsonify, make_response, request

import ai_log_analyzer.web.app as web_app
from ai_log_analyzer.web.app import require_role

bp = Blueprint('triage', __name__)


@bp.route("/api/triage", methods=["POST"])
@require_role("operator")
def api_triage():
    """Per-device deep triage: verdict + health score + severity histogram
    + top processes + deduped error patterns for one host. Thin wrapper
    over web_app.triage_from_manager(); never raises for a single bad source."""
    body = request.get_json(silent=True) or {}
    hostname = (body.get("hostname") or "").strip()
    if not hostname:
        return jsonify({"ok": False, "error": "hostname required"}), 400
    raw_ids = body.get("source_ids")
    source_ids = [str(s) for s in raw_ids] if isinstance(raw_ids, list) else None
    result = web_app.triage_from_manager(
        hostname,
        source_ids,
        since_seconds=int(body.get("since_seconds", 86_400)),
        limit=int(body.get("limit", 5000)),
    )
    return jsonify(result)

# ── Streaming triage worker ───────────────────────────────────────────
def _worker_or_400():
    from ai_log_analyzer.triage_worker import get_worker
    worker = get_worker()
    if worker is None:
        abort(make_response(jsonify({"error": "streaming triage needs AI_LOG_ANALYZER_STATE_DB "
                                              "(the syslog spool)"}), 400))
    return worker

@bp.route("/api/triage/stream/status", methods=["GET"])
@require_role("viewer")
def api_triage_stream_status():
    from ai_log_analyzer.triage_worker import get_worker
    worker = get_worker(create=False)
    if worker is None:
        from ai_log_analyzer.state_store import get_state_db
        return jsonify({"running": False, "configured": get_state_db() is not None})
    try:
        limit = max(1, min(int(request.args.get("limit") or 50), 500))
    except ValueError:
        return jsonify({"error": "limit must be an integer"}), 400
    tickets = worker.db.triage_all(limit=limit)
    return jsonify({**worker.status(), "tickets": tickets})

@bp.route("/api/triage/stream/start", methods=["POST"])
@require_role("admin", "triage.worker.start")
def api_triage_stream_start():
    worker = _worker_or_400()
    return jsonify({"ok": True, "started": worker.start(), **worker.status()})

@bp.route("/api/triage/stream/stop", methods=["POST"])
@require_role("admin", "triage.worker.stop")
def api_triage_stream_stop():
    worker = _worker_or_400()
    worker.stop()
    return jsonify({"ok": True, **worker.status()})

@bp.route("/api/triage/stream/tick", methods=["POST"])
@require_role("admin", "triage.worker.tick")
def api_triage_stream_tick():
    """Run one triage tick now (useful for cron-style deployments)."""
    return jsonify(_worker_or_400().run_once())
