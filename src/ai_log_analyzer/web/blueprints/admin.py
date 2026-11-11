"""Flask Blueprint: admin routes (moved verbatim from web/app.py).

Pure restructure — no behaviour change. Shared auth helpers and
app-module state (API_TOKEN, SAMPLES_DIR, ...) are reached through
`ai_log_analyzer.web.app` so tests that monkeypatch that module
keep working.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, request

from ai_log_analyzer import audit
from ai_log_analyzer.web.app import require_role

bp = Blueprint('admin', __name__)


@bp.route("/api/audit", methods=["GET"])
@require_role("admin")
def api_audit():
    """Newest-first audit rows. Filters: ?actor=, ?action= (``*`` wildcard), ?since=, ?limit=."""
    if not audit.is_enabled():
        return jsonify({"enabled": False, "entries": [],
                        "hint": "set AI_LOG_ANALYZER_STATE_DB or AI_LOG_ANALYZER_AUDIT_DB"})
    try:
        since = float(request.args.get("since") or 0)
        limit = int(request.args.get("limit") or 100)
    except ValueError:
        return jsonify({"error": "since and limit must be numbers"}), 400
    return jsonify({"enabled": True, "entries": audit.query(
        limit=limit, actor=request.args.get("actor", ""), action=request.args.get("action", ""),
        since=since)})

@bp.route("/api/audit/verify", methods=["GET"])
@require_role("admin")
def api_audit_verify():
    return jsonify(audit.verify())
