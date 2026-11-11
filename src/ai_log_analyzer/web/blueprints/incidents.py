"""Flask Blueprint: incidents routes (moved verbatim from web/app.py).

Pure restructure — no behaviour change. Shared auth helpers and
app-module state (API_TOKEN, SAMPLES_DIR, ...) are reached through
`ai_log_analyzer.web.app` so tests that monkeypatch that module
keep working.
"""
from __future__ import annotations

import threading

from flask import Blueprint, jsonify, request

import ai_log_analyzer.web.app as web_app
from ai_log_analyzer import audit
from ai_log_analyzer.web.app import _body_fields, require_role

bp = Blueprint('incidents', __name__)


# ── Incident memory ────────────────────────────────────────────────────
@bp.route("/api/incidents/similar", methods=["GET"])
@require_role("viewer")
def api_incidents_similar():
    """Free-text search over the local incident journal.

    Requires AI_LOG_ANALYZER_INCIDENT_STORE; ?q=<text>&top=<n>.
    """
    from ai_log_analyzer.memory import get_store
    store = get_store()
    if store is None:
        return jsonify({"error": "incident store not configured — "
                        "set AI_LOG_ANALYZER_INCIDENT_STORE"}), 400
    q = (request.args.get("q") or "").strip()
    if not q:
        return jsonify({"error": "q parameter required"}), 400
    try:
        top = max(1, min(20, int(request.args.get("top") or 5)))
    except ValueError:
        top = 5
    return jsonify({"query": q, "journal_size": len(store),
                    "matches": store.find_similar(q, top_n=top)})


# ── Live tail (SSE) ────────────────────────────────────────────────────
sse_lock = threading.Lock()
sse_active = [0]

@bp.route("/api/correlate", methods=["POST"])
@require_role("operator")
def api_correlate():
    """Cross-source device correlation: which hosts surface actionable
    events from >=2 sources (confirmed) vs 1 (suspected). Thin wrapper
    over web_app.correlate_from_manager(); never raises for a single bad source."""
    body = request.get_json(silent=True) or {}
    # None => all registered sources; an explicit list selects a subset.
    raw_ids = body.get("source_ids")
    source_ids = [str(s) for s in raw_ids] if isinstance(raw_ids, list) else None
    min_severity = (body.get("min_severity") or "medium").strip().lower()
    try:
        result = web_app.correlate_from_manager(
            source_ids,
            since_seconds=int(body.get("since_seconds", 3600)),
            limit=int(body.get("limit", 5000)),
            min_severity=min_severity,
        )
    except ValueError as exc:  # unknown min_severity label
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify(result)

# ── Incident resolution (feeds retrieval precedents) ──────────────────
@bp.route("/api/incidents/<incident_id>/resolve", methods=["POST"])
@require_role("operator", "incident.resolve", _body_fields("resolution"))
def api_incident_resolve(incident_id: str):
    from ai_log_analyzer.memory import get_store
    body = request.get_json(silent=True) or {}
    resolution = str(body.get("resolution") or "").strip()
    if not resolution:
        return jsonify({"error": "resolution is required"}), 400
    store = get_store()
    if store is None:
        return jsonify({"error": "incident store not configured"}), 400
    rec = store.resolve(incident_id, resolution, resolved_by=audit.current_actor().name)
    if rec is None:
        return jsonify({"error": f"unknown incident {incident_id}"}), 404
    return jsonify({"ok": True, "incident": rec})
