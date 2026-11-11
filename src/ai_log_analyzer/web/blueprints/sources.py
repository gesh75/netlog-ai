"""Flask Blueprint: sources routes (moved verbatim from web/app.py).

Pure restructure — no behaviour change. Shared auth helpers and
app-module state (API_TOKEN, SAMPLES_DIR, ...) are reached through
`ai_log_analyzer.web.app` so tests that monkeypatch that module
keep working.
"""
from __future__ import annotations

import os
import threading

from flask import Blueprint, abort, current_app, jsonify, request

import ai_log_analyzer.web.app as web_app
from ai_log_analyzer import rbac, webhooks
from ai_log_analyzer.analyzer import analyze
from ai_log_analyzer.sources import SourceConfig, SourceError, registry
from ai_log_analyzer.sources.manager import manager as source_manager
from ai_log_analyzer.web.app import (
    _audit_auth_failure,
    _body_fields,
    _parse_bool,
    _redact_source,
    _scrub_analysis,
    _scrub_event,
    _scrub_text,
    _tail_start_cursor,
    current_principal,
    require_role,
)

bp = Blueprint('sources', __name__)


# ── Live tail (SSE) ────────────────────────────────────────────────────
sse_lock = threading.Lock()
sse_active = [0]

@bp.route("/api/tail/<source_id>", methods=["GET"])
def api_tail(source_id: str):
    """Server-Sent Events stream of classified events from a syslog source.

    Zero-dependency real time: EventSource in the browser, chunked
    response here — no websocket stack. The token goes in a header like
    every other route (the dashboard reads the stream with fetch(), since
    EventSource cannot set headers); it is never accepted in the URL.
    Optional ?min_severity=critical|high|medium|low filters server-side.
    """
    if rbac.auth_enabled(web_app.API_TOKEN) and current_principal() is None:
        _audit_auth_failure()
        abort(401)   # any role may watch the live tail
    src = source_manager.get(source_id)
    if src is None:
        return jsonify({"error": f"unknown source: {source_id}"}), 404
    if not hasattr(src, "fetch_new"):
        return jsonify({"error": "live tail supports syslog listener sources only"}), 400

    from ai_log_analyzer.classifier import SEV_ORDER
    min_sev = (request.args.get("min_severity") or "info").lower()
    max_rank = SEV_ORDER.get(min_sev, 4)
    try:
        poll_s = min(5.0, max(0.2, float(request.args.get("poll") or 1.0)))
    except ValueError:
        return jsonify({"error": "poll must be a number of seconds"}), 400
    cursor0 = _tail_start_cursor(src)   # start at "now"

    # Every open stream pins a worker for its whole life: cap them so a couple
    # of viewers cannot starve the API. The slot is freed when the response closes.
    try:
        max_streams = max(1, int(os.environ.get("AI_LOG_ANALYZER_MAX_SSE", "8")))
    except ValueError:
        max_streams = 8
    with sse_lock:
        if sse_active[0] >= max_streams:
            return jsonify({"error": f"too many live tail streams (max {max_streams})",
                            "hint": "close another tail or raise AI_LOG_ANALYZER_MAX_SSE"}), 503
        sse_active[0] += 1

    def stream():
        import json as _json
        import time as _time

        from ai_log_analyzer.classifier import iter_classify
        cursor = cursor0
        yield "event: hello\ndata: {}\n\n"
        idle = 0.0
        while True:
            events, cursor = src.fetch_new(cursor)
            sent = False
            for ce in iter_classify(iter(events)):
                if SEV_ORDER.get(ce.severity, 4) <= max_rank:
                    yield f"data: {_json.dumps(_scrub_event(ce.to_dict()))}\n\n"
                    sent = True
            if sent:
                idle = 0.0
            else:
                idle += poll_s
                if idle >= 15.0:  # keep proxies from timing the stream out
                    yield ": keepalive\n\n"
                    idle = 0.0
            _time.sleep(poll_s)

    resp = current_app.response_class(
        stream(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )

    def release() -> None:
        with sse_lock:
            sse_active[0] -= 1
    resp.call_on_close(release)
    return resp

# ── External log sources (Kibana, Splunk, Loki, syslog, LibreNMS, SolarWinds, ...) ────
@bp.route("/api/sources", methods=["GET"])
@require_role("viewer")
def api_sources_list():
    """List configured sources + the connector kinds the registry knows.

    URL userinfo and ``extra`` values are redacted (key names only)."""
    return jsonify({
        "sources": [_redact_source(x) for x in source_manager.describe()],
        "known_kinds": source_manager.known_kinds(),
    })

@bp.route("/api/sources", methods=["POST"])
@require_role("admin", "config.sources.add", _body_fields("id", "type", "url"))
def api_sources_add():
    """Register a new source. Body: {id, type, url, api_token?, username?,
    password?, auth_methods?, extra?, verify_tls?, timeout_seconds?}."""
    body = request.get_json(silent=True) or {}
    src_id = (body.get("id") or "").strip()
    stype = (body.get("type") or "").strip()
    url = (body.get("url") or "").strip()
    if not src_id or not stype or not url:
        return jsonify({"ok": False, "error": "id, type, url are required"}), 400
    if not registry.is_registered(stype):
        return jsonify({"ok": False, "error": f"unknown type {stype!r}",
                        "known": source_manager.known_kinds()}), 400
    try:
        auth_methods = tuple(body.get("auth_methods") or ())
        cfg = SourceConfig(
            id=src_id,
            type=stype,
            url=url,
            auth_methods=auth_methods,
            api_token=body.get("api_token", ""),
            username=body.get("username", ""),
            password=body.get("password", ""),
            cookies=dict(body.get("cookies") or {}),
            extra={str(k): str(v) for k, v in (body.get("extra") or {}).items()},
            verify_tls=_parse_bool(body.get("verify_tls", True), default=True),
            timeout_seconds=float(body.get("timeout_seconds", 30.0)),
        )
        source_manager.add(cfg)
    except SourceError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except (TypeError, ValueError) as exc:
        return jsonify({"ok": False, "error": f"bad config: {exc}"}), 400
    return jsonify({"ok": True, "id": src_id})

@bp.route("/api/sources/<source_id>", methods=["GET"])
@require_role("viewer")
def api_sources_get(source_id: str):
    """Inspect a registered source: config, health, and recent buffered events."""
    src = source_manager.get(source_id)
    if src is None:
        return jsonify({"ok": False, "error": f"unknown source: {source_id}"}), 404

    matching = [s for s in source_manager.describe() if s["id"] == source_id]
    desc = _redact_source(matching[0]) if matching else {"id": source_id}
    health = source_manager.healthcheck(source_id)

    try:
        limit = min(100, max(1, int(request.args.get("limit") or 25)))
    except (ValueError, TypeError):
        limit = 25
    try:
        since = int(request.args.get("since") or 3600)
    except (ValueError, TypeError):
        since = 3600

    events = []
    try:
        events = source_manager.fetch(source_id, since_seconds=since, limit=limit)
    except Exception:
        pass

    return jsonify({
        "ok": True,
        "source": desc,
        "health": health,
        "recent_events_count": len(events),
        "events": [
            {
                "timestamp": e.timestamp,
                "hostname": e.hostname,
                "appname": e.appname,
                "severity_raw": e.severity_raw,
                "message": _scrub_text(e.message),
            }
            for e in events
        ],
    })


@bp.route("/api/sources/<source_id>", methods=["DELETE"])
@require_role("admin", "config.sources.remove")
def api_sources_remove(source_id: str):
    removed = source_manager.remove(source_id)
    return jsonify({"ok": removed})

@bp.route("/api/sources/<source_id>/test", methods=["POST"])
@require_role("operator")
def api_sources_test(source_id: str):
    return jsonify(source_manager.healthcheck(source_id))

@bp.route("/api/sources/<source_id>/fetch", methods=["POST"])
@require_role("operator")
def api_sources_fetch(source_id: str):
    """Pull a batch of events from a registered source. Body:
    {since_seconds, limit, host_filter}."""
    body = request.get_json(silent=True) or {}
    try:
        events = source_manager.fetch(
            source_id,
            since_seconds=int(body.get("since_seconds", 3600)),
            limit=int(body.get("limit", 1000)),
            host_filter=str(body.get("host_filter", "")),
        )
    except SourceError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({
        "ok": True,
        "count": len(events),
        "events": [
            {
                "timestamp": e.timestamp, "hostname": e.hostname,
                "appname": e.appname, "severity_raw": e.severity_raw,
                "message": _scrub_text(e.message),
            }
            for e in events
        ],
    })

@bp.route("/api/sources/<source_id>/analyze", methods=["POST"])
@require_role("operator")
def api_sources_analyze(source_id: str):
    """Fetch + run the full analyzer (classifier → dedup → optional LLM)."""
    body = request.get_json(silent=True) or {}
    try:
        events = source_manager.fetch(
            source_id,
            since_seconds=int(body.get("since_seconds", 3600)),
            limit=int(body.get("limit", 5000)),
            host_filter=str(body.get("host_filter", "")),
        )
    except SourceError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    if not events:
        return jsonify({"ok": True, "count": 0, "result": None,
                        "message": "no events in window"})
    result = analyze(
        events,
        use_llm=_parse_bool(body.get("use_llm", True), default=True),
        dedup=_parse_bool(body.get("dedup"), default=False),
        evpn_causal=_parse_bool(body.get("evpn_causal"), default=False),
    )
    result_dict = _scrub_analysis(result.to_dict())
    webhooks.notify_analysis(result_dict, f"source:{source_id}")
    return jsonify({"ok": True, "count": len(events), "result": result_dict})
