"""Flask Blueprint: Prometheus telemetry (P4 item 14).

``GET /api/metrics`` renders the exposition text from
``ai_log_analyzer.metrics``. Same auth model as the other ``/api/*`` routes
(``viewer`` role; open in dev mode when no API token is set).

A scrape is cheap and side-effect free: it reads the spool depth from
``spool_meta``, the durable P3 backpressure counters from kv, and the
listeners' in-memory ``stats()``. It never writes to the state DB and never
probes an LLM provider. Any source that is unavailable is omitted from the
output rather than faked — a missing metric means "unknown", not zero.
"""
from __future__ import annotations

from flask import Blueprint, Response

from ai_log_analyzer import __version__, llm, metrics
from ai_log_analyzer.sources.manager import manager as source_manager
from ai_log_analyzer.web.app import require_role

bp = Blueprint('metrics', __name__)


@bp.route("/api/metrics", methods=["GET"])
@require_role("viewer")
def api_metrics():
    """Prometheus exposition format: EPS, spool depth, analysis time,
    LLM latency/errors, dropped UDP datagrams."""
    from ai_log_analyzer.state_store import get_state_db

    spool = None
    drops = None
    db = get_state_db()
    if db is not None:
        try:
            spool = db.spool_stats()
        except Exception:
            spool = None
        try:
            drops = db.backpressure_status()
        except Exception:
            drops = None

    listeners = []
    for sid in source_manager.list_ids():
        src = source_manager.get(sid)
        if hasattr(src, "stats"):
            try:
                listeners.append({"id": sid, **src.stats()})
            except Exception:
                pass

    try:
        llm_state = llm.get_state()
    except Exception:
        llm_state = None

    body = metrics.render(
        version=__version__,
        spool=spool,
        drops=drops,
        listeners=listeners,
        llm_state=llm_state,
    )
    return Response(body, mimetype="text/plain; version=0.0.4; charset=utf-8")
