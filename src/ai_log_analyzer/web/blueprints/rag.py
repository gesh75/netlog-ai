"""Flask Blueprint: rag routes (moved verbatim from web/app.py).

Pure restructure — no behaviour change. Shared auth helpers and
app-module state (API_TOKEN, SAMPLES_DIR, ...) are reached through
`ai_log_analyzer.web.app` so tests that monkeypatch that module
keep working.
"""
from __future__ import annotations

import os
from pathlib import Path

from flask import Blueprint, abort, jsonify, make_response, request

import ai_log_analyzer.web.app as web_app
from ai_log_analyzer.web.app import _body_fields, _load_site_devices, _parse_bool, require_role, sanitize_line

bp = Blueprint('rag', __name__)


# ── Retrieval index (configs, drift, topology, runbooks, incidents) ───
def _rag_or_400():
    from ai_log_analyzer import rag
    index = rag.get_index()
    if index is None:
        abort(make_response(jsonify({"error": "retrieval index not configured "
                                              "(set AI_LOG_ANALYZER_RAG_DB or AI_LOG_ANALYZER_STATE_DB)"}), 400))
    return index

@bp.route("/api/rag/search", methods=["GET"])
@require_role("viewer")
def api_rag_search():
    from ai_log_analyzer import rag
    q = (request.args.get("q") or "").strip()
    if not q:
        return jsonify({"error": "q is required"}), 400
    hosts = [h for h in (request.args.get("hosts") or "").split(",") if h.strip()]
    kinds = [k for k in (request.args.get("kinds") or "").split(",") if k.strip()] or None
    try:
        k = min(int(request.args.get("k") or 8), 50)
    except ValueError:
        return jsonify({"error": "k must be an integer"}), 400
    index = _rag_or_400()
    hits = index.search(q, k=k, kinds=kinds, hosts=hosts)
    return jsonify({"query": q, "mode": index.last_search_mode,
                    "embeddings": index.stats()["embeddings"],
                    "hits": rag.public_evidence(
        [{**h, "id": f"S{i}"} for i, h in enumerate(hits, 1)])})

@bp.route("/api/rag/stats", methods=["GET"])
@require_role("viewer")
def api_rag_stats():
    return jsonify(_rag_or_400().stats())

@bp.route("/api/rag/reindex", methods=["POST"])
@require_role("admin", "rag.reindex", _body_fields("netbox"))
def api_rag_reindex():
    from ai_log_analyzer import rag
    body = request.get_json(silent=True) or {}
    golden = os.environ.get("AI_LOG_ANALYZER_GOLDEN_DIR", "").strip() or None
    report = rag.build_default_index(_rag_or_400(), sites_dir=web_app.SITES_DIR, golden_dir=golden,
                                     netbox=_parse_bool(body.get("netbox"), default=False))
    return jsonify({"ok": True, **report})

@bp.route("/api/rag/drift", methods=["POST"])
@require_role("operator")
def api_rag_drift():
    """Running vs golden config drift. Body: {running, golden} or {site, hostname} with
    AI_LOG_ANALYZER_GOLDEN_DIR / <site>/golden/ holding the golden file."""
    from ai_log_analyzer import rag
    body = request.get_json(silent=True) or {}
    running, golden = body.get("running"), body.get("golden")
    if not (isinstance(running, str) and isinstance(golden, str)):
        site, host = str(body.get("site") or ""), str(body.get("hostname") or "")
        safe_site = Path(site).name
        devices, manifest = _load_site_devices(safe_site) if safe_site else (None, None)
        dev = next((d for d in devices or [] if d.get("hostname") == host), None)
        file_of = {d.get("hostname"): d.get("file") for d in (manifest or {}).get("devices", [])}
        if dev is None:
            return jsonify({"error": "give running+golden text, or a known site + hostname"}), 400
        gdir = os.environ.get("AI_LOG_ANALYZER_GOLDEN_DIR", "").strip()
        candidates = [web_app.SITES_DIR / safe_site / "golden"] + ([Path(gdir) / safe_site, Path(gdir)] if gdir else [])
        golden = None
        for d in candidates:
            for name in (file_of.get(host) or "", f"{host}.txt", f"{host}.cfg"):
                if name and (d / Path(name).name).is_file():
                    golden = (d / Path(name).name).read_text(encoding="utf-8", errors="replace")
                    break
            if golden is not None:
                break
        if golden is None:
            return jsonify({"error": f"no golden config found for {host}"}), 404
        running = dev.get("config_text") or ""
    drift = rag.config_drift(running, golden)
    for h in drift["hunks"]:   # never echo secrets that differ between the two files
        h["added"] = [sanitize_line(x) for x in h["added"]]
        h["removed"] = [sanitize_line(x) for x in h["removed"]]
    return jsonify(drift)
