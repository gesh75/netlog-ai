"""Flask Blueprint: llm routes (moved verbatim from web/app.py).

Pure restructure — no behaviour change. Shared auth helpers and
app-module state (API_TOKEN, SAMPLES_DIR, ...) are reached through
`ai_log_analyzer.web.app` so tests that monkeypatch that module
keep working.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, request

import ai_log_analyzer.web.app as web_app
from ai_log_analyzer import copilot, llm, rbac
from ai_log_analyzer.web.app import _body_fields, _load_site_devices, current_principal, require_role

bp = Blueprint('llm', __name__)


@bp.route("/api/llm/status", methods=["GET"])
def llm_status():
    state = llm.get_state()
    # last_errors carries upstream HTTP error bodies — useful in the UI,
    # but on a token-protected deployment don't hand it to anonymous
    # callers. Dev mode (no token) keeps full output for the dashboard.
    if rbac.auth_enabled(web_app.API_TOKEN) and current_principal() is None:
        state = {k: v for k, v in state.items() if k != "last_errors"}
    return jsonify(state)

@bp.route("/api/llm/provider", methods=["POST"])
@require_role("admin", "llm.provider.set", _body_fields("provider"))
def llm_set_provider():
    body = request.get_json(silent=True) or {}
    ok, msg = llm.set_provider(body.get("provider", ""))
    if not ok:
        return jsonify({"ok": False, "error": msg}), 400
    return jsonify({"ok": True, "provider": msg})

@bp.route("/api/llm/toggle", methods=["POST"])
@require_role("admin", "llm.toggle", _body_fields("enabled"))
def llm_toggle():
    body = request.get_json(silent=True) or {}
    enabled = bool(body.get("enabled", True))
    return jsonify({"ok": True, "enabled": llm.set_enabled(enabled)})

@bp.route("/api/sanitize-diff", methods=["POST"])
@require_role("operator")
def api_sanitize_diff():
    """Preview the sanitize-before-LLM gate on pasted text.

    Body: {"text": "..."}. Returns original, sanitized, total, by_rule.
    """
    from ai_log_analyzer.sanitize import sanitize_report
    body = request.get_json(silent=True) or {}
    text = body.get("text")
    if not isinstance(text, str):
        return jsonify({"error": "body must be {\"text\": \"...\"}"}), 400
    # Bound the preview so a huge paste can't pin a worker.
    text = text[:200_000]
    report = sanitize_report(text, mask_pii=True)
    return jsonify({
        "original": text,
        "sanitized": report["sanitized"],
        "total": report["total"],
        "by_rule": report["by_rule"],
    })

# ── AI Copilot ────────────────────────────────────────────────────────
@bp.route("/api/copilot", methods=["POST"])
@require_role("operator")
def api_copilot():
    body = request.get_json(silent=True) or {}
    question = (body.get("question") or "").strip()
    if not question:
        return jsonify({"error": "question required"}), 400
    # Source: site bundle OR single hostname OR raw config
    site_id = (body.get("site_id") or "").strip()
    hostname = (body.get("hostname") or "").strip()
    raw_cfg = body.get("config_text")
    context_blocks: list[dict] = []
    if site_id:
        safe = "".join(c for c in site_id if c.isalnum() or c in "-_").lower()
        devs, _ = _load_site_devices(safe)
        if devs:
            context_blocks = devs
    elif raw_cfg:
        context_blocks = [{"hostname": hostname or "device", "platform": body.get("platform", "junos"),
                           "config_text": raw_cfg}]
    if not context_blocks:
        return jsonify({"error": "no context — supply site_id or config_text"}), 400
    return jsonify(copilot.ask(question, context_blocks))
