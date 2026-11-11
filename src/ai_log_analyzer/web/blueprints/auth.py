"""Flask Blueprint: auth routes (moved verbatim from web/app.py).

Pure restructure — no behaviour change. Shared auth helpers and
app-module state (API_TOKEN, SAMPLES_DIR, ...) are reached through
`ai_log_analyzer.web.app` so tests that monkeypatch that module
keep working.
"""
from __future__ import annotations

from flask import Blueprint, jsonify

import ai_log_analyzer.web.app as web_app
from ai_log_analyzer import audit, rbac
from ai_log_analyzer.web.app import require_role

bp = Blueprint('auth', __name__)


# ── Identity + audit trail ────────────────────────────────────────────
@bp.route("/api/whoami", methods=["GET"])
@require_role("viewer")
def api_whoami():
    actor = audit.current_actor()
    return jsonify({"name": actor.name, "role": actor.role,
                    "auth": "rbac" if rbac.auth_enabled(web_app.API_TOKEN) else "dev"})
