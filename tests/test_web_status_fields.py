"""The header status feed must expose the triage worker's loss/backlog signals and the dashboard must render them."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

import ai_log_analyzer.web.app as web_app
from ai_log_analyzer.state_store import open_db
from ai_log_analyzer.web.app import create_app

JS = Path(web_app.STATIC_DIR) / "v2.js"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(web_app, "API_TOKEN", "")
    monkeypatch.setenv("AI_LOG_ANALYZER_STATE_DB", str(tmp_path / "state.db"))
    open_db(tmp_path / "state.db")
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


@pytest.mark.unit
def test_overview_exposes_gap_pending_and_sink_state(client):
    from ai_log_analyzer.triage_worker import get_worker, reset_worker
    try:
        get_worker().run_once()
        tri = client.get("/api/status/overview").get_json()["triage"]
        assert tri["spool_gap_rows"] == {} and tri["pending_deliveries"] == 0 and tri["sink_state"] == {}
    finally:
        reset_worker()


@pytest.mark.unit
def test_dashboard_renders_the_new_signals():
    js = JS.read_text(encoding="utf-8")
    for needle in ("remote-host", "spool_gap_rows", "pending_deliveries", "sink_state", "udp_drops", "spool_lines_lost"):
        assert needle in js, needle
    assert "innerHTML" not in js


@pytest.mark.unit
@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_v2_js_still_parses():
    out = subprocess.run(["node", "--check", str(JS)], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
