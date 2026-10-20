"""V2 dashboard: the /api/status/overview header feed, the LLM egress policy
it reports, and the contracts the zero-build frontend relies on (script
order, element ids, remediation export shapes)."""
from __future__ import annotations

import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest

import ai_log_analyzer.web.app as web_app
from ai_log_analyzer import llm
from ai_log_analyzer.state_store import StateDB, open_db
from ai_log_analyzer.web.app import create_app

STATIC = Path(web_app.STATIC_DIR)


@pytest.fixture
def state(tmp_path, monkeypatch):
    path = tmp_path / "state.db"
    monkeypatch.setenv("AI_LOG_ANALYZER_STATE_DB", str(path))
    return open_db(path)


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(web_app, "API_TOKEN", "")
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


@pytest.fixture
def llm_state(monkeypatch):
    monkeypatch.setattr(llm, "_sync_shared_state", lambda force=False: None)
    for key in ("provider", "enabled", "allow_cloud_fallback", "last_call"):
        monkeypatch.setitem(llm._state, key, llm._state.get(key))
    return llm._state


# ── /api/status/overview ────────────────────────────────────────────────────

def test_overview_in_dev_mode_without_state_db(client):
    body = client.get("/api/status/overview").get_json()
    assert body["spool"] == {"enabled": False, "sources": []}
    assert body["triage"] == {"configured": False, "running": False}
    assert body["identity"] == {"name": "anonymous", "role": "dev", "auth": "dev"}
    assert body["audit"] is False
    assert {"provider", "enabled", "mode", "order", "last_call"} <= set(body["llm"])


def test_overview_reports_spool_depth_and_triage_tickets(client, state):
    now = time.time()
    state.spool_append("syslog-1", [(now - 30, "10.0.0.1", "a"), (now - 5, "10.0.0.1", "b")], cap=100)
    state.spool_append("syslog-2", [(now - 100, "", "c")], cap=100)
    state.triage_put({"fingerprint": "NETLOG-X", "first_seen": now, "last_seen": now, "last_sent": now,
                      "severity": "high", "event_count": 1, "last_event_at": now, "sends": 1, "held": 0,
                      "state": "active", "title": "t", "refs": []})
    body = client.get("/api/status/overview").get_json()
    spool = body["spool"]
    assert spool["enabled"] is True and spool["rows"] == 3
    by_src = {s["source"]: s for s in spool["sources"]}
    assert by_src["syslog-1"]["rows"] == 2 and by_src["syslog-1"]["max_id"] == 2
    assert 3 <= by_src["syslog-1"]["age_s"] <= 60
    assert body["triage"]["configured"] is True and body["triage"]["tickets"] == 1
    assert body["audit"] is True


def test_overview_includes_a_running_worker(client, state):
    from ai_log_analyzer.triage_worker import get_worker, reset_worker
    try:
        worker = get_worker()
        worker.run_once()
        tri = client.get("/api/status/overview").get_json()["triage"]
        assert tri["role"] == "active" and tri["sinks"] == ["dry-run"] and tri["last_tick_at"]
    finally:
        reset_worker()


def test_overview_requires_a_token_when_rbac_is_on(client, monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_VIEWER_TOKENS", "vera:v-tok")
    assert client.get("/api/status/overview").status_code == 401
    body = client.get("/api/status/overview", headers={"Authorization": "Bearer v-tok"}).get_json()
    assert body["identity"] == {"name": "vera", "role": "viewer", "auth": "rbac"}


@pytest.mark.parametrize(("provider", "fallback", "mode"), [
    ("ollama", False, "local-only"),
    ("local", False, "local-only"),
    ("ollama", True, "cloud-fallback"),
    ("claude", False, "cloud"),
    ("claude-only", False, "cloud"),
    ("grok", False, "cloud"),
])
def test_egress_policy_modes(llm_state, provider, fallback, mode):
    llm_state.update(provider=provider, allow_cloud_fallback=fallback, enabled=True)
    pol = llm.egress_policy()
    assert pol["mode"] == mode
    assert pol["order"] == llm.provider_order(provider)
    if mode == "local-only":
        assert not {"claude", "grok"} & set(pol["order"])


def test_overview_never_probes_providers(client, llm_state, monkeypatch):
    def boom():
        raise AssertionError("status bar must not probe providers")
    monkeypatch.setattr(llm, "_list_available_providers", boom)
    llm_state.update(last_call={"provider": "claude", "entities_tokenized": 7, "redactions": 2, "ok": True})
    body = client.get("/api/status/overview").get_json()
    assert body["llm"]["last_call"]["entities_tokenized"] == 7


def test_spool_stats_and_triage_count(tmp_path):
    db = StateDB(tmp_path / "s.db")
    assert db.spool_stats() == [] and db.triage_count() == 0
    db.spool_append("a", [(1.0, "", "x"), (2.0, "", "y")], cap=10)
    assert db.spool_stats() == [{"source": "a", "rows": 2, "max_id": 2, "last_received_at": 2.0}]


# ── frontend contracts ──────────────────────────────────────────────────────

def test_v2_script_loads_before_app_js():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert html.index('src="v2.js"') < html.index('src="app.js"')   # token wrapper must exist first
    assert (STATIC / "v2.js").is_file()


def test_every_element_id_v2_uses_exists_in_index_html():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    js = (STATIC / "v2.js").read_text(encoding="utf-8")
    ids = set(re.findall(r'getElementById\("([\w-]+)"\)', js))
    ids |= set(re.findall(r'chip(?:Text|State)\("([\w-]+)"', js))
    assert ids, "no ids found: the regex no longer matches v2.js"
    missing = sorted(i for i in ids if f'id="{i}"' not in html)
    assert missing == []


def test_frontend_never_injects_html():
    for name in ("v2.js",):
        js = (STATIC / name).read_text(encoding="utf-8")
        assert "innerHTML" not in js and "insertAdjacentHTML" not in js and "document.write" not in js


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
@pytest.mark.parametrize("name", ["v2.js", "app.js"])
def test_javascript_parses(name):
    out = subprocess.run(["node", "--check", str(STATIC / name)], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr


# ── remediation export shapes the remediation card depends on ──────────────

def test_remediation_ansible_export_has_a_check_mode_dry_run(client):
    r = client.post("/api/remediation", json={"device": "FGT-HQ-01", "vendor": "fortinet_fortios",
                                              "action": "drain", "interface": "wan1", "export": "ansible"})
    body = r.get_json()
    assert r.status_code == 200 and body["plan"]["vendor"] == "fortinet_fortios"
    assert "check_mode: true" in body["export"]["content"]
    for key in ("pre_checks", "config_commands", "commit_with_timer_commands", "post_checks",
                "confirm_commit_commands", "manual_rollback_commands", "plan_id", "rollback_minutes"):
        assert key in body["plan"]


def test_unsupported_export_still_returns_the_plan_for_the_cli_view(client):
    r = client.post("/api/remediation", json={"device": "vedge-br02", "vendor": "cisco_sdwan",
                                              "action": "drain", "interface": "ge0/0", "export": "ansible"})
    body = r.get_json()
    assert r.status_code == 400 and body["ok"] is False
    assert "vManage" in body["error"] and body["plan"]["device"] == "vedge-br02"
