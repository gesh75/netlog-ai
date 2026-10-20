"""RBAC (viewer < operator < admin), the append-only audit trail, and
attribution of privileged actions and external LLM calls."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from unittest.mock import patch

import pytest

import ai_log_analyzer.web.app as web_app
from ai_log_analyzer import audit, llm, rbac
from ai_log_analyzer.state_store import StateDB, open_db
from ai_log_analyzer.web.app import create_app

VIEW, OPER, ADMIN = "view-tok-1", "oper-tok-1", "admin-tok-1"


@pytest.fixture
def state(tmp_path, monkeypatch):
    path = tmp_path / "state.db"
    monkeypatch.setenv("AI_LOG_ANALYZER_STATE_DB", str(path))
    return open_db(path)


@pytest.fixture
def client(monkeypatch, state):
    monkeypatch.setattr(web_app, "API_TOKEN", "")
    monkeypatch.setenv("AI_LOG_ANALYZER_VIEWER_TOKENS", f"vera:{VIEW}")
    monkeypatch.setenv("AI_LOG_ANALYZER_OPERATOR_TOKENS", f"otto:{OPER}")
    monkeypatch.setenv("AI_LOG_ANALYZER_ADMIN_TOKENS", f"ada:{ADMIN}")
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


def _h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ── principals ──────────────────────────────────────────────────────────────

def test_principals_from_env_and_hashed_file(tmp_path, monkeypatch):
    f = tmp_path / "rbac.json"
    f.write_text(json.dumps({"users": [
        {"name": "alice", "role": "operator", "token_sha256": hashlib.sha256(b"alice-secret").hexdigest()},
        {"name": "bad", "role": "superuser", "token": "x"},
    ]}))
    monkeypatch.setenv("AI_LOG_ANALYZER_RBAC_FILE", str(f))
    monkeypatch.setenv("AI_LOG_ANALYZER_VIEWER_TOKENS", "bare-token")
    assert rbac.authenticate("alice-secret").name == "alice"
    assert rbac.authenticate("alice-secret").role == "operator"
    assert rbac.authenticate("bare-token").role == "viewer"
    assert rbac.authenticate("x") is None                 # invalid role entry skipped
    assert rbac.authenticate("legacy", legacy_token="legacy").role == "admin"
    assert rbac.authenticate("") is None


def test_role_ordering():
    p = rbac.Principal("o", "operator", "0" * 64)
    assert p.allows("viewer") and p.allows("operator") and not p.allows("admin")


# ── route enforcement ───────────────────────────────────────────────────────

def test_unknown_or_missing_token_is_401(client):
    assert client.get("/api/incidents/similar?q=bgp").status_code == 401
    assert client.get("/api/incidents/similar?q=bgp", headers=_h("nope")).status_code == 401


def test_viewer_reads_dashboards_but_cannot_act(client):
    assert client.get("/api/incidents/similar?q=bgp", headers=_h(VIEW)).status_code == 200
    assert client.get("/api/whoami", headers=_h(VIEW)).get_json()["role"] == "viewer"
    assert client.get("/api/triage/stream/status", headers=_h(VIEW)).status_code == 200
    assert client.post("/api/analyze", json={}, headers=_h(VIEW)).status_code == 403
    assert client.post("/api/llm/toggle", json={"enabled": False}, headers=_h(VIEW)).status_code == 403
    assert client.post("/api/run", json={"hostname": "r1", "command": "show version"},
                       headers=_h(VIEW)).status_code == 403


def test_operator_analyzes_but_privileged_actions_need_admin(client):
    r = client.post("/api/analyze", json={"source": "text", "text": "Oct 20 10:00:00 r1 bgpd: x"},
                    headers=_h(OPER))
    assert r.status_code not in (401, 403)
    assert client.post("/api/run", json={"hostname": "r1", "command": "show version"},
                       headers=_h(OPER)).status_code == 403
    assert client.post("/api/llm/provider", json={"provider": "ollama"}, headers=_h(OPER)).status_code == 403
    assert client.post("/api/llm/toggle", json={"enabled": False}, headers=_h(OPER)).status_code == 403
    assert client.post("/api/sources", json={"id": "x"}, headers=_h(OPER)).status_code == 403
    assert client.get("/api/audit", headers=_h(OPER)).status_code == 403


def test_admin_passes_every_gate_and_legacy_token_is_admin(client, monkeypatch):
    assert client.post("/api/llm/provider", json={"provider": "ollama"}, headers=_h(ADMIN)).status_code == 200
    assert client.get("/api/audit", headers=_h(ADMIN)).status_code == 200
    monkeypatch.setattr(web_app, "API_TOKEN", "legacy-shared")
    assert client.get("/api/audit", headers={"X-API-Token": "legacy-shared"}).status_code == 200
    llm.set_provider("ollama")


def test_llm_status_redacts_errors_for_anonymous_only(client):
    assert "last_errors" not in client.get("/api/llm/status").get_json()
    assert "last_errors" in client.get("/api/llm/status", headers=_h(VIEW)).get_json()


def test_sse_tail_accepts_any_role_via_query_token(client):
    assert client.get("/api/tail/nope").status_code == 401
    assert client.get(f"/api/tail/nope?token={VIEW}").status_code == 404   # past the gate


def test_dev_mode_without_principals_stays_open(monkeypatch, state):
    monkeypatch.setattr(web_app, "API_TOKEN", "")
    app = create_app()
    c = app.test_client()
    assert c.get("/api/whoami").get_json() == {"name": "anonymous", "role": "dev", "auth": "dev"}
    assert c.post("/api/llm/toggle", json={"enabled": True}).status_code == 200


# ── audit trail ─────────────────────────────────────────────────────────────

def test_privileged_actions_are_audited_with_the_principal(client):
    client.post("/api/llm/toggle", json={"enabled": True}, headers=_h(ADMIN))
    with patch.object(web_app.network_tool, "is_available", return_value=False), \
            patch.object(web_app.frr, "is_lab_container", return_value=False):
        client.post("/api/run", json={"hostname": "r1", "command": "show bgp summary"}, headers=_h(ADMIN))
    client.post("/api/run", json={"hostname": "r1", "command": "reload"}, headers=_h(OPER))   # denied
    rows = audit.query(limit=10)
    by_action = {r["action"]: r for r in rows}
    toggle = by_action["llm.toggle"]
    assert toggle["actor"] == "ada" and toggle["role"] == "admin" and toggle["detail"]["enabled"] is True
    run = by_action["run.command"]
    assert run["detail"]["command"] == "show bgp summary" and run["outcome"] == "http_503"
    denied = by_action["authz.denied"]
    assert denied["actor"] == "otto" and denied["target"] == "/api/run" and denied["outcome"] == "denied"


def test_audit_never_stores_credentials_from_request_bodies(client):
    client.post("/api/sources", json={"id": "orion", "type": "solarwinds", "url": "https://sw",
                                       "password": "hunter2", "api_token": "tok-123"}, headers=_h(ADMIN))
    row = next(r for r in audit.query(limit=10) if r["action"] == "config.sources.add")
    blob = json.dumps(row)
    assert "hunter2" not in blob and "tok-123" not in blob and row["detail"]["id"] == "orion"


def test_audit_log_is_append_only_and_tamper_evident(tmp_path):
    db = StateDB(tmp_path / "a.db")
    for i in range(3):
        db.audit_append({"actor": f"u{i}", "role": "admin", "action": "x"})
    assert db.audit_verify() == {"ok": True, "checked": 3, "broken_at": None}
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        db.conn().execute("UPDATE audit_log SET actor='mallory' WHERE id=2")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        db.conn().execute("DELETE FROM audit_log WHERE id=1")
    # An attacker with raw file access drops the trigger first: the hash chain still catches it.
    conn = db.conn()
    conn.execute("DROP TRIGGER audit_log_no_update")
    conn.execute("UPDATE audit_log SET actor='mallory' WHERE id=2")
    assert db.audit_verify() == {"ok": False, "checked": 1, "broken_at": 2}


def test_audit_endpoint_filters_and_verify(client):
    client.post("/api/llm/toggle", json={"enabled": True}, headers=_h(ADMIN))
    rows = client.get("/api/audit?action=llm.*&actor=ada", headers=_h(ADMIN)).get_json()["entries"]
    assert rows and all(r["action"].startswith("llm.") and r["actor"] == "ada" for r in rows)
    assert client.get("/api/audit/verify", headers=_h(ADMIN)).get_json()["ok"] is True


def test_external_llm_calls_are_audited_and_attributed(state, monkeypatch):
    monkeypatch.setitem(llm._PROVIDERS, "claude", lambda s, p, m: "answer")
    monkeypatch.setitem(llm._PROVIDERS, "ollama", lambda s, p, m: "answer")
    monkeypatch.setattr(llm, "_sync_shared_state", lambda force=False: None)
    monkeypatch.setitem(llm._state, "enabled", True)
    monkeypatch.setitem(llm._state, "provider", "claude")
    with audit.actor_scope(audit.Actor("otto", "operator", "10.0.0.5")):
        assert llm.query("sys", "neighbor 10.1.1.1 down") == "answer"
    row = audit.query(action="llm.query")[0]
    assert row["actor"] == "otto" and row["target"] == "claude" and row["detail"]["cloud"] is True
    assert "10.1.1.1" not in json.dumps(row)                 # sizes and counts only, never content
    # Local providers are not external egress: not audited unless AUDIT_LLM=all.
    monkeypatch.setitem(llm._state, "provider", "ollama")
    llm.query("sys", "x")
    assert len(audit.query(action="llm.query")) == 1
    monkeypatch.setenv("AI_LOG_ANALYZER_AUDIT_LLM", "all")
    llm.query("sys", "x")
    assert audit.query(action="llm.query")[0]["target"] == "ollama"


def test_audit_is_a_noop_without_a_store():
    assert audit.record("x") is None and audit.query() == []
    assert audit.verify()["ok"] is False


# ── incident resolution + retrieval routes ──────────────────────────────────

def test_operator_resolves_incident_and_resolution_is_attributed(client, state):
    from ai_log_analyzer.memory import SqliteIncidentStore
    SqliteIncidentStore(state).record([{"description": "BGP hold timer expired", "devices": ["edge-01"]}], "t")
    r = client.post("/api/incidents/INC-000001/resolve", json={"resolution": "replaced optic"}, headers=_h(OPER))
    assert r.status_code == 200 and r.get_json()["incident"]["resolved_by"] == "otto"
    assert client.post("/api/incidents/INC-000001/resolve", json={"resolution": "x"},
                       headers=_h(VIEW)).status_code == 403
    assert client.post("/api/incidents/INC-999999/resolve", json={"resolution": "x"},
                       headers=_h(OPER)).status_code == 404


def test_rag_routes_roles(client):
    assert client.post("/api/rag/reindex", json={}, headers=_h(OPER)).status_code == 403
    r = client.post("/api/rag/reindex", json={}, headers=_h(ADMIN))
    assert r.status_code == 200 and r.get_json()["stats"]["documents"] > 0
    hits = client.get("/api/rag/search?q=bgp+neighbor+remote-as&k=3", headers=_h(VIEW)).get_json()["hits"]
    assert hits and hits[0]["id"] == "S1" and hits[0]["citation"]
    drift = client.post("/api/rag/drift", json={"running": "a\nb\n", "golden": "a\nc\n"}, headers=_h(OPER))
    assert drift.get_json()["drifted"] is True


def test_triage_worker_control_is_admin_only(client):
    assert client.post("/api/triage/stream/tick", headers=_h(OPER)).status_code == 403
    r = client.post("/api/triage/stream/tick", headers=_h(ADMIN))
    assert r.status_code == 200 and r.get_json()["role"] in ("active", "standby")
    from ai_log_analyzer.triage_worker import reset_worker
    reset_worker()


def test_query_string_tokens_only_work_for_the_sse_tail(client):
    assert client.get(f"/api/incidents/similar?q=bgp&token={ADMIN}").status_code == 401
    assert client.get(f"/api/tail/nope?token={ADMIN}").status_code == 404


def test_a_crashing_privileged_route_is_still_audited(client):
    with patch.object(web_app.network_tool, "is_available", side_effect=RuntimeError("boom")):
        with pytest.raises(RuntimeError):
            client.post("/api/run", json={"hostname": "r1", "command": "show clock"}, headers=_h(ADMIN))
    row = next(r for r in audit.query(limit=5) if r["action"] == "run.command")
    assert row["outcome"] == "http_500" and row["actor"] == "ada"
