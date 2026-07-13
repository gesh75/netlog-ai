"""Security-gate tests: API-token enforcement, file-ingest path confinement,
and llm/status redaction for anonymous callers on tokened deployments.
"""
from __future__ import annotations

import pytest

import ai_log_analyzer.web.app as web_app
from ai_log_analyzer.web.app import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


# ──────────────────────────────────────────────────────────────────────────────
# require_api_token
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_token_unset_decorator_is_noop(client, monkeypatch):
    monkeypatch.setattr(web_app, "API_TOKEN", "")
    r = client.post("/api/llm/provider", json={})
    assert r.status_code != 401


@pytest.mark.unit
def test_token_set_rejects_missing_and_wrong_token(client, monkeypatch):
    monkeypatch.setattr(web_app, "API_TOKEN", "sekrit")
    assert client.post("/api/llm/provider", json={}).status_code == 401
    r = client.post("/api/llm/provider", json={},
                    headers={"X-API-Token": "wrong"})
    assert r.status_code == 401


@pytest.mark.unit
def test_token_set_accepts_correct_token(client, monkeypatch):
    monkeypatch.setattr(web_app, "API_TOKEN", "sekrit")
    r = client.post("/api/llm/provider", json={},
                    headers={"X-API-Token": "sekrit"})
    assert r.status_code != 401  # passes the gate; body validation may 400


@pytest.mark.unit
def test_token_accepts_authorization_bearer(client, monkeypatch):
    monkeypatch.setattr(web_app, "API_TOKEN", "sekrit")
    r = client.post("/api/llm/provider", json={},
                    headers={"Authorization": "Bearer sekrit"})
    assert r.status_code != 401
    r = client.post("/api/llm/provider", json={},
                    headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401


@pytest.mark.unit
def test_sources_test_and_fetch_require_token(client, monkeypatch):
    """/api/sources/<id>/test and /fetch were the only POST data routes
    missing the auth gate — regression check that they now enforce it."""
    monkeypatch.setattr(web_app, "API_TOKEN", "sekrit")
    assert client.post("/api/sources/x/test").status_code == 401
    assert client.post("/api/sources/x/fetch", json={}).status_code == 401
    assert client.post("/api/rules", json={}).status_code == 401


# ──────────────────────────────────────────────────────────────────────────────
# /api/analyze {source:"file"} path confinement
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_file_source_outside_roots_is_403(client, monkeypatch, tmp_path):
    monkeypatch.setattr(web_app, "FILE_ROOTS", [tmp_path / "allowed"])
    r = client.post("/api/analyze", json={"source": "file", "path": "/etc/hosts"})
    assert r.status_code == 403
    assert "allowed roots" in r.get_json()["error"]


@pytest.mark.unit
def test_file_source_inside_roots_is_served(client, monkeypatch, tmp_path):
    monkeypatch.setattr(web_app, "FILE_ROOTS", [tmp_path])
    log = tmp_path / "dev.log"
    log.write_text(
        "Jan  1 00:00:01 r1 rpd[123]: BGP_NEIGHBOR_DOWN: peer 192.0.2.1 down\n"
    )
    r = client.post("/api/analyze",
                    json={"source": "file", "path": str(log), "use_llm": False})
    assert r.status_code == 200
    assert len(r.get_json()["classified_events"]) >= 1


@pytest.mark.unit
def test_file_source_traversal_is_blocked(client, monkeypatch, tmp_path):
    monkeypatch.setattr(web_app, "FILE_ROOTS", [tmp_path / "allowed"])
    sneaky = str(tmp_path / "allowed" / ".." / "secret.log")
    r = client.post("/api/analyze", json={"source": "file", "path": sneaky})
    assert r.status_code == 403


# ──────────────────────────────────────────────────────────────────────────────
# /api/llm/status redaction
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_llm_status_hides_last_errors_from_anonymous_when_tokened(client, monkeypatch):
    monkeypatch.setattr(web_app, "API_TOKEN", "sekrit")
    state = client.get("/api/llm/status").get_json()
    assert "last_errors" not in state
    state = client.get("/api/llm/status",
                       headers={"X-API-Token": "sekrit"}).get_json()
    assert "last_errors" in state


@pytest.mark.unit
def test_llm_status_full_in_dev_mode(client, monkeypatch):
    monkeypatch.setattr(web_app, "API_TOKEN", "")
    state = client.get("/api/llm/status").get_json()
    assert "last_errors" in state
