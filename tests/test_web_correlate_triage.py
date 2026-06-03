"""Route-wrapper tests for /api/correlate and /api/triage.

These exercise the thin Flask wrappers (body parsing, validation, envelope
pass-through, error status codes) with the backend correlate/triage functions
mocked — no live SourceManager is touched.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from ai_log_analyzer.web.app import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


_CORRELATE_OK = {
    "ok": True,
    "source_ids": [],
    "device_count": 0,
    "confirmed_count": 0,
    "suspected_count": 0,
    "confirmed": [],
    "suspected": [],
    "devices": [],
    "skipped": {},
}

_TRIAGE_OK = {
    "ok": True,
    "hostname": "r1",
    "total_events": 0,
    "severity_dist": {},
    "processes": [],
    "patterns": [],
    "verdict": "INFORMATIONAL",
    "issue_type": "info",
    "health_score": 100,
    "top_process": "",
    "sources": [],
    "skipped": {},
}


# ── /api/correlate ───────────────────────────────────────────────────────────

@pytest.mark.unit
def test_correlate_empty_body_uses_all_sources(client):
    with patch("ai_log_analyzer.web.app.correlate_from_manager",
               return_value=dict(_CORRELATE_OK)) as mock:
        resp = client.post("/api/correlate", json={})
    assert resp.status_code == 200
    mock.assert_called_once()
    args, kwargs = mock.call_args
    assert args[0] is None
    assert kwargs["since_seconds"] == 3600
    assert kwargs["min_severity"] == "medium"
    assert resp.get_json()["ok"] is True


@pytest.mark.unit
def test_correlate_passes_source_ids_and_minsev(client):
    with patch("ai_log_analyzer.web.app.correlate_from_manager",
               return_value=dict(_CORRELATE_OK)) as mock:
        resp = client.post("/api/correlate", json={
            "source_ids": ["kibana", "librenms"],
            "min_severity": "high",
            "since_seconds": 600,
        })
    assert resp.status_code == 200
    args, kwargs = mock.call_args
    assert args[0] == ["kibana", "librenms"]
    assert kwargs["since_seconds"] == 600
    assert kwargs["min_severity"] == "high"


@pytest.mark.unit
def test_correlate_bad_min_severity_returns_400(client):
    with patch("ai_log_analyzer.web.app.correlate_from_manager",
               side_effect=ValueError("Unknown min_severity 'bogus'.")):
        resp = client.post("/api/correlate", json={"min_severity": "bogus"})
    assert resp.status_code == 400
    body = resp.get_json()
    assert body["ok"] is False
    assert "Unknown" in body["error"]


@pytest.mark.unit
def test_correlate_non_list_source_ids_coerced_to_none(client):
    with patch("ai_log_analyzer.web.app.correlate_from_manager",
               return_value=dict(_CORRELATE_OK)) as mock:
        resp = client.post("/api/correlate", json={"source_ids": "kibana"})
    assert resp.status_code == 200
    args, _ = mock.call_args
    assert args[0] is None


@pytest.mark.unit
def test_correlate_envelope_passthrough(client):
    full = dict(_CORRELATE_OK)
    full.update(confirmed_count=2, suspected_count=1)
    with patch("ai_log_analyzer.web.app.correlate_from_manager",
               return_value=full):
        resp = client.post("/api/correlate", json={})
    assert resp.status_code == 200
    assert resp.get_json() == full


# ── /api/triage ──────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_triage_missing_hostname_returns_400(client):
    resp = client.post("/api/triage", json={})
    assert resp.status_code == 400
    assert resp.get_json() == {"ok": False, "error": "hostname required"}


@pytest.mark.unit
def test_triage_blank_hostname_returns_400(client):
    resp = client.post("/api/triage", json={"hostname": "   "})
    assert resp.status_code == 400
    assert resp.get_json()["ok"] is False


@pytest.mark.unit
def test_triage_calls_backend_with_defaults(client):
    with patch("ai_log_analyzer.web.app.triage_from_manager",
               return_value=dict(_TRIAGE_OK)) as mock:
        resp = client.post("/api/triage", json={"hostname": "r1"})
    assert resp.status_code == 200
    args, kwargs = mock.call_args
    assert args[0] == "r1"
    assert args[1] is None
    assert kwargs["since_seconds"] == 86_400
    assert kwargs["limit"] == 5000
    assert resp.get_json()["ok"] is True


@pytest.mark.unit
def test_triage_passes_source_ids_and_window(client):
    with patch("ai_log_analyzer.web.app.triage_from_manager",
               return_value=dict(_TRIAGE_OK)) as mock:
        resp = client.post("/api/triage", json={
            "hostname": "r1",
            "source_ids": ["kibana"],
            "since_seconds": 3600,
            "limit": 200,
        })
    assert resp.status_code == 200
    args, kwargs = mock.call_args
    assert args[1] == ["kibana"]
    assert kwargs["since_seconds"] == 3600
    assert kwargs["limit"] == 200


@pytest.mark.unit
def test_triage_envelope_passthrough(client):
    full = dict(_TRIAGE_OK)
    full.update(health_score=42, verdict="DEGRADED")
    with patch("ai_log_analyzer.web.app.triage_from_manager",
               return_value=full):
        resp = client.post("/api/triage", json={"hostname": "r1"})
    assert resp.status_code == 200
    assert resp.get_json() == full
