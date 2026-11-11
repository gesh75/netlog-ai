"""Tests for the P4 /api/metrics Prometheus endpoint."""
from __future__ import annotations

import pytest

import ai_log_analyzer.web.app as web_app
from ai_log_analyzer import llm, metrics
from ai_log_analyzer.state_store import open_db
from ai_log_analyzer.web.app import create_app


@pytest.fixture(autouse=True)
def _reset_metrics():
    metrics.reset()
    yield
    metrics.reset()


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(web_app, "API_TOKEN", "")
    monkeypatch.setenv("AI_LOG_ANALYZER_STATE_DB", str(tmp_path / "state.db"))
    open_db(tmp_path / "state.db")
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


# ── render(): exposition format ──────────────────────────────────────────

def test_render_emits_help_type_and_samples():
    body = metrics.render(
        version="2.2.0",
        spool=[{"source": "syslog-1", "rows": 42}],
        drops={"sources": [{"source": "syslog-1", "udp_drops": 3, "spool_lines_lost": 1,
                            "queue_overflow": 0, "dropped_oversize": 0, "total": 4,
                            "warning": True, "message": "x"}]},
        listeners=[{"id": "syslog-1", "received": 1000}],
        llm_state={"enabled": True, "last_call": {"ok": True}},
        now=1000.0,
    )
    assert "# HELP netlog_spool_rows " in body
    assert "# TYPE netlog_spool_rows gauge" in body
    assert 'netlog_spool_rows{source="syslog-1"} 42' in body
    assert 'netlog_spool_rows_total 42' in body
    assert 'netlog_dropped_datagrams_total{source="syslog-1",reason="udp_drops"} 3' in body
    assert 'netlog_dropped_datagrams_total{source="syslog-1",reason="spool_lines_lost"} 1' in body
    assert 'netlog_ingested_datagrams_total{source="syslog-1"} 1000' in body
    assert 'netlog_llm_enabled 1' in body
    assert 'netlog_llm_last_call_ok 1' in body
    assert 'netlog_build_info{version="2.2.0"} 1' in body
    # No EPS gauge on the first scrape: no previous sample, never a fake 0.
    assert "netlog_events_per_second" not in body
    # Every line is a comment, a HELP/TYPE line, or "name{labels} value".
    for line in body.splitlines():
        assert line.startswith("#") or " " in line, line


def test_render_eps_needs_two_samples():
    first = metrics.render(version="2.2.0",
                           listeners=[{"id": "s1", "received": 100}],
                           now=1000.0)
    assert "netlog_events_per_second" not in first
    second = metrics.render(version="2.2.0",
                            listeners=[{"id": "s1", "received": 160}],
                            now=1010.0)
    assert 'netlog_events_per_second{source="s1"} 6' in second


def test_render_omits_unavailable_sources():
    body = metrics.render(version="2.2.0")
    assert "netlog_spool_rows" not in body
    assert "netlog_dropped_datagrams_total" not in body
    assert "netlog_ingested_datagrams_total" not in body
    assert "netlog_llm_enabled" not in body
    # Counters with no observations yet still render as 0 — they exist.
    assert "netlog_analysis_runs_total 0" in body
    assert "netlog_llm_calls_total" not in body  # no providers observed yet


def test_render_escapes_label_values():
    body = metrics.render(
        version='2.2.0"\\n',
        spool=[{"source": 'we"ird\nname', "rows": 1}],
        now=1000.0,
    )
    assert 'netlog_spool_rows{source="we\\"ird\\nname"} 1' in body
    assert 'netlog_build_info{version="2.2.0\\"\\\\n"} 1' in body


def test_observe_functions_feed_render():
    metrics.observe_llm_call("ollama", 0.5, True)
    metrics.observe_llm_call("ollama", 1.5, False)
    metrics.observe_llm_call("claude", 2.0, True)
    metrics.observe_analysis(3.25)
    body = metrics.render(version="2.2.0")
    assert 'netlog_llm_calls_total{provider="ollama",status="ok"} 1' in body
    assert 'netlog_llm_calls_total{provider="ollama",status="error"} 1' in body
    assert 'netlog_llm_calls_total{provider="claude",status="ok"} 1' in body
    assert 'netlog_llm_call_seconds_total{provider="ollama"} 2' in body
    assert 'netlog_llm_call_seconds_total{provider="claude"} 2' in body
    assert "netlog_analysis_runs_total 1" in body
    assert "netlog_analysis_seconds_total 3.25" in body


# ── Endpoint ───────────────────────────────────────────────────────────

@pytest.mark.unit
def test_metrics_endpoint_returns_prometheus_text(client):
    resp = client.get("/api/metrics")
    assert resp.status_code == 200
    assert "text/plain" in resp.content_type
    assert "version=0.0.4" in resp.content_type
    body = resp.get_data(as_text=True)
    for name in ("netlog_build_info", "netlog_spool_rows_total",
                 "netlog_analysis_runs_total", "netlog_uptime_seconds"):
        assert name in body, name


@pytest.mark.unit
def test_metrics_endpoint_reflects_spool_and_drops(client, tmp_path):
    from ai_log_analyzer.state_store import get_state_db

    db = get_state_db()
    assert db is not None
    db.spool_append("syslog-1", [(1700000000.0, "h1", "test line")], cap=1000)
    db.backpressure_report("syslog-1", {"udp_drops": 7, "spool_lines_lost": 0,
                                        "queue_overflow": 0, "dropped_oversize": 0})
    body = client.get("/api/metrics").get_data(as_text=True)
    assert 'netlog_spool_rows{source="syslog-1"} 1' in body
    assert ('netlog_dropped_datagrams_total{source="syslog-1",reason="udp_drops"} 7'
            in body)


@pytest.mark.unit
def test_metrics_endpoint_requires_viewer_role_when_auth_on(client, monkeypatch):
    monkeypatch.setattr(web_app, "API_TOKEN", "a-very-long-test-token-123")
    resp = client.get("/api/metrics")
    assert resp.status_code in (401, 403)


@pytest.fixture
def _llm_isolated(monkeypatch):
    """Isolated LLM gateway state with faked providers (mirrors test_llm_gateway)."""
    import copy

    snap = copy.deepcopy(llm._state)
    llm._state.update({
        "enabled": True,
        "provider": "ollama",
        "anthropic_api_key": "<redacted>",
        "xai_api_key": "xai-test-never-real",
        "allow_cloud_fallback": False,
        "tokenize_hostnames": "auto",
        "last_errors": {},
    })
    monkeypatch.setattr(llm, "_sleep", lambda _s: None)
    yield
    llm._state.clear()
    llm._state.update(snap)


# ── LLM hook: a real query records latency + outcome ───────────────────

@pytest.mark.unit
def test_llm_query_records_call_metrics(monkeypatch, _llm_isolated):
    from tests.test_llm_gateway import _Recorder

    rec = _Recorder(monkeypatch, {"ollama": "answer", "local": None})
    assert llm.query("sys", "user") == "answer"
    assert rec.providers == ["ollama"]
    body = metrics.render(version="2.2.0")
    assert 'netlog_llm_calls_total{provider="ollama",status="ok"} 1' in body
    assert 'netlog_llm_call_seconds_total{provider="ollama"}' in body


@pytest.mark.unit
def test_llm_query_records_failed_call(monkeypatch, _llm_isolated):
    from tests.test_llm_gateway import _Recorder

    rec = _Recorder(monkeypatch, {"ollama": None, "local": None})
    assert llm.query("sys", "user") is None
    assert rec.providers == ["ollama", "local"]
    body = metrics.render(version="2.2.0")
    assert 'netlog_llm_calls_total{provider="ollama",status="error"} 1' in body
    assert 'netlog_llm_calls_total{provider="local",status="error"} 1' in body
