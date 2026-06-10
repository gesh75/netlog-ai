"""Webhook notifications: threshold logic, payload shapes, delivery behavior,
and the /api/analyze integration. Delivery must be best-effort — a dead
webhook can never break an analysis response.
"""
from __future__ import annotations

import pytest
import requests

from ai_log_analyzer import webhooks

RESULT = {
    "score": 62,
    "grade": "C",
    "severity_counts": {"critical": 1, "high": 3, "medium": 5, "low": 2, "info": 90},
    "action_items": [
        {"severity": "critical", "category": "system", "description": "Kernel panic on fw-01",
         "count": 1, "devices": ["fw-01"], "sample_messages": ["..."], "deep_analysis": {}},
        {"severity": "high", "category": "routing", "description": "BGP peer down",
         "count": 3, "devices": ["rt-01", "rt-02"], "sample_messages": ["..."], "deep_analysis": {}},
    ],
    "generated_at": "2026-06-10 12:00:00 UTC",
}

QUIET = {"score": 98, "grade": "A", "generated_at": "",
         "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 1, "info": 50},
         "action_items": []}


# ── threshold ────────────────────────────────────────────────────────────────

@pytest.mark.unit
@pytest.mark.parametrize("min_sev,expected", [
    ("critical", True), ("high", True), ("medium", True), ("low", True),
])
def test_should_notify_thresholds_alerting_result(min_sev, expected):
    assert webhooks.should_notify(RESULT["severity_counts"], min_sev) is expected


@pytest.mark.unit
def test_should_notify_quiet_result():
    assert webhooks.should_notify(QUIET["severity_counts"], "high") is False
    assert webhooks.should_notify(QUIET["severity_counts"], "low") is True  # 1 low


# ── payloads ─────────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_generic_payload_shape():
    p = webhooks.build_payload(RESULT, "raw", "generic", "high")
    assert p["source"] == "netlog-ai"
    assert p["event"] == "analysis_completed"
    assert p["input"] == "raw"
    assert p["score"] == 62
    assert len(p["action_items"]) == 2
    assert p["action_items"][0]["description"] == "Kernel panic on fw-01"
    assert "sample_messages" not in p["action_items"][0]  # payload stays lean


@pytest.mark.unit
def test_slack_payload_shape():
    p = webhooks.build_payload(RESULT, "syslog", "slack", "high")
    assert set(p) == {"text"}
    assert "netlog-ai" in p["text"]
    assert "1 critical" in p["text"] and "3 high" in p["text"]
    assert "BGP peer down" in p["text"]
    assert "medium" not in p["text"].split("\n")[0]  # below threshold not in headline


# ── delivery ─────────────────────────────────────────────────────────────────

class _Resp:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


@pytest.mark.unit
def test_notify_unconfigured_is_noop(monkeypatch):
    monkeypatch.delenv("AI_LOG_ANALYZER_WEBHOOK_URL", raising=False)
    called = []
    monkeypatch.setattr(webhooks.requests, "post", lambda *a, **k: called.append(a))
    assert webhooks.notify_analysis(RESULT, "raw") is False
    assert not called


@pytest.mark.unit
def test_notify_below_threshold_is_noop(monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_WEBHOOK_URL", "http://hook.example/x")
    monkeypatch.setenv("AI_LOG_ANALYZER_WEBHOOK_MIN_SEVERITY", "high")
    called = []
    monkeypatch.setattr(webhooks.requests, "post", lambda *a, **k: called.append(a))
    assert webhooks.notify_analysis(QUIET, "raw") is False
    assert not called


@pytest.mark.unit
def test_notify_posts_and_succeeds(monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_WEBHOOK_URL", "http://hook.example/x")
    captured: dict = {}

    def fake_post(url, json=None, timeout=None):
        captured.update(url=url, json=json, timeout=timeout)
        return _Resp(200)

    monkeypatch.setattr(webhooks.requests, "post", fake_post)
    assert webhooks.notify_analysis(RESULT, "raw") is True
    assert captured["url"] == "http://hook.example/x"
    assert captured["json"]["severity_counts"]["critical"] == 1
    assert captured["timeout"] == webhooks._TIMEOUT_S


@pytest.mark.unit
def test_notify_swallows_network_errors(monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_WEBHOOK_URL", "http://hook.example/x")

    def boom(*a, **k):
        raise requests.ConnectionError("refused")

    monkeypatch.setattr(webhooks.requests, "post", boom)
    assert webhooks.notify_analysis(RESULT, "raw") is False  # no exception


@pytest.mark.unit
def test_notify_treats_http_error_as_failure(monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_WEBHOOK_URL", "http://hook.example/x")
    monkeypatch.setattr(webhooks.requests, "post", lambda *a, **k: _Resp(500))
    assert webhooks.notify_analysis(RESULT, "raw") is False


@pytest.mark.unit
def test_invalid_config_falls_back(monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_WEBHOOK_URL", "http://hook.example/x")
    monkeypatch.setenv("AI_LOG_ANALYZER_WEBHOOK_MIN_SEVERITY", "bogus")
    monkeypatch.setenv("AI_LOG_ANALYZER_WEBHOOK_FORMAT", "carrier-pigeon")
    url, min_sev, fmt = webhooks._config()
    assert (min_sev, fmt) == ("high", "generic")


# ── integration: /api/analyze fires the webhook ─────────────────────────────

@pytest.mark.unit
def test_api_analyze_triggers_webhook(monkeypatch, tmp_path):
    import ai_log_analyzer.web.app as web_app
    from ai_log_analyzer.web.app import create_app

    monkeypatch.setenv("AI_LOG_ANALYZER_WEBHOOK_URL", "http://hook.example/x")
    monkeypatch.setenv("AI_LOG_ANALYZER_WEBHOOK_MIN_SEVERITY", "high")
    monkeypatch.setattr(web_app, "FILE_ROOTS", [tmp_path])
    captured: list = []
    monkeypatch.setattr(webhooks.requests, "post",
                        lambda *a, **k: captured.append(k) or _Resp(200))

    log = tmp_path / "burst.log"
    log.write_text(
        "Jan  1 00:00:01 rt-01 rpd[11]: bgp peer 192.0.2.1 down hold timer expired\n"
        "Jan  1 00:00:02 rt-01 kernel: kernel panic - not syncing\n"
    )
    app = create_app()
    app.config.update(TESTING=True)
    r = app.test_client().post(
        "/api/analyze", json={"source": "file", "path": str(log), "use_llm": False})
    assert r.status_code == 200
    assert len(captured) == 1
    assert captured[0]["json"]["input"] == "file"
