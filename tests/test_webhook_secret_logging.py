"""A webhook failure must not write the destination URL to the logs (CWE-532).

For Slack, Discord and Teams incoming webhooks the URL path (or a ``sig`` query value) IS the credential.
Failure logging keeps scheme and host and the failure class or status, never the path, query or userinfo.
"""
from __future__ import annotations

import logging

import pytest
import requests

from ai_log_analyzer import webhooks

pytestmark = pytest.mark.unit

SECRET = "S3cr3tExampleOnly"
RESULT = {"severity_counts": {"critical": 2}, "score": 10, "grade": "F", "action_items": []}
SLACK = f"https://hooks.example.com/services/T000/B000/{SECRET}"
TEAMS = f"https://flows.example.com:443/workflows/abc/triggers/manual/paths/invoke?api-version=1&sig={SECRET}"
USERINFO = f"https://svc:{SECRET}@hooks.example.com/x"


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch):
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AI_LOG_ANALYZER_WEBHOOK_FORMAT", "slack")


def _everything(caplog) -> str:
    return "\n".join(f"{r.name} {r.getMessage()} {r.exc_text or ''}" for r in caplog.records)


class _Resp:
    def __init__(self, status: int) -> None:
        self.status_code = status


@pytest.mark.parametrize("url", [SLACK, TEAMS, USERINFO])
@pytest.mark.parametrize("status", [400, 404, 429, 500])
def test_a_non_2xx_answer_logs_the_host_and_status_not_the_url(
        monkeypatch: pytest.MonkeyPatch, caplog, url: str, status: int) -> None:
    monkeypatch.setenv("AI_LOG_ANALYZER_WEBHOOK_URL", url)
    monkeypatch.setattr(webhooks.requests, "post", lambda *a, **k: _Resp(status))
    with caplog.at_level(logging.DEBUG):
        assert webhooks.notify_analysis(RESULT, "src") is False
    text = _everything(caplog)
    assert SECRET not in text and "/services" not in text and "T000" not in text, text
    assert "hooks.example.com" in text or "flows.example.com" in text
    assert str(status) in text


@pytest.mark.parametrize("url", [SLACK, TEAMS, USERINFO])
def test_a_transport_error_logs_no_path_query_or_userinfo(
        monkeypatch: pytest.MonkeyPatch, caplog, url: str) -> None:
    monkeypatch.setenv("AI_LOG_ANALYZER_WEBHOOK_URL", url)
    path = url.split("://", 1)[1].split("@")[-1].split("/", 1)[1]

    def boom(*_a, **_k):
        raise requests.exceptions.ConnectionError(
            f"HTTPSConnectionPool(host='hooks.example.com', port=443): Max retries exceeded with url: "
            f"/{path} (Caused by NameResolutionError(\"Failed to resolve 'hooks.example.com'\"))")

    monkeypatch.setattr(webhooks.requests, "post", boom)
    with caplog.at_level(logging.DEBUG):
        assert webhooks.notify_analysis(RESULT, "src") is False
    text = _everything(caplog)
    assert SECRET not in text and "T000" not in text and "B000" not in text and "sig=" not in text, text
    assert "ConnectionError" in text or "NameResolutionError" in text   # still says what went wrong


def test_a_real_connection_error_to_a_secret_path_is_not_logged(
        monkeypatch: pytest.MonkeyPatch, caplog) -> None:
    """The text urllib3 builds for a refused connection really does carry the path."""
    url = f"http://127.0.0.1:1/services/T000/B000/{SECRET}?token={SECRET}"
    monkeypatch.setenv("AI_LOG_ANALYZER_WEBHOOK_URL", url)
    with pytest.raises(requests.exceptions.ConnectionError) as raw:
        requests.post(url, json={}, timeout=2)
    assert SECRET in str(raw.value)                                   # the assumption behind the fix
    with caplog.at_level(logging.DEBUG):
        assert webhooks.notify_analysis(RESULT, "src") is False
    text = _everything(caplog)
    assert SECRET not in text and "/services" not in text and "token=" not in text, text
    assert "127.0.0.1" in text


def test_the_failure_is_not_chained_into_a_logged_traceback(
        monkeypatch: pytest.MonkeyPatch, caplog) -> None:
    monkeypatch.setenv("AI_LOG_ANALYZER_WEBHOOK_URL", SLACK)
    monkeypatch.setattr(webhooks.requests, "post", lambda *a, **k: (_ for _ in ()).throw(
        requests.exceptions.ConnectTimeout(f"Max retries exceeded with url: /services/T000/B000/{SECRET}")))
    with caplog.at_level(logging.DEBUG):
        webhooks.notify_analysis(RESULT, "src")
    assert all(r.exc_info is None for r in caplog.records)
    assert SECRET not in _everything(caplog)


def test_delivery_still_works_and_returns_true_on_2xx(monkeypatch: pytest.MonkeyPatch, caplog) -> None:
    monkeypatch.setenv("AI_LOG_ANALYZER_WEBHOOK_URL", SLACK)
    seen = {}
    monkeypatch.setattr(webhooks.requests, "post",
                        lambda url, **k: seen.update(url=url) or _Resp(200))
    with caplog.at_level(logging.DEBUG):
        assert webhooks.notify_analysis(RESULT, "src") is True
    assert seen["url"] == SLACK                                       # the real URL is still what is posted
    assert SECRET not in _everything(caplog)
