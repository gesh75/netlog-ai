"""Triage sink failures must not carry the webhook secret (CWE-209 / CWE-532).

``requests`` transport errors embed the request path and query, which for Slack-style webhooks is the
credential. The text is stored in the tick report, logged, audited and served by
``GET /api/triage/stream/status`` to the lowest role. It is redacted at the source, and the raw error
strings are admin-only in the API.
"""
from __future__ import annotations

import json
import logging

import pytest
import requests

import ai_log_analyzer.web.app as web_app
from ai_log_analyzer import audit
from ai_log_analyzer.state_store import StateDB
from ai_log_analyzer.triage_worker import MemorySink, StreamingTriageWorker, TriageConfig, WebhookSink

pytestmark = pytest.mark.unit

SECRET = "S3cr3tExampleOnly"
T0 = 1_800_000_000.0
CONSERVE = ('<185>date=2026-10-20 time=07:05:30 devname="FGT-BR-07" devid="FG60FTK21000007" tz="+0000" vd="root" '
            'logid="0100022011" type="event" subtype="system" level="critical" logdesc="Memory conserve mode entered" '
            'msg="Kernel enters memory conserve mode"')
SLACK_PATH = f"/services/T000/B000/{SECRET}"


@pytest.fixture(autouse=True)
def _no_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_STATE_DB", str(tmp_path / "state.db"))
    return StateDB(tmp_path / "state.db")


def _worker(db, *sinks):
    return StreamingTriageWorker(db, list(sinks), TriageConfig(), clock=lambda: T0, owner="t")


def _tick(db, *sinks):
    db.spool_append("syslog-1", [(T0, "10.9.9.9", CONSERVE)], cap=1000)
    w = _worker(db, *sinks)
    return w, w.run_once(T0)


class _Raises:
    name = "itsm"

    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    def upsert_incident(self, payload):
        raise self.exc


def _all(*parts) -> str:
    return json.dumps(parts, default=str)


def test_a_real_webhook_transport_error_is_stored_without_the_secret_path(db, caplog) -> None:
    sink = WebhookSink(f"http://127.0.0.1:1{SLACK_PATH}?token={SECRET}", "slack")
    caplog.set_level(logging.DEBUG)
    w, tick = _tick(db, sink, MemorySink())            # a second sink succeeds: the audit row is written
    assert len(tick["errors"]) == 1 and tick["errors"][0].startswith("webhook:")
    rows = audit.query(action="triage.ticket.*")
    assert rows and rows[0]["detail"]["errors"]
    blob = _all(tick, w.status(), rows, [r.getMessage() for r in caplog.records])
    assert SECRET not in blob and "T000" not in blob and "B000" not in blob and "token=" not in blob, blob


def test_the_webhook_sink_maps_transport_errors_to_a_fixed_message(monkeypatch) -> None:
    def boom(*_a, **_k):
        raise requests.exceptions.ConnectionError(f"Max retries exceeded with url: {SLACK_PATH}")

    monkeypatch.setattr(requests, "post", boom)
    sink = WebhookSink(f"https://hooks.example.com{SLACK_PATH}", "slack")
    with pytest.raises(RuntimeError) as exc:
        sink.upsert_incident(_payload())
    assert str(exc.value) == "webhook delivery failed: ConnectionError"
    assert exc.value.__cause__ is None and exc.value.__suppress_context__


def _payload():
    from ai_log_analyzer.itsm import IncidentEnrichmentPayload
    return IncidentEnrichmentPayload(
        site="s", root_device="leaf1", root_layer="L2", root_interface=None, summary_title="t",
        rca_rationale="r", confidence=0.9, affected_devices=["leaf1"])


@pytest.mark.parametrize("text", [
    f"HTTPSConnectionPool(host='hooks.example.com', port=443): Max retries exceeded with url: {SLACK_PATH} "
    "(Caused by NameResolutionError(\"x\"))",
    f"401 Client Error: Unauthorized for url: https://svc:{SECRET}@jira.example.com/rest/api/2/issue?api_key={SECRET}",
    f"Invalid URL 'https://svc:{SECRET}@': No host supplied",
])
def test_any_sink_error_text_is_redacted_before_it_is_stored(db, caplog, text: str) -> None:
    caplog.set_level(logging.DEBUG)
    w, tick = _tick(db, _Raises(RuntimeError(text)), MemorySink())
    assert len(tick["errors"]) == 1 and tick["errors"][0].startswith("itsm:")
    blob = _all(tick, w.status(), audit.query(action="triage.ticket.*"), [r.getMessage() for r in caplog.records])
    assert SECRET not in blob and "T000" not in blob, blob


def test_the_error_keeps_its_diagnostic_value(db) -> None:
    _, tick = _tick(db, _Raises(ConnectionError("ITSM unreachable")))
    assert "ITSM unreachable" in tick["errors"][0]
    _, tick = _tick(db, _Raises(RuntimeError(f"webhook answered HTTP 429 for https://h.example.com{SLACK_PATH}")))
    assert "HTTP 429" in tick["errors"][0] and "h.example.com" in tick["errors"][0]


# ── GET /api/triage/stream/status ───────────────────────────────────────────

VIEW, OPER, ADMIN = "view-tok-0123456789", "oper-tok-0123456789", "admin-tok-0123456789"


def _client(monkeypatch, w):
    monkeypatch.setattr(web_app, "API_TOKEN", "")
    monkeypatch.setenv("AI_LOG_ANALYZER_VIEWER_TOKENS", f"vera:{VIEW}")
    monkeypatch.setenv("AI_LOG_ANALYZER_OPERATOR_TOKENS", f"otto:{OPER}")
    monkeypatch.setenv("AI_LOG_ANALYZER_ADMIN_TOKENS", f"ada:{ADMIN}")
    monkeypatch.setattr("ai_log_analyzer.triage_worker.get_worker", lambda *a, **k: w)
    return web_app.create_app().test_client()


def _h(tok: str) -> dict:
    return {"Authorization": f"Bearer {tok}"}


def test_viewers_and_operators_get_a_count_not_the_error_text(db, monkeypatch) -> None:
    w, tick = _tick(db, _Raises(RuntimeError(f"boom {SLACK_PATH}")))     # raw text, as a third-party sink might
    assert tick["errors"]
    c = _client(monkeypatch, w)
    for tok in (VIEW, OPER):
        body = c.get("/api/triage/stream/status", headers=_h(tok)).get_json()
        assert body["last_tick"]["errors"] == [] and body["last_tick"]["error_count"] == 1
        assert "boom" not in json.dumps(body) and SECRET not in json.dumps(body)
    assert w.last_tick["errors"], "the worker's own record is untouched"


def test_admins_still_see_the_redacted_error_strings(db, monkeypatch) -> None:
    w, _ = _tick(db, _Raises(ConnectionError("ITSM unreachable")))
    body = _client(monkeypatch, w).get("/api/triage/stream/status", headers=_h(ADMIN)).get_json()
    assert body["last_tick"]["errors"] == ["itsm: ITSM unreachable"]


def test_dev_mode_keeps_the_full_status(db, monkeypatch) -> None:
    w, _ = _tick(db, _Raises(ConnectionError("ITSM unreachable")))
    monkeypatch.setattr(web_app, "API_TOKEN", "")
    monkeypatch.setattr("ai_log_analyzer.triage_worker.get_worker", lambda *a, **k: w)
    body = web_app.create_app().test_client().get("/api/triage/stream/status").get_json()
    assert body["last_tick"]["errors"] == ["itsm: ITSM unreachable"]
