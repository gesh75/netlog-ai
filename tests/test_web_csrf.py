"""Cross-site request forgery (CWE-352): with auth off nothing tells a cross-site browser request apart from
a dashboard request, and routes that work with an empty body could be forged by any web page.

Every state-changing request (POST/PUT/PATCH/DELETE) must carry something a cross-site "simple" request
cannot: a JSON content type, a custom header, or the API token header. GET never changes state."""
from __future__ import annotations

from pathlib import Path

import pytest

import ai_log_analyzer.web.app as web_app
from ai_log_analyzer import llm
from ai_log_analyzer.web.app import create_app

STATIC = Path(web_app.__file__).parent / "static"
TOKEN = "t0ken-0123456789-abcdef"


class _Worker:
    def __init__(self):
        self.calls: list[str] = []

    def start(self):
        self.calls.append("start")
        return True

    def stop(self):
        self.calls.append("stop")

    def run_once(self):
        self.calls.append("tick")
        return {"ok": True}

    def status(self):
        return {"running": False}


@pytest.fixture
def worker(monkeypatch):
    w = _Worker()
    monkeypatch.setattr("ai_log_analyzer.triage_worker.get_worker", lambda *a, **k: w)
    return w


@pytest.fixture
def dev(monkeypatch):
    """Auth off: the case a hostile web page can reach from the engineer's own browser."""
    monkeypatch.setattr(web_app, "API_TOKEN", "")
    llm.set_enabled(False)
    yield create_app().test_client()
    llm.set_enabled(True)


# What a hostile page can send without a preflight: no body, or a "simple" content type.
_SIMPLE = [
    {},
    {"data": "enabled=true", "content_type": "application/x-www-form-urlencoded"},
    {"data": '{"enabled": true}', "content_type": "text/plain"},
    {"data": '{"enabled": true}', "content_type": "text/plain;charset=UTF-8"},
    {"data": {"enabled": "true"}, "content_type": "multipart/form-data"},
]
_IDS = ["no-body", "form", "text-plain", "text-plain-charset", "multipart"]

_FORGEABLE = [
    ("post", "/api/llm/toggle"),
    ("post", "/api/triage/stream/start"),
    ("post", "/api/triage/stream/stop"),
    ("post", "/api/triage/stream/tick"),
    ("post", "/api/rag/reindex"),
    ("post", "/api/sources/orion/analyze"),
    ("post", "/api/sources/orion/test"),
    ("post", "/api/sources/orion/fetch"),
    ("post", "/api/correlate"),
    ("post", "/api/incidents/abc/resolve"),
    ("delete", "/api/sources/orion"),
    ("put", "/api/llm/toggle"),
    ("patch", "/api/llm/toggle"),
]


@pytest.mark.parametrize("kw", _SIMPLE, ids=_IDS)
@pytest.mark.parametrize("method,path", _FORGEABLE)
def test_a_cross_site_style_request_is_refused(dev, worker, method, path, kw):
    r = getattr(dev, method)(path, headers={"Origin": "https://evil.example"}, **kw)
    assert r.status_code == 403, (method, path, r.status_code)
    assert "cross-site" in r.get_json()["error"]


def test_forged_requests_change_no_state(dev, worker):
    for path in ("/api/triage/stream/start", "/api/triage/stream/stop", "/api/triage/stream/tick"):
        dev.post(path, headers={"Origin": "https://evil.example"})
    dev.post("/api/llm/toggle", data="enabled=true", content_type="application/x-www-form-urlencoded")
    assert worker.calls == []
    assert llm.get_state()["enabled"] is False


def test_the_dashboards_own_requests_still_work(dev, worker):
    assert dev.post("/api/llm/toggle", json={"enabled": True}).status_code == 200      # JSON content type
    assert llm.get_state()["enabled"] is True
    assert dev.post("/api/triage/stream/stop", json={}).status_code == 200
    r = dev.post("/api/triage/stream/start", headers={"X-Requested-With": "netlog-ai"})   # custom header
    assert r.status_code == 200 and worker.calls == ["stop", "start"]
    assert dev.post("/api/triage/stream/tick", data="{}", content_type="application/json").status_code == 200
    assert dev.post("/api/rag/reindex", headers={"X-Requested-With": "x"}).status_code == 400   # past the guard


def test_a_json_vendor_content_type_counts_as_json(dev, worker):
    r = dev.post("/api/triage/stream/stop", data="{}", content_type="application/vnd.api+json")
    assert r.status_code == 200


def test_reads_are_never_blocked(dev):
    assert dev.get("/api/health").status_code == 200
    assert dev.get("/api/whoami").status_code == 200
    assert dev.options("/api/llm/toggle", headers={"Origin": "http://localhost:6060",
                                                   "Access-Control-Request-Method": "POST"}).status_code == 200


def test_a_hostile_origin_gets_no_cors_grant_for_the_preflight(dev):
    r = dev.options("/api/llm/toggle", headers={"Origin": "https://evil.example",
                                                "Access-Control-Request-Method": "POST",
                                                "Access-Control-Request-Headers": "content-type"})
    assert "Access-Control-Allow-Origin" not in r.headers


def test_no_route_changes_state_on_get(dev):
    unsafe = {"POST", "PUT", "PATCH", "DELETE"}
    for rule in dev.application.url_map.iter_rules():
        if rule.endpoint != "static" and "GET" in rule.methods:
            assert not (rule.methods & unsafe), f"{rule.rule} answers GET and {rule.methods & unsafe}"


# ── auth on: the token header is the proof; tokenless stays a plain 401 ─────

@pytest.fixture
def authed(monkeypatch):
    monkeypatch.setattr(web_app, "API_TOKEN", TOKEN)
    yield create_app().test_client()
    llm.set_enabled(True)


def test_with_auth_on_a_tokenless_request_is_401_not_403(authed):
    assert authed.post("/api/llm/toggle").status_code == 401
    assert authed.post("/api/llm/toggle", data="enabled=true",
                       content_type="application/x-www-form-urlencoded").status_code == 401


def test_with_auth_on_a_token_header_is_accepted_without_a_body(authed, worker):
    for headers in ({"Authorization": f"Bearer {TOKEN}"}, {"X-API-Token": TOKEN}):
        assert authed.post("/api/triage/stream/stop", headers=headers).status_code == 200
    assert worker.calls == ["stop", "stop"]


# ── the bundled front end ───────────────────────────────────────────────────

def test_the_dashboard_marks_every_state_changing_api_call():
    v2 = (STATIC / "v2.js").read_text(encoding="utf-8")
    assert "X-Requested-With" in v2
    assert "GET" in v2[v2.index("X-Requested-With") - 700:v2.index("X-Requested-With") + 100]
