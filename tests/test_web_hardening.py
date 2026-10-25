"""Web hardening: request-body flags, security headers, body-size cap, 401 auditing,
live-tail cursor / stream cap / sanitization, CDN pin, and the version badge."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

import ai_log_analyzer.web.app as web_app
from ai_log_analyzer import __version__, audit, site_doc
from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.state_store import open_db
from ai_log_analyzer.web.app import create_app

STATIC = Path(web_app.__file__).parent / "static"
TOKEN = "t0ken-0123456789-abcdef"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(web_app, "API_TOKEN", "")
    return create_app().test_client()


@pytest.fixture
def authed(monkeypatch):
    monkeypatch.setattr(web_app, "API_TOKEN", TOKEN)
    return create_app().test_client()


def _h(token: str = TOKEN) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ── E: request bodies cannot relax the SSRF guard or borrow server credentials ──

class _FakeSNow:
    kwargs: dict = {}

    def __init__(self, **kw):
        type(self).kwargs = kw

    def sync_incident(self, *a, **k):
        class _R:
            @staticmethod
            def to_dict():
                return {"ok": True}
        return _R()


def _sync(client, **extra):
    return client.post("/api/itsm/servicenow/sync", json={
        "instance_url": "https://10.0.0.5", "dry_run": True, "username": "u", "password": "p", **extra})


def test_servicenow_sync_ignores_allow_private_from_the_body(client, monkeypatch):
    monkeypatch.setattr(web_app, "ServiceNowClient", _FakeSNow)
    monkeypatch.delenv("AI_LOG_ANALYZER_ITSM_ALLOW_PRIVATE", raising=False)
    assert _sync(client, allow_private=True).status_code == 200
    assert _FakeSNow.kwargs["allow_private"] is False


def test_servicenow_sync_allow_private_is_admin_env_only(client, monkeypatch):
    monkeypatch.setattr(web_app, "ServiceNowClient", _FakeSNow)
    monkeypatch.setenv("AI_LOG_ANALYZER_ITSM_ALLOW_PRIVATE", "1")
    assert _sync(client).status_code == 200
    assert _FakeSNow.kwargs["allow_private"] is True


def test_servicenow_sync_private_instance_is_refused_for_body_flag(client):
    r = _sync(client, allow_private=True)         # the real client, dry-run: URL validated at construction
    assert r.status_code == 400


@pytest.mark.parametrize("system", ["jira", "servicenow"])
def test_itsm_enrich_never_sends_env_credentials_to_a_body_supplied_url(client, monkeypatch, system):
    from ai_log_analyzer import itsm
    for k, v in {"JIRA_URL": "https://jira.corp.test", "JIRA_EMAIL": "svc@corp.test", "JIRA_API_TOKEN": "env-secret",
                 "SERVICENOW_URL": "https://corp.service-now.test", "SERVICENOW_USER": "svc",
                 "SERVICENOW_PASSWORD": "env-secret"}.items():
        monkeypatch.setenv(k, v)

    def _boom(*a, **k):
        raise AssertionError(f"client built with {a!r} - env credentials leaked to a caller-chosen host")

    monkeypatch.setattr(itsm, "JiraITSMClient", _boom)
    monkeypatch.setattr(itsm, "ServiceNowITSMClient", _boom)
    r = client.post("/api/itsm/enrich", json={
        "system": system, "dry_run": False, "device": "r1", "vendor": "arista_eos",
        "root_cause_summary": "link down", "instance_url": "https://attacker.example"})
    assert r.status_code == 400 and "missing" in r.get_json()["error"]


def test_run_docker_exec_fallback_honours_the_disable_switch(client, monkeypatch):
    from ai_log_analyzer.adapters import network_tool as nt
    monkeypatch.setattr(nt, "is_available", lambda timeout=1.0: False)
    monkeypatch.setattr(web_app.frr, "is_lab_container", lambda _n: True)
    ran: list[int] = []
    monkeypatch.setattr(nt, "container_run", lambda *a, **k: ran.append(1))
    monkeypatch.setattr(nt, "DOCKER_EXEC_FALLBACK", False)
    r = client.post("/api/run", json={"hostname": "de-fra-core-01", "command": "show version"})
    assert r.status_code == 503 and ran == []


# ── G: headers, body cap ────────────────────────────────────────────────────

@pytest.mark.parametrize("path", [
    "/api/health", "/",
    pytest.param("/api/nope", marks=pytest.mark.skipif(not hasattr(web_app.Flask, "wsgi_app"),
                                                       reason="offline Flask shim skips hooks on 404")),
])
def test_security_headers_on_every_response(client, path):
    h = client.get(path).headers
    assert h.get("X-Content-Type-Options") == "nosniff"
    assert h.get("X-Frame-Options") == "DENY"
    assert h.get("Referrer-Policy") == "no-referrer"


def test_security_headers_on_a_401(authed):
    r = authed.get("/api/rules")
    assert r.status_code == 401 and r.headers.get("X-Content-Type-Options") == "nosniff"


def test_max_content_length_default_and_override(monkeypatch):
    monkeypatch.delenv("AI_LOG_ANALYZER_MAX_CONTENT_LENGTH", raising=False)
    assert create_app().config["MAX_CONTENT_LENGTH"] == 16 * 1024 * 1024
    monkeypatch.setenv("AI_LOG_ANALYZER_MAX_CONTENT_LENGTH", "4096")
    assert create_app().config["MAX_CONTENT_LENGTH"] == 4096


@pytest.mark.skipif(not hasattr(web_app.Flask, "wsgi_app"), reason="offline Flask shim does not enforce limits")
def test_oversized_body_is_a_json_413(monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_MAX_CONTENT_LENGTH", "1000")
    c = create_app().test_client()
    r = c.post("/api/sanitize-diff", json={"text": "x" * 5000})
    assert r.status_code == 413 and "too large" in r.get_json()["error"]


# ── G: failed authentication is audited, rate-limited ───────────────────────

@pytest.fixture
def audit_db(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_STATE_DB", str(tmp_path / "state.db"))
    audit._THROTTLE.clear()
    audit._THROTTLE_SUPPRESSED[0] = 0
    audit._THROTTLE_GLOBAL[:] = [0.0, 0]
    return open_db(tmp_path / "state.db")


def test_failed_auth_is_audited_once_per_window_with_a_suppressed_count(authed, audit_db):
    for _ in range(40):
        assert authed.get("/api/rules", headers=_h("wrong-token-0123456789")).status_code == 401
    rows = audit.query(action="authn.failed")
    assert len(rows) == 1                                   # a flood cannot bloat the log
    assert rows[0]["outcome"] == "unauthorized" and rows[0]["target"] == "/api/rules"
    assert "wrong-token" not in json.dumps(rows)            # never the credential itself
    audit._THROTTLE.clear()                                  # next window
    authed.get("/api/rules")
    rows = audit.query(action="authn.failed")
    assert len(rows) == 2 and rows[0]["detail"]["suppressed"] == 39


def test_sse_401_is_audited_and_missing_vs_invalid_is_recorded(authed, audit_db):
    assert authed.get("/api/tail/x").status_code == 401
    (row,) = audit.query(action="authn.failed")
    assert row["detail"]["token"] == "missing" and row["target"] == "/api/tail/x"


def test_forbidden_is_still_audited_unthrottled(monkeypatch, audit_db):
    monkeypatch.setattr(web_app, "API_TOKEN", "")
    monkeypatch.setenv("AI_LOG_ANALYZER_VIEWER_TOKENS", f"vera:{TOKEN}")
    c = create_app().test_client()
    for _ in range(3):
        assert c.post("/api/llm/toggle", json={}, headers=_h()).status_code == 403
    assert len(audit.query(action="authz.denied")) == 3


def test_audit_global_cap_bounds_a_spoofed_source_flood(audit_db):
    for i in range(audit._THROTTLE_GLOBAL_MAX + 50):
        audit.record_throttled("authn.failed", key=f"10.0.{i // 250}.{i % 250}")
    assert len(audit.query(action="authn.failed", limit=1000)) == audit._THROTTLE_GLOBAL_MAX


# ── G: live tail ────────────────────────────────────────────────────────────

class _FakeDB:
    def spool_max_id(self, name):
        return 42


class _FakeTail:
    name = "fake"

    def __init__(self, db=None, events=()):
        self._db = db
        self._total_ingested = 7
        self.cursors: list[int] = []
        self._events = list(events)

    def fetch_new(self, cursor, limit=1000):
        self.cursors.append(cursor)
        out, self._events = self._events, []
        return out, cursor + len(out)


def _tail(client, monkeypatch, src, query="poll=0.2"):
    monkeypatch.setattr(web_app.source_manager, "get", lambda sid: src if sid == "fake" else None)
    return client.get(f"/api/tail/fake?{query}", buffered=False)


def _frames(resp):
    for chunk in resp.response:
        yield chunk.decode() if isinstance(chunk, bytes) else chunk


def test_tail_in_spool_mode_starts_at_the_spool_max_id_not_the_ingest_counter(client, monkeypatch):
    ev = LogEvent("Jan  1 00:00:01", "r1", "rpd", "err", "BGP_NEIGHBOR_DOWN: neighbor 192.0.2.1 down")
    src = _FakeTail(db=_FakeDB(), events=[ev])
    resp = _tail(client, monkeypatch, src)
    frames = _frames(resp)
    assert "hello" in next(frames)
    assert next(f for f in frames if f.startswith("data: {"))
    assert src.cursors[0] == 42
    resp.close()


def test_tail_in_memory_mode_starts_at_the_ingest_counter(client, monkeypatch):
    ev = LogEvent("Jan  1 00:00:01", "r1", "rpd", "err", "BGP_NEIGHBOR_DOWN: neighbor 192.0.2.1 down")
    src = _FakeTail(db=None, events=[ev])
    resp = _tail(client, monkeypatch, src)
    frames = _frames(resp)
    next(frames)
    next(f for f in frames if f.startswith("data: {"))
    assert src.cursors[0] == 7
    resp.close()


def test_tail_streams_sanitized_events(client, monkeypatch):
    ev = LogEvent("Jan  1 00:00:01", "r1", "rpd", "err",
                  "BGP_NEIGHBOR_DOWN: neighbor 192.0.2.1 password S3cretBGPkey down")
    resp = _tail(client, monkeypatch, _FakeTail(events=[ev]))
    frames = _frames(resp)
    next(frames)
    data = next(f for f in frames if f.startswith("data: {"))
    resp.close()
    assert "S3cretBGPkey" not in data and "<REDACTED>" in data


def test_tail_caps_concurrent_streams_and_frees_slots_on_close(client, monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_MAX_SSE", "2")
    src = _FakeTail()
    first, second = _tail(client, monkeypatch, src), _tail(client, monkeypatch, src)
    assert first.status_code == second.status_code == 200
    third = _tail(client, monkeypatch, src)
    assert third.status_code == 503 and "too many" in third.get_json()["error"]
    first.close()
    again = _tail(client, monkeypatch, src)
    assert again.status_code == 200
    second.close()
    again.close()


def test_tail_bad_poll_is_400_and_does_not_leak_a_slot(client, monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_MAX_SSE", "1")
    src = _FakeTail()
    assert _tail(client, monkeypatch, src, "poll=abc").status_code == 400
    ok = _tail(client, monkeypatch, src)
    assert ok.status_code == 200
    ok.close()


# ── G: CDN pin ──────────────────────────────────────────────────────────────

def test_site_doc_pins_mermaid_to_an_exact_version():
    html = site_doc.render_site_doc_html("LAB", [{"hostname": "r1", "platform": "junos", "config_text": "x"}],
                                         include_diagram=True, include_compliance=False, use_llm_summary=False)
    tags = re.findall(r"<script[^>]+mermaid[^>]*>", html)
    assert tags, "site doc should still load mermaid"
    for tag in tags:
        assert re.search(r"mermaid@\d+\.\d+\.\d+/", tag), tag     # not the floating @10
        assert 'crossorigin="anonymous"' in tag


# ── H: version badge ────────────────────────────────────────────────────────

def test_index_html_has_no_hardcoded_version():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert __version__ not in html
    assert not re.search(r'class="brand-version"[^>]*>\s*v?\d', html)


def test_version_badge_is_filled_from_health_at_runtime(client):
    assert client.get("/api/health").get_json()["version"] == __version__
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    assert ".brand-version" in js and "h.version" in js
