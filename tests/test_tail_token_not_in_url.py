"""The long-lived API token never travels in a URL (CWE-598): the live tail takes it from a header only,
and the dashboard reads the stream with fetch() so the Authorization header carries it."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

import ai_log_analyzer.web.app as web_app
from ai_log_analyzer.web.app import create_app

STATIC = Path(web_app.__file__).parent / "static"
VIEW, OPER, ADMIN = "view-tok-0123456789", "oper-tok-0123456789", "admin-tok-0123456789"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(web_app, "API_TOKEN", "")
    monkeypatch.setenv("AI_LOG_ANALYZER_VIEWER_TOKENS", f"vera:{VIEW}")
    monkeypatch.setenv("AI_LOG_ANALYZER_OPERATOR_TOKENS", f"otto:{OPER}")
    monkeypatch.setenv("AI_LOG_ANALYZER_ADMIN_TOKENS", f"ada:{ADMIN}")
    return create_app().test_client()


@pytest.mark.parametrize("tok", [VIEW, OPER, ADMIN])
def test_a_token_in_the_tail_url_is_not_accepted(client, tok):
    assert client.get(f"/api/tail/nope?token={tok}").status_code == 401
    assert client.get(f"/api/tail/nope?min_severity=high&token={tok}").status_code == 401


@pytest.mark.parametrize("tok", [VIEW, OPER, ADMIN])
def test_the_tail_takes_any_role_from_a_header(client, tok):
    assert client.get("/api/tail/nope", headers={"Authorization": f"Bearer {tok}"}).status_code == 404
    assert client.get("/api/tail/nope", headers={"X-API-Token": tok}).status_code == 404


def test_the_query_string_is_never_a_credential_on_any_route(client):
    assert client.get(f"/api/incidents/similar?q=bgp&token={ADMIN}").status_code == 401
    assert client.get(f"/api/whoami?token={ADMIN}").status_code == 401
    assert client.get(f"/api/audit?token={ADMIN}").status_code == 401


def test_a_query_token_is_not_even_counted_as_supplied_and_is_never_stored(client, monkeypatch, tmp_path):
    from ai_log_analyzer import audit
    from ai_log_analyzer.state_store import open_db
    monkeypatch.setenv("AI_LOG_ANALYZER_STATE_DB", str(tmp_path / "s.db"))
    audit._THROTTLE.clear()
    audit._THROTTLE_SUPPRESSED[0] = 0
    audit._THROTTLE_GLOBAL[:] = [0.0, 0]
    open_db(tmp_path / "s.db")
    client.get(f"/api/tail/nope?token={ADMIN}")
    rows = audit.query(action="authn.failed")
    assert rows and rows[0]["detail"]["token"] == "missing" and ADMIN not in repr(rows)


def test_the_dashboard_never_puts_the_token_in_a_url():
    v2 = (STATIC / "v2.js").read_text(encoding="utf-8")
    app_js = (STATIC / "app.js").read_text(encoding="utf-8")
    assert not re.search(r"[?&]token=", v2), "v2.js must not build a ?token= URL"
    assert "extends OrigES" not in v2 and "window.EventSource" not in v2
    assert "new EventSource" not in app_js, "the live tail must be read with fetch() (Authorization header)"
    assert "openTailStream" in app_js
