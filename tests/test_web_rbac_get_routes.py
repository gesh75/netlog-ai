"""Read routes need a token when auth is on; sources/samples responses leak nothing."""
from __future__ import annotations

import pytest

import ai_log_analyzer.web.app as web_app
from ai_log_analyzer.sources import SourceConfig
from ai_log_analyzer.sources.manager import manager as source_manager
from ai_log_analyzer.web.app import create_app

VIEW, OPER = "viewer-tok-0123456789", "oper-tok-0123456789ab"


def _h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(web_app, "API_TOKEN", "")
    monkeypatch.setenv("AI_LOG_ANALYZER_VIEWER_TOKENS", f"vera:{VIEW}")
    monkeypatch.setenv("AI_LOG_ANALYZER_OPERATOR_TOKENS", f"otto:{OPER}")
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


def _a_site() -> str:
    return sorted(p.name for p in web_app.SITES_DIR.iterdir() if (p / "manifest.json").is_file())[0]


def _a_sample() -> str:
    import json
    return json.loads((web_app.SAMPLES_DIR / "_manifest.json").read_text())[0]["id"]


READ_ROUTES = [
    "/api/sources", "/api/samples", "/api/lab/containers", "/api/network-tool/devices",
    "/api/rules", "/api/sites",
]


@pytest.mark.parametrize("path", READ_ROUTES)
def test_read_routes_are_401_without_a_token_and_200_for_a_viewer(client, path):
    assert client.get(path).status_code == 401
    assert client.get(path, headers=_h("wrong-token-0123456789")).status_code == 401
    assert client.get(path, headers=_h(VIEW)).status_code == 200


@pytest.mark.parametrize("template", [
    "/api/topology/{site}", "/api/compliance/{site}", "/api/sitedoc/{site}?llm=0",
])
def test_site_routes_are_401_without_a_token_and_200_for_a_viewer(client, template):
    path = template.format(site=_a_site())
    assert client.get(path).status_code == 401
    assert client.get(path, headers=_h(VIEW)).status_code == 200


def test_sample_preview_requires_a_token(client):
    path = f"/api/samples/{_a_sample()}"
    assert client.get(path).status_code == 401
    assert client.get(path, headers=_h(VIEW)).status_code == 200


def test_health_stays_open(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.get_json()["ok"] is True


def test_read_routes_stay_open_in_dev_mode(monkeypatch):
    monkeypatch.setattr(web_app, "API_TOKEN", "")
    c = create_app().test_client()
    for path in READ_ROUTES:
        assert c.get(path).status_code == 200, path


def test_samples_do_not_expose_server_paths(client):
    body = client.get("/api/samples", headers=_h(VIEW)).get_data(as_text=True)
    assert str(web_app.SAMPLES_DIR) not in body and "samples_dir" not in body
    sites = client.get("/api/sites", headers=_h(VIEW)).get_data(as_text=True)
    assert str(web_app.SITES_DIR) not in sites and "sites_dir" not in sites


# ── /api/sitedoc: llm=1 spends money, so it is operator-only ────────────────

@pytest.fixture
def llm_calls(monkeypatch):
    seen: list[bool] = []
    real = web_app.site_doc.render_site_doc

    def spy(*a, use_llm_summary=True, **k):
        seen.append(use_llm_summary)
        return real(*a, use_llm_summary=False, **k)   # never call a real LLM from a test
    monkeypatch.setattr(web_app.site_doc, "render_site_doc", spy)
    return seen


def test_sitedoc_defaults_llm_off_for_viewers_and_refuses_llm_1(client, llm_calls):
    site = _a_site()
    assert client.get(f"/api/sitedoc/{site}", headers=_h(VIEW)).status_code == 200
    assert llm_calls == [False]
    r = client.get(f"/api/sitedoc/{site}?llm=1", headers=_h(VIEW))
    assert r.status_code == 403 and "operator" in r.get_json()["error"]
    assert llm_calls == [False]            # the refused request never reached the renderer


def test_sitedoc_defaults_llm_on_for_operators(client, llm_calls):
    site = _a_site()
    assert client.get(f"/api/sitedoc/{site}", headers=_h(OPER)).status_code == 200
    assert client.get(f"/api/sitedoc/{site}?llm=1", headers=_h(OPER)).status_code == 200
    assert llm_calls == [True, True]


def test_sitedoc_dev_mode_keeps_llm_default(monkeypatch, llm_calls):
    monkeypatch.setattr(web_app, "API_TOKEN", "")
    c = create_app().test_client()
    assert c.get(f"/api/sitedoc/{_a_site()}").status_code == 200
    assert llm_calls == [True]


# ── /api/sources redaction ──────────────────────────────────────────────────

def test_sources_listing_redacts_extra_values_and_url_userinfo(client):
    source_manager.add(SourceConfig(
        id="w3-redact", type="loki", url="https://svc-user:hunter2pw@loki.example.test:3100/x",
        api_token="tok-abc", auth_methods=("api_token",),
        extra={"api_key": "sk-live-SECRETVALUE", "org_id": "tenant-7"}))
    try:
        r = client.get("/api/sources", headers=_h(VIEW))
        body = r.get_data(as_text=True)
        assert r.status_code == 200
        assert "SECRETVALUE" not in body and "tenant-7" not in body and "hunter2pw" not in body
        entry = next(s for s in r.get_json()["sources"] if s["id"] == "w3-redact")
        assert entry["url"] == "https://loki.example.test:3100/x"
        assert entry["extra"] == {"api_key": "***", "org_id": "***"}
        assert entry["type"] == "loki"                      # what the UI actually needs
    finally:
        source_manager.remove("w3-redact")
