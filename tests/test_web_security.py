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


@pytest.mark.unit
def test_incident_search_requires_token(client, monkeypatch):
    """Incident history must not be searchable anonymously when tokened."""
    monkeypatch.setattr(web_app, "API_TOKEN", "sekrit")
    url = "/api/incidents/similar?q=router"
    assert client.get(url).status_code == 401
    assert client.get(url, headers={"X-API-Token": "wrong"}).status_code == 401
    assert client.get(url, headers={"X-API-Token": "sekrit"}).status_code != 401


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


@pytest.mark.unit
def test_directory_source_pattern_cannot_escape_root(client, monkeypatch, tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    (tmp_path / "secret.log").write_text("TOP SECRET\n", encoding="utf-8")
    monkeypatch.setattr(web_app, "FILE_ROOTS", [tmp_path])

    r = client.post("/api/analyze", json={
        "source": "file",
        "path": str(allowed),
        "pattern": "../secret.log",
        "recursive": False,
        "use_llm": False,
    })
    assert r.status_code == 400
    assert "path components" in r.get_json()["error"]


# ──────────────────────────────────────────────────────────────────────────────
# /api/analyze {source:"frr"} docker-logs allow-list
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_frr_source_rejects_containers_outside_lab_allowlist(client, monkeypatch):
    """Caller-supplied container names must be in list_lab_containers().
    Otherwise docker logs would read any container on the host."""
    import ai_log_analyzer.adapters.frr as frr

    monkeypatch.setattr(frr, "list_lab_containers", lambda: ["de-fra-core-01"])
    called: list[str] = []

    def _should_not_run(container, tail=500, since=None):
        called.append(container)
        return []

    monkeypatch.setattr(frr, "frr_docker_logs", _should_not_run)
    r = client.post("/api/analyze", json={
        "source": "frr",
        "containers": ["postgres"],
        "use_llm": False,
    })
    assert r.status_code == 403
    body = r.get_json()
    assert "allow-list" in body["error"]
    assert body["rejected"] == ["postgres"]
    assert called == []


@pytest.mark.unit
def test_frr_source_rejects_mixed_allowlist_and_foreign(client, monkeypatch):
    """A mixed list fails closed — do not silently analyze the allowed subset."""
    import ai_log_analyzer.adapters.frr as frr

    monkeypatch.setattr(frr, "list_lab_containers", lambda: ["de-fra-core-01"])
    called: list[str] = []
    monkeypatch.setattr(
        frr, "frr_docker_logs",
        lambda container, tail=500, since=None: called.append(container) or [],
    )
    r = client.post("/api/analyze", json={
        "source": "frr",
        "containers": ["de-fra-core-01", "vault"],
        "use_llm": False,
    })
    assert r.status_code == 403
    assert r.get_json()["rejected"] == ["vault"]
    assert called == []


@pytest.mark.unit
def test_frr_source_allows_inventory_container(client, monkeypatch):
    import ai_log_analyzer.adapters.frr as frr
    from ai_log_analyzer.classifier import LogEvent

    monkeypatch.setattr(frr, "list_lab_containers", lambda: ["de-fra-core-01"])

    def _logs(container, tail=500, since=None):
        return [LogEvent(
            timestamp="2026-05-03T23:21:06",
            hostname=container,
            appname="watchfrr",
            severity_raw="info",
            message="zebra state -> up : connect succeeded",
        )]

    monkeypatch.setattr(frr, "frr_docker_logs", _logs)
    r = client.post("/api/analyze", json={
        "source": "frr",
        "containers": ["de-fra-core-01"],
        "use_llm": False,
    })
    assert r.status_code == 200
    assert len(r.get_json()["classified_events"]) >= 1


@pytest.mark.unit
def test_frr_source_rejects_non_list_containers(client, monkeypatch):
    """A string would otherwise iterate as characters and miss the allow-list."""
    import ai_log_analyzer.adapters.frr as frr

    monkeypatch.setattr(frr, "list_lab_containers", lambda: ["de-fra-core-01"])
    called: list[str] = []
    monkeypatch.setattr(
        frr, "frr_docker_logs",
        lambda container, tail=500, since=None: called.append(container) or [],
    )
    r = client.post("/api/analyze", json={
        "source": "frr",
        "containers": "postgres",
        "use_llm": False,
    })
    assert r.status_code == 400
    assert "must be a list" in r.get_json()["error"]
    assert called == []


@pytest.mark.unit
def test_frr_source_rejects_flag_like_and_non_string_names(client, monkeypatch):
    import ai_log_analyzer.adapters.frr as frr

    called: list[str] = []
    monkeypatch.setattr(frr, "list_lab_containers", lambda: ["de-fra-core-01"])
    monkeypatch.setattr(
        frr, "frr_docker_logs",
        lambda container, tail=500, since=None: called.append(container) or [],
    )
    r = client.post("/api/analyze", json={
        "source": "frr",
        "containers": ["--privileged"],
        "use_llm": False,
    })
    assert r.status_code == 400
    r = client.post("/api/analyze", json={
        "source": "frr",
        "containers": [123],
        "use_llm": False,
    })
    assert r.status_code == 400
    assert called == []


@pytest.mark.unit
def test_optimize_does_not_docker_exec_non_lab_hostname(client, monkeypatch):
    """ /api/optimize FRR fallback must not docker-exec an arbitrary hostname. """
    from ai_log_analyzer.adapters import frr, network_tool as nt

    monkeypatch.setattr(nt, "is_available", lambda timeout=1.0: False)
    monkeypatch.setattr(nt, "DOCKER_EXEC_FALLBACK", True)
    monkeypatch.setattr(frr, "is_lab_container", lambda _name: False)
    ran: list[int] = []

    def _run(*_a, **_k):
        ran.append(1)
        raise AssertionError("docker exec must not run for a non-lab hostname")

    monkeypatch.setattr(nt.shutil, "which", lambda _b: "/usr/bin/docker")
    monkeypatch.setattr(nt.subprocess, "run", _run)
    r = client.post("/api/optimize", json={
        "hostname": "postgres",
        "platform": "frr",
    })
    assert r.status_code == 502
    assert ran == []


@pytest.mark.unit
def test_run_does_not_docker_exec_non_lab_hostname(client, monkeypatch):
    """ /api/run docker-exec fallback must stay inside the lab inventory. """
    from ai_log_analyzer.adapters import frr, network_tool as nt

    monkeypatch.setattr(nt, "is_available", lambda timeout=1.0: False)
    monkeypatch.setattr(frr, "is_lab_container", lambda _name: False)
    ran: list[int] = []

    def _run(*_a, **_k):
        ran.append(1)
        raise AssertionError("docker exec must not run for a non-lab hostname")

    monkeypatch.setattr(nt.shutil, "which", lambda _b: "/usr/bin/docker")
    monkeypatch.setattr(nt.subprocess, "run", _run)
    r = client.post("/api/run", json={
        "hostname": "postgres",
        "command": "show version",
    })
    assert r.status_code == 503
    assert ran == []


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
