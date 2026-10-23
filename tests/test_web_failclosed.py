"""Fail-closed deployment: REQUIRE_AUTH, non-loopback bind refusal, token length,
Host-header allowlist, and the container / compose definitions."""
from __future__ import annotations

from pathlib import Path

import pytest

import ai_log_analyzer.web.app as web_app
from ai_log_analyzer import rbac
from ai_log_analyzer.web.app import create_app, main

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "t0ken-0123456789-abcdef"


@pytest.fixture(autouse=True)
def _no_ambient_auth(monkeypatch):
    monkeypatch.setattr(web_app, "API_TOKEN", "")
    for name in ("AI_LOG_ANALYZER_REQUIRE_AUTH", "AI_LOG_ANALYZER_ALLOW_NOAUTH", "ANALYZER_HOST",
                 "AI_LOG_ANALYZER_ALLOWED_HOSTS"):
        monkeypatch.delenv(name, raising=False)


# ── REQUIRE_AUTH ────────────────────────────────────────────────────────────

def test_require_auth_refuses_to_start_without_a_token(monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_REQUIRE_AUTH", "1")
    with pytest.raises(RuntimeError) as exc:
        create_app()
    assert "AI_LOG_ANALYZER_API_TOKEN" in str(exc.value)


@pytest.mark.parametrize("setup", ["legacy", "rbac-env"])
def test_require_auth_starts_when_a_token_is_configured(monkeypatch, setup):
    monkeypatch.setenv("AI_LOG_ANALYZER_REQUIRE_AUTH", "1")
    if setup == "legacy":
        monkeypatch.setattr(web_app, "API_TOKEN", TOKEN)
    else:
        monkeypatch.setenv("AI_LOG_ANALYZER_VIEWER_TOKENS", f"vera:{TOKEN}")
    create_app()


def test_without_require_auth_dev_mode_still_starts(monkeypatch):
    create_app()   # unchanged developer experience: loopback, no token


def test_short_tokens_are_a_startup_error(monkeypatch):
    monkeypatch.setattr(web_app, "API_TOKEN", "short")
    with pytest.raises(RuntimeError) as exc:
        create_app()
    assert "at least 16" in str(exc.value)


@pytest.mark.parametrize("var", ["VIEWER", "OPERATOR", "ADMIN"])
def test_short_role_tokens_are_refused_not_dropped(monkeypatch, var):
    monkeypatch.setenv(f"AI_LOG_ANALYZER_{var}_TOKENS", "bob:tooshort")
    with pytest.raises(rbac.RbacConfigError):
        rbac.principals()


def test_token_of_exactly_16_chars_is_accepted(monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_VIEWER_TOKENS", "bob:" + "x" * 16)
    assert rbac.authenticate("x" * 16).name == "bob"


# ── main(): non-loopback bind ───────────────────────────────────────────────

@pytest.fixture
def runs(monkeypatch):
    calls: list[dict] = []
    monkeypatch.setattr(web_app.Flask, "run", lambda self, **kw: calls.append(kw))
    return calls


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.0.2.10", "analyzer.lan"])
def test_main_refuses_a_non_loopback_bind_without_auth(monkeypatch, runs, host):
    monkeypatch.setenv("ANALYZER_HOST", host)
    with pytest.raises(SystemExit) as exc:
        main()
    assert "AI_LOG_ANALYZER_API_TOKEN" in str(exc.value) and "ALLOW_NOAUTH" in str(exc.value)
    assert runs == []


def test_main_allows_non_loopback_with_a_token(monkeypatch, runs):
    monkeypatch.setenv("ANALYZER_HOST", "0.0.0.0")
    monkeypatch.setattr(web_app, "API_TOKEN", TOKEN)
    main()
    assert runs and runs[0]["host"] == "0.0.0.0"


def test_main_allows_non_loopback_without_auth_only_when_explicitly_accepted(monkeypatch, runs, capsys):
    monkeypatch.setenv("ANALYZER_HOST", "0.0.0.0")
    monkeypatch.setenv("AI_LOG_ANALYZER_ALLOW_NOAUTH", "1")
    main()
    assert runs and "unauthenticated" in capsys.readouterr().out


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_main_on_loopback_is_unchanged(monkeypatch, runs, host):
    monkeypatch.setenv("ANALYZER_HOST", host)
    main()
    assert runs and runs[0]["host"] == host


# ── DNS rebinding: Host allowlist when auth is off ──────────────────────────

def _get(client, host):
    return client.get("/api/health", headers={"Host": host})


@pytest.mark.parametrize("host", ["localhost", "localhost:6060", "127.0.0.1:6060", "[::1]:6060", "LOCALHOST"])
def test_loopback_hosts_are_served_without_auth(host):
    c = create_app().test_client()
    assert _get(c, host).status_code == 200


@pytest.mark.parametrize("host", ["evil.example", "evil.example:6060", "127.0.0.1.evil.example", "10.0.0.5"])
def test_foreign_host_header_is_rejected_without_auth(host):
    r = _get(create_app().test_client(), host)
    assert r.status_code == 400
    assert "host" in r.get_json()["error"]


def test_host_check_is_skipped_when_auth_is_on(monkeypatch):
    monkeypatch.setattr(web_app, "API_TOKEN", TOKEN)
    assert _get(create_app().test_client(), "analyzer.example.com").status_code == 200


def test_allowed_hosts_env_and_bind_host_extend_the_list(monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_ALLOWED_HOSTS", "netlog.lan, localhost")
    monkeypatch.setenv("ANALYZER_HOST", "192.0.2.10")
    c = create_app().test_client()
    assert _get(c, "netlog.lan:6060").status_code == 200
    assert _get(c, "192.0.2.10:6060").status_code == 200
    assert _get(c, "evil.example").status_code == 400


def test_wildcard_allowed_hosts_disables_the_check(monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_ALLOWED_HOSTS", "*")
    assert _get(create_app().test_client(), "anything.example").status_code == 200


# ── Docker image / compose ──────────────────────────────────────────────────

def _read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def test_dockerfile_enforces_auth_and_drops_root():
    df = _read("Dockerfile")
    assert "AI_LOG_ANALYZER_REQUIRE_AUTH=1" in df
    assert any(line.startswith("USER ") and line.split()[1] not in {"root", "0"} for line in df.splitlines())
    assert "pip install -e" not in df and "curl" not in df
    assert df.count("FROM ") >= 2                       # multi-stage
    assert "HEALTHCHECK" in df and "--timeout=" in df
    assert "ARG PYTHON_IMAGE" in df                      # pin-by-digest hook
    assert "DOCKER_EXEC_FALLBACK=false" in df


def test_compose_binds_loopback_requires_token_and_gates_docker_sock():
    dc = _read("docker-compose.yml")
    assert '"127.0.0.1:${ANALYZER_PORT:-6060}:6060"' in dc
    assert "${AI_LOG_ANALYZER_API_TOKEN:?" in dc
    assert "AI_LOG_ANALYZER_STATE_DB: /data/state.db" in dc and "netlog-data:/data" in dc
    assert "\nvolumes:\n  netlog-data:" in dc


def test_compose_docker_socket_only_in_the_lab_profile_service():
    yaml = pytest.importorskip("yaml")
    services = yaml.safe_load(_read("docker-compose.yml"))["services"]
    for name, svc in services.items():
        has_sock = any("docker.sock" in str(v) for v in svc.get("volumes", []))
        assert has_sock == ("lab" in svc.get("profiles", [])), name
    assert services["app-lab"]["environment"]["DOCKER_EXEC_FALLBACK"] == "true"


def test_dockerignore_excludes_secrets_and_vcs():
    lines = {ln.strip() for ln in _read(".dockerignore").splitlines()}
    for needed in (".git", ".env*", "tests", "dist", "__pycache__", "*.pyc", ".venv"):
        assert needed in lines, needed
