"""A configured RBAC file that is unusable must never mean "no login" (CWE-636).

Startup refuses to run; a file that breaks while the server runs denies every request (503) and never
falls back to the unauthenticated dev mode. A path that is simply not configured keeps dev mode."""
from __future__ import annotations

import hashlib
import json
import os

import pytest

import ai_log_analyzer.web.app as web_app
from ai_log_analyzer import llm, rbac
from ai_log_analyzer.web.app import create_app

ADMIN = "admin-file-tok-0123456789"


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _good(path, tokens=(("ada", "admin", ADMIN),)):
    path.write_text(json.dumps({"users": [
        {"name": n, "role": r, "token_sha256": _digest(t)} for n, r, t in tokens]}))
    return path


def _rewrite(path, text: str) -> None:
    """Change the file the way an editor would, and make sure the mtime differs from the last write."""
    before = path.stat().st_mtime_ns
    path.write_text(text)
    os.utime(path, ns=(before + 5_000_000_000, before + 5_000_000_000))


@pytest.fixture(autouse=True)
def _only_the_rbac_file(monkeypatch):
    monkeypatch.setattr(web_app, "API_TOKEN", "")
    monkeypatch.delenv("AI_LOG_ANALYZER_REQUIRE_AUTH", raising=False)
    yield
    llm.set_enabled(True)


def _bad_files(tmp_path):
    missing = tmp_path / "gone.json"
    not_json = tmp_path / "not_json.json"
    not_json.write_text("{ this is not json")
    not_object = tmp_path / "list.json"
    not_object.write_text("[]")
    users_not_list = tmp_path / "users_str.json"
    users_not_list.write_text('{"users": "alice"}')
    empty = tmp_path / "empty.json"
    empty.write_text('{"users": []}')
    no_users_key = tmp_path / "nokey.json"
    no_users_key.write_text("{}")
    all_invalid = tmp_path / "invalid.json"
    all_invalid.write_text(json.dumps({"users": [
        {"name": "bob", "role": "superuser", "token_sha256": _digest("x" * 20)},
        {"name": "", "role": "admin", "token_sha256": _digest("y" * 20)},
        {"name": "eve", "role": "admin", "token_sha256": "not-64-hex"},
        "not-an-object"]}))
    return {"missing": missing, "not_json": not_json, "not_object": not_object,
            "users_not_list": users_not_list, "empty": empty, "no_users_key": no_users_key,
            "all_invalid": all_invalid}


_KINDS = ["missing", "not_json", "not_object", "users_not_list", "empty", "no_users_key", "all_invalid"]


# ── startup: refuse to run ──────────────────────────────────────────────────

@pytest.mark.parametrize("kind", _KINDS)
def test_startup_refuses_a_configured_but_unusable_file(tmp_path, monkeypatch, kind):
    monkeypatch.setenv("AI_LOG_ANALYZER_RBAC_FILE", str(_bad_files(tmp_path)[kind]))
    with pytest.raises(RuntimeError) as exc:
        create_app()
    assert "AI_LOG_ANALYZER_RBAC_FILE" in str(exc.value)
    with pytest.raises(rbac.RbacConfigError):
        rbac.principals()


def test_startup_refuses_an_unreadable_file(tmp_path, monkeypatch):
    if os.geteuid() == 0:
        pytest.skip("root reads everything")
    f = _good(tmp_path / "rbac.json")
    f.chmod(0)
    monkeypatch.setenv("AI_LOG_ANALYZER_RBAC_FILE", str(f))
    try:
        with pytest.raises(RuntimeError):
            create_app()
    finally:
        f.chmod(0o600)


def test_a_broken_file_is_refused_even_when_env_tokens_exist(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_VIEWER_TOKENS", "vera:viewer-env-tok-0123456789")
    monkeypatch.setenv("AI_LOG_ANALYZER_RBAC_FILE", str(_bad_files(tmp_path)["empty"]))
    with pytest.raises(RuntimeError):
        create_app()


def test_main_exits_with_a_clear_message(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_RBAC_FILE", str(tmp_path / "gone.json"))
    monkeypatch.setattr(web_app.Flask, "run", lambda self, **kw: pytest.fail("server must not start"))
    with pytest.raises(SystemExit) as exc:
        web_app.main()
    assert "AI_LOG_ANALYZER_RBAC_FILE" in str(exc.value)


def test_a_usable_file_starts_and_authenticates(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_RBAC_FILE", str(_good(tmp_path / "rbac.json")))
    c = create_app().test_client()
    assert c.get("/api/health").get_json()["auth"] == "rbac"
    assert c.post("/api/llm/toggle", json={"enabled": True}).status_code == 401
    assert c.post("/api/llm/toggle", json={"enabled": True},
                  headers={"Authorization": f"Bearer {ADMIN}"}).status_code == 200


def test_a_file_with_one_valid_user_and_some_junk_still_starts(tmp_path, monkeypatch):
    f = tmp_path / "rbac.json"
    f.write_text(json.dumps({"users": [
        {"name": "ada", "role": "admin", "token_sha256": _digest(ADMIN)},
        {"name": "bob", "role": "superuser", "token_sha256": _digest("x" * 20)}, "junk"]}))
    monkeypatch.setenv("AI_LOG_ANALYZER_RBAC_FILE", str(f))
    create_app()
    assert rbac.authenticate(ADMIN).name == "ada"


# ── not configured: dev mode as documented ──────────────────────────────────

def test_unconfigured_file_keeps_dev_mode(monkeypatch):
    monkeypatch.delenv("AI_LOG_ANALYZER_RBAC_FILE", raising=False)
    c = create_app().test_client()
    assert c.get("/api/health").get_json()["auth"] == "dev"
    assert c.post("/api/llm/toggle", json={"enabled": True}).status_code == 200


def test_a_blank_file_variable_counts_as_not_configured(monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_RBAC_FILE", "   ")
    assert create_app().test_client().get("/api/health").get_json()["auth"] == "dev"


# ── runtime: the file breaks while the server runs ──────────────────────────

def _breakers(tmp_path):
    return {
        "invalid_json": lambda f: _rewrite(f, "{ half a write"),
        "empty_users": lambda f: _rewrite(f, '{"users": []}'),
        "all_invalid": lambda f: _rewrite(f, json.dumps({"users": [{"name": "x", "role": "root"}]})),
        "not_object": lambda f: _rewrite(f, "[]"),
        "removed": lambda f: f.unlink(),
    }


@pytest.mark.parametrize("how", ["invalid_json", "empty_users", "all_invalid", "not_object", "removed"])
def test_a_file_that_breaks_at_runtime_never_opens_the_api(tmp_path, monkeypatch, how):
    f = _good(tmp_path / "rbac.json")
    monkeypatch.setenv("AI_LOG_ANALYZER_RBAC_FILE", str(f))
    c = create_app().test_client()
    bearer = {"Authorization": f"Bearer {ADMIN}"}
    assert c.post("/api/llm/toggle", json={"enabled": True}, headers=bearer).status_code == 200

    _breakers(tmp_path)[how](f)

    assert c.get("/api/health").get_json()["auth"] == "rbac"       # never "dev"
    for headers in ({}, bearer):                                    # tokenless AND the old good token
        r = c.post("/api/llm/toggle", json={"enabled": False}, headers=headers)
        assert r.status_code in (401, 503), (how, headers, r.status_code)
        assert llm.get_state()["enabled"] is True                   # the admin handler never ran
    assert c.post("/api/run", json={"hostname": "r1", "command": "show version"}).status_code in (401, 503)
    assert "last_errors" not in c.get("/api/llm/status").get_json()   # anonymous stays redacted
    assert c.get("/api/llm/status", headers=bearer).status_code == 503
    assert c.get("/api/tail/anything").status_code in (401, 503)
    body = c.post("/api/llm/toggle", json={"enabled": False}).get_json()
    assert str(tmp_path) not in json.dumps(body)                    # no file path in the response


def test_the_api_recovers_when_the_file_is_fixed(tmp_path, monkeypatch):
    f = _good(tmp_path / "rbac.json")
    monkeypatch.setenv("AI_LOG_ANALYZER_RBAC_FILE", str(f))
    c = create_app().test_client()
    bearer = {"Authorization": f"Bearer {ADMIN}"}
    _rewrite(f, "oops")
    assert c.post("/api/llm/toggle", json={"enabled": True}, headers=bearer).status_code == 503
    _good(f)
    os.utime(f, ns=(f.stat().st_mtime_ns + 9_000_000_000,) * 2)
    assert c.post("/api/llm/toggle", json={"enabled": True}, headers=bearer).status_code == 200
    assert c.post("/api/llm/toggle", json={"enabled": True}).status_code == 401


def test_a_file_edit_that_removes_a_user_revokes_that_user(tmp_path, monkeypatch):
    f = _good(tmp_path / "rbac.json", (("ada", "admin", ADMIN), ("vera", "viewer", "viewer-file-tok-0123456")))
    monkeypatch.setenv("AI_LOG_ANALYZER_RBAC_FILE", str(f))
    c = create_app().test_client()
    vera = {"Authorization": "Bearer viewer-file-tok-0123456"}
    assert c.get("/api/whoami", headers=vera).status_code == 200
    _rewrite(f, json.dumps({"users": [{"name": "ada", "role": "admin", "token_sha256": _digest(ADMIN)}]}))
    assert c.get("/api/whoami", headers=vera).status_code == 401


def test_the_failure_is_logged_as_an_error(tmp_path, monkeypatch, caplog):
    f = _good(tmp_path / "rbac.json")
    monkeypatch.setenv("AI_LOG_ANALYZER_RBAC_FILE", str(f))
    c = create_app().test_client()
    _rewrite(f, "oops")
    with caplog.at_level("ERROR", logger="ai_log_analyzer.rbac"):
        c.get("/api/whoami", headers={"Authorization": f"Bearer {ADMIN}"})
    assert any("AI_LOG_ANALYZER_RBAC_FILE" in r.getMessage() for r in caplog.records if r.levelname == "ERROR")


def test_a_configured_file_means_auth_is_on_even_when_unreadable(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_RBAC_FILE", str(tmp_path / "gone.json"))
    assert rbac.auth_enabled() is True
