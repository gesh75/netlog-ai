"""File-source confinement: default roots, hidden / credential files, and
sanitized event text in the analyze response."""
from __future__ import annotations

import pytest

import ai_log_analyzer.web.app as web_app
from ai_log_analyzer.web.app import create_app

LOG_LINE = "Jan  1 00:00:01 r1 rpd[1]: BGP_NEIGHBOR_DOWN: neighbor 192.0.2.1 password S3cretBGPkey down\n"


@pytest.fixture
def client():
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


def _analyze(client, path, **extra):
    return client.post("/api/analyze", json={"source": "file", "path": str(path), "use_llm": False, **extra})


def test_default_roots_are_var_log_and_optional_data_dir(monkeypatch):
    monkeypatch.delenv("AI_LOG_ANALYZER_DATA_DIR", raising=False)
    assert web_app._default_file_roots() == "/var/log"
    monkeypatch.setenv("AI_LOG_ANALYZER_DATA_DIR", "/srv/netlogs")
    assert web_app._default_file_roots() == "/var/log:/srv/netlogs"


def test_home_and_repo_are_not_default_roots(monkeypatch):
    from pathlib import Path
    monkeypatch.delenv("AI_LOG_ANALYZER_DATA_DIR", raising=False)
    roots = web_app._default_file_roots().split(":")
    assert str(Path.home()) not in roots and str(Path(web_app.__file__).resolve().parents[3]) not in roots


def test_home_credentials_file_is_not_readable_by_default(client, tmp_path, monkeypatch):
    """The reported exploit: a credentials file under $HOME came back in the analyze JSON."""
    monkeypatch.delenv("AI_LOG_ANALYZER_DATA_DIR", raising=False)
    monkeypatch.setattr(web_app, "FILE_ROOTS", [web_app.Path(p) for p in web_app._default_file_roots().split(":")])
    creds = tmp_path / "credentials"
    creds.write_text(LOG_LINE)
    r = _analyze(client, creds)
    assert r.status_code == 403
    assert "S3cretBGPkey" not in r.get_data(as_text=True)


@pytest.mark.parametrize("rel", [
    ".aws/credentials", ".ssh/id_rsa", ".env", ".env.production", ".netrc", ".hidden.log",
    "id_rsa", "id_ed25519.pub", "server.pem", "tls.key", "credentials", "credentials.log",
    "rbac.json", "state.db", "dir/.git/config", ".config/app.log",
])
def test_hidden_and_credential_files_are_denied_inside_an_allowed_root(client, tmp_path, monkeypatch, rel):
    target = tmp_path / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(LOG_LINE)
    monkeypatch.setattr(web_app, "FILE_ROOTS", [tmp_path])
    r = _analyze(client, target)
    assert r.status_code == 403
    assert "S3cretBGPkey" not in r.get_data(as_text=True)


def test_a_dot_directory_above_the_root_does_not_deny_the_root(client, tmp_path, monkeypatch):
    root = tmp_path / ".data" / "logs"            # only parts BELOW the root are judged
    root.mkdir(parents=True)
    log = root / "dev.log"
    log.write_text(LOG_LINE)
    monkeypatch.setattr(web_app, "FILE_ROOTS", [root])
    assert _analyze(client, log).status_code == 200


def test_directory_scan_skips_hidden_and_credential_files(client, tmp_path, monkeypatch):
    (tmp_path / "ok.log").write_text("Jan  1 00:00:01 r1 rpd[1]: BGP_NEIGHBOR_DOWN: peer 192.0.2.9 down\n")
    (tmp_path / ".secret.log").write_text(LOG_LINE.replace("S3cretBGPkey", "HIDDENFILEMARKER"))
    (tmp_path / "credentials.log").write_text(LOG_LINE.replace("S3cretBGPkey", "CREDFILEMARKER"))
    monkeypatch.setattr(web_app, "FILE_ROOTS", [tmp_path])
    r = _analyze(client, tmp_path, recursive=False)
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "192.0.2.9" in body
    assert "HIDDENFILEMARKER" not in body and "CREDFILEMARKER" not in body


def test_directory_with_only_denied_files_is_404(client, tmp_path, monkeypatch):
    (tmp_path / ".only.log").write_text(LOG_LINE)
    monkeypatch.setattr(web_app, "FILE_ROOTS", [tmp_path])
    assert _analyze(client, tmp_path).status_code == 404


def test_analyze_response_never_echoes_secrets_from_log_lines(client, tmp_path, monkeypatch):
    log = tmp_path / "dev.log"
    log.write_text(LOG_LINE)
    monkeypatch.setattr(web_app, "FILE_ROOTS", [tmp_path])
    r = _analyze(client, log)
    assert r.status_code == 200
    assert r.get_json()["classified_events"], "the file should still be analyzed"
    assert "S3cretBGPkey" not in r.get_data(as_text=True)


def test_raw_source_response_is_scrubbed_too(client):
    r = client.post("/api/analyze", json={"source": "raw", "use_llm": False, "text": LOG_LINE})
    assert r.status_code == 200
    assert "S3cretBGPkey" not in r.get_data(as_text=True)
