"""A web or MCP caller must not choose host file paths for a syslog source.

``extra.spool`` made the service create directories and a SQLite database anywhere it could write, and
``extra.tls_cert`` / ``tls_key`` / ``tls_ca`` made it read any file and echo the OS error. Requests (POST
/api/sources, MCP add_source) are now confined; operator configuration (NETLOG_SOURCE_<id>_* environment,
code calling SourceManager.add) is unchanged.
"""
from __future__ import annotations

import asyncio
import socket
import sqlite3

import pytest

import ai_log_analyzer.web.app as web_app
from ai_log_analyzer.sources import SourceConfig
from ai_log_analyzer.sources import syslog as _syslog  # noqa: F401  (registers the connector)
from ai_log_analyzer.sources.base import SourceError
from ai_log_analyzer.sources.manager import SourceManager
from ai_log_analyzer.state_store import open_db
from ai_log_analyzer.web.app import create_app

pytestmark = pytest.mark.unit

ADMIN = "admin-tok-0123456789"
IDS = ("p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9", "tls1", "tls2", "tls3")


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    """The operator's data directory: where AI_LOG_ANALYZER_STATE_DB lives."""
    d = tmp_path / "data"
    d.mkdir()
    monkeypatch.setenv("AI_LOG_ANALYZER_STATE_DB", str(d / "state.db"))
    open_db(d / "state.db")
    return d


@pytest.fixture
def client(monkeypatch, data_dir):
    monkeypatch.setattr(web_app, "API_TOKEN", "")
    monkeypatch.setenv("AI_LOG_ANALYZER_ADMIN_TOKENS", f"ada:{ADMIN}")
    app = create_app()
    app.config.update(TESTING=True)
    yield app.test_client()
    for sid in IDS:
        web_app.source_manager.remove(sid)


def _post(client, source_id: str, **extra):
    body = {"id": source_id, "type": "syslog", "url": "udp://127.0.0.1",
            "extra": {"port": str(_free_port()), "bind": "127.0.0.1", **{k: str(v) for k, v in extra.items()}}}
    return client.post("/api/sources", json=body, headers={"Authorization": f"Bearer {ADMIN}"})


# ── spool path ──────────────────────────────────────────────────────────────

def test_api_refuses_a_spool_outside_the_data_directory(client, tmp_path):
    outside = tmp_path / "elsewhere" / "deep" / "x.db"
    r = _post(client, "p1", spool=outside)
    assert r.status_code == 400, r.get_json()
    assert not (tmp_path / "elsewhere").exists(), "no directory or file may be created"
    assert "p1" not in web_app.source_manager.list_ids()


def test_api_refuses_traversal_and_symlink_escapes(client, data_dir, tmp_path):
    (tmp_path / "outside").mkdir()
    (data_dir / "link").symlink_to(tmp_path / "outside", target_is_directory=True)
    for sid, path in (("p1", data_dir / ".." / "outside" / "a.db"), ("p2", data_dir / "link" / "b.db")):
        r = _post(client, sid, spool=path)
        assert r.status_code == 400, (path, r.get_json())
    assert list((tmp_path / "outside").iterdir()) == []


def test_api_accepts_a_new_spool_inside_the_data_directory(client, data_dir):
    r = _post(client, "p1", spool=data_dir / "spools" / "web.db")
    assert r.status_code == 200, r.get_json()
    assert (data_dir / "spools" / "web.db").is_file()


def test_api_will_not_adopt_an_existing_file_that_is_not_a_spool(client, data_dir):
    other = data_dir / "audit.db"
    con = sqlite3.connect(other)
    con.execute("CREATE TABLE audit_note (x)")
    con.commit()
    con.close()
    (data_dir / "empty.db").write_bytes(b"")
    (data_dir / "notes.txt").write_text("not a database")
    for sid, name in (("p1", "audit.db"), ("p2", "empty.db"), ("p3", "notes.txt"), ("p4", "state.db.wal")):
        r = _post(client, sid, spool=data_dir / name)
        assert r.status_code == 400, (name, r.get_json())
    con = sqlite3.connect(other)
    tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    con.close()
    assert "syslog_spool" not in tables, "the foreign database must not have been given the spool schema"


def test_api_may_name_the_operators_own_spool_database(client, data_dir):
    assert _post(client, "p1", spool=data_dir / "state.db").status_code == 200


def test_without_a_configured_data_directory_the_api_cannot_pick_a_spool(client, monkeypatch, tmp_path):
    monkeypatch.delenv("AI_LOG_ANALYZER_STATE_DB")
    r = _post(client, "p1", spool=tmp_path / "anywhere.db")
    assert r.status_code == 400 and not (tmp_path / "anywhere.db").exists()


# ── TLS files ───────────────────────────────────────────────────────────────

def test_api_refuses_tls_file_paths_and_does_not_say_what_they_are(client, tmp_path):
    a_dir = tmp_path / "adir"
    a_dir.mkdir()
    a_file = tmp_path / "afile.pem"
    a_file.write_text("not a pem")
    errors = []
    for sid, path in (("tls1", tmp_path / "missing.pem"), ("tls2", a_dir), ("tls3", a_file)):
        r = _post(client, sid, proto="tls", tls_cert=path, tls_key=path)
        assert r.status_code == 400, (path, r.get_json())
        errors.append(r.get_json()["error"])
    assert len(set(errors)) == 1, f"errors tell the cases apart: {errors}"
    assert all(str(tmp_path) not in e and "SSL" not in e and "No such" not in e for e in errors)


def test_api_refuses_tls_options_even_on_a_plain_listener(client, tmp_path):
    for sid, key in (("p1", "tls_cert"), ("p2", "tls_key"), ("p3", "tls_ca")):
        assert _post(client, sid, **{key: tmp_path / "x.pem"}).status_code == 400, key


# ── MCP ─────────────────────────────────────────────────────────────────────

def test_mcp_add_source_is_confined_the_same_way(data_dir, tmp_path, monkeypatch):
    pytest.importorskip("mcp")
    from ai_log_analyzer.mcp_server import server as srv_mod

    monkeypatch.setenv("NETLOG_MCP_ALLOW_WRITE", "1")
    server = srv_mod._build_server()

    def add(source_id, **extra):
        res = asyncio.run(server.call_tool("add_source", {
            "source_id": source_id, "source_type": "syslog", "url": "udp://127.0.0.1",
            "extra": {"port": str(_free_port()), "bind": "127.0.0.1", **{k: str(v) for k, v in extra.items()}}}))
        return res.structured_content

    try:
        out = add("p1", spool=tmp_path / "elsewhere" / "x.db")
        assert out["ok"] is False and not (tmp_path / "elsewhere").exists()
        assert add("p2", tls_cert=tmp_path / "c.pem", proto="tls")["ok"] is False
        assert add("p3", spool=data_dir / "mcp.db")["ok"] is True
        assert (data_dir / "mcp.db").is_file()
    finally:
        for sid in ("p1", "p2", "p3"):
            srv_mod.source_manager.remove(sid)


# ── operator configuration keeps working ────────────────────────────────────

def test_operator_environment_may_point_a_spool_anywhere(data_dir, tmp_path, monkeypatch):
    elsewhere = tmp_path / "var-spool" / "op.db"
    for key, value in (("TYPE", "syslog"), ("URL", "udp://127.0.0.1"), ("PORT", str(_free_port())),
                       ("BIND", "127.0.0.1"), ("SPOOL", str(elsewhere))):
        monkeypatch.setenv(f"NETLOG_SOURCE_op1_{key}", value)
    mgr = SourceManager()
    try:
        assert mgr.load_from_env() == ["op1"]
        assert elsewhere.is_file()
    finally:
        mgr.shutdown()


def test_code_registering_a_source_directly_is_not_restricted(data_dir, tmp_path):
    cfg = SourceConfig(id="code1", type="syslog", url="", extra={
        "port": str(_free_port()), "bind": "127.0.0.1", "spool": str(tmp_path / "anywhere" / "c.db")})
    mgr = SourceManager()
    try:
        mgr.add(cfg)
        assert (tmp_path / "anywhere" / "c.db").is_file()
        with pytest.raises(SourceError):
            mgr.add(SourceConfig(id="code2", type="syslog", url="", extra={
                "port": str(_free_port()), "bind": "127.0.0.1", "spool": str(tmp_path / "nope" / "d.db")}),
                trusted=False)
        assert not (tmp_path / "nope").exists()
    finally:
        mgr.shutdown()
