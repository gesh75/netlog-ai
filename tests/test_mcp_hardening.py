"""MCP server hardening: write gate, transport auth, bounds, sanitization, ReDoS, audit."""
from __future__ import annotations

import asyncio
import socket
import time
from typing import Any

import pytest
import requests

from ai_log_analyzer.classifier import LogEvent

pytestmark = pytest.mark.unit
pytest.importorskip("mcp")

from ai_log_analyzer.mcp_server import server as srv_mod  # noqa: E402

WRITE_TOOLS = {"add_source", "enrich_itsm_incident", "push_solarwinds_alert_note",
               "netlog_servicenow_sync_incident"}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("NETLOG_MCP_ALLOW_WRITE", "NETLOG_MCP_TOKEN", "NETLOG_MCP_HOST", "NETLOG_MCP_PORT",
                 "AI_LOG_ANALYZER_AUDIT_DB", "AI_LOG_ANALYZER_STATE_DB", "NETLOG_ALLOW_PRIVATE_OUTBOUND",
                 "SNOW_URL", "SNOW_USER", "SNOW_PASSWORD", "JIRA_BASE_URL",
                 "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def server():
    return srv_mod._build_server()


def call(server, name: str, args: dict | None = None) -> dict[str, Any]:
    res = asyncio.run(server.call_tool(name, args or {}))
    assert res.is_error is False, res
    return res.structured_content or {}


def _events(n: int = 3, message: str = "bgp neighbor 10.0.0.1 down") -> list[LogEvent]:
    return [LogEvent(f"Oct 13 10:00:0{i % 10}", f"leaf{i}", "rpd", "err", message) for i in range(n)]


# ── C3: annotations ──────────────────────────────────────────────────────────

def test_every_tool_has_safety_annotations(server) -> None:
    tools = {t.name: t for t in asyncio.run(server.list_tools())}
    assert tools
    for name, tool in tools.items():
        ann = tool.annotations
        assert ann is not None and ann.read_only_hint is not None, name
        assert ann.read_only_hint is (name not in WRITE_TOOLS), name
        assert ann.destructive_hint is not True, name


# ── C1: write gate ───────────────────────────────────────────────────────────

def test_mutating_tools_are_off_by_default(server, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a, **_k):
        raise AssertionError("must not reach any connector while writes are disabled")

    monkeypatch.setattr(srv_mod.source_manager, "add", boom)
    monkeypatch.setattr(srv_mod, "_solarwinds_connector", boom)
    monkeypatch.setattr("ai_log_analyzer.sources.outbound.safe_urlopen", boom)
    calls = {
        "add_source": {"source_id": "x", "source_type": "loki", "url": "https://l.example.com"},
        "enrich_itsm_incident": {"system": "jira", "device": "leaf1", "vendor": "arista_eos",
                                 "root_cause_summary": "x", "dry_run": False},
        "push_solarwinds_alert_note": {"alert_object_id": 1, "note": "n"},
        "netlog_servicenow_sync_incident": {"log_text": "leaf01 bgp neighbor 10.0.0.1 down",
                                            "instance_url": "https://o.service-now.com", "dry_run": False},
    }
    for name, args in calls.items():
        out = call(server, name, args)
        assert out["ok"] is False and "NETLOG_MCP_ALLOW_WRITE=1" in out["error"], name


def test_dry_run_previews_stay_available(server) -> None:
    out = call(server, "enrich_itsm_incident", {"system": "jira", "device": "leaf1", "vendor": "arista_eos",
                                                "root_cause_summary": "x"})
    assert out["ok"] is True and out["dry_run"] is True
    out = call(server, "netlog_servicenow_sync_incident", {"log_text": "leaf01 bgp neighbor 10.0.0.1 down"})
    assert out["ok"] is True and out["action"] == "preview"


def test_add_source_with_write_enabled_ignores_allow_private(server, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETLOG_MCP_ALLOW_WRITE", "1")
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.7", port or 0))])
    out = call(server, "add_source", {"source_id": "mcp-priv", "source_type": "loki",
                                      "url": "http://internal.example:3100", "api_token": "t",
                                      "extra": {"allow_private": "true"}})
    assert out["ok"] is False and "private" in out["error"]
    assert "mcp-priv" not in srv_mod.source_manager.list_ids()

    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port or 0))])
    out = call(server, "add_source", {"source_id": "mcp-pub", "source_type": "loki",
                                      "url": "https://loki.example.com", "api_token": "t",
                                      "extra": {"allow_private": "true", "query": "{job=\"x\"}"}})
    try:
        assert out["ok"] is True and out["ignored_options"] == ["allow_private"]
        cfg = {row["id"]: row for row in srv_mod.source_manager.describe()}["mcp-pub"]
        assert "allow_private" not in cfg["extra"] and cfg["extra"]["query"] == '{job="x"}'
    finally:
        srv_mod.source_manager.remove("mcp-pub")


# ── A via MCP: caller-chosen instance_url cannot receive server credentials ──

def test_servicenow_sync_cannot_exfiltrate_env_credentials(server, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETLOG_MCP_ALLOW_WRITE", "1")
    monkeypatch.setenv("SERVICENOW_URL", "https://corp.service-now.com")
    monkeypatch.setenv("SERVICENOW_USER", "svc")
    monkeypatch.setenv("SERVICENOW_PASSWORD", "pw-from-env")
    sent: list[Any] = []
    monkeypatch.setattr("ai_log_analyzer.sources.outbound.safe_urlopen",
                        lambda req, *a, **k: sent.append(req) or (_ for _ in ()).throw(AssertionError("sent")))
    out = call(server, "netlog_servicenow_sync_incident", {
        "log_text": "leaf01 bgp neighbor 10.0.0.1 down",
        "instance_url": "https://attacker.example.com", "dry_run": False})
    assert out["ok"] is False and "refusing" in out["error"]
    assert sent == []


def test_servicenow_sync_without_url_uses_the_configured_instance(server, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETLOG_MCP_ALLOW_WRITE", "1")
    monkeypatch.setenv("SERVICENOW_URL", "https://corp.service-now.com")
    monkeypatch.setenv("SERVICENOW_USER", "svc")
    monkeypatch.setenv("SERVICENOW_PASSWORD", "pw-from-env")
    seen: list[str] = []

    class R:
        def read(self):
            return b'{"result": {"number": "INC1", "sys_id": "s"}}'

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr("ai_log_analyzer.sources.outbound.safe_urlopen",
                        lambda req, *a, **k: seen.append(req.full_url) or R())
    out = call(server, "netlog_servicenow_sync_incident", {
        "log_text": "leaf01 bgp neighbor 10.0.0.1 down", "dry_run": False})
    assert out["ok"] is True and out["dry_run"] is False
    assert seen and all(u.startswith("https://corp.service-now.com/") for u in seen)


# ── D: ITSM path safety ──────────────────────────────────────────────────────

def test_enrich_refuses_destructive_commands(server) -> None:
    out = call(server, "enrich_itsm_incident", {
        "system": "servicenow", "device": "leaf1", "vendor": "cisco_ios", "root_cause_summary": "x",
        "config_commands": ["interface Gi0/1", "shutdown", "write erase", "reload"],
        "post_checks": ["show ip bgp summary"]})
    assert out["ok"] is False and "Safety violation" in out["error"]
    assert {v["command"] for v in out["violations"]} == {"write erase", "reload"}
    assert all(v["field"] == "config_commands" for v in out["violations"])

    out = call(server, "enrich_itsm_incident", {
        "system": "jira", "device": "leaf1", "vendor": "cisco_ios", "root_cause_summary": "x",
        "post_checks": ["reload in 5"], "config_commands": ["interface Gi0/1", "shutdown"]})
    assert out["ok"] is False and out["violations"][0]["field"] == "post_checks"


def test_enrich_unknown_vendor_is_an_error_not_eos(server) -> None:
    out = call(server, "enrich_itsm_incident", {
        "system": "jira", "device": "leaf1", "vendor": "acme_os", "root_cause_summary": "x",
        "config_commands": ["interface Gi0/1", "shutdown"]})
    assert out["ok"] is False and "acme_os" in out["error"] and "arista_eos" in out["valid_vendors"]


def test_enrich_rejects_out_of_range_rollback(server) -> None:
    out = call(server, "enrich_itsm_incident", {
        "system": "jira", "device": "leaf1", "vendor": "arista_eos", "root_cause_summary": "x",
        "config_commands": ["interface Ethernet1", "shutdown"], "rollback_minutes": 9999})
    assert out["ok"] is False and "rollback_minutes" in out["error"]


# ── C4/C5/C7: bounds, sanitization, error containment ────────────────────────

def test_limits_are_clamped(server, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[dict] = []

    def fake_fetch(source_id, *, since_seconds, limit, host_filter):
        seen.append({"since": since_seconds, "limit": limit})
        return _events()

    monkeypatch.setattr(srv_mod.source_manager, "fetch", fake_fetch)
    call(server, "fetch_logs", {"source_id": "s", "limit": 10**9, "since_seconds": 10**12})
    call(server, "search_logs", {"source_id": "s", "pattern": "bgp", "limit": 10**9, "max_matches": 10**9,
                                 "since_seconds": 10**12})
    call(server, "analyze_logs", {"source_id": "s", "limit": 10**9, "since_seconds": 10**12})
    out = call(server, "get_top_offenders", {"source_id": "s", "limit": 10**9, "top_n": 10**9,
                                             "since_seconds": 10**12})
    assert [c["limit"] for c in seen] == [5000, 10_000, 10_000, 10_000]
    assert all(c["since"] == 30 * 86_400 for c in seen)
    assert len(out["offenders"]) <= 100


def test_returned_log_text_is_sanitized_and_search_runs_on_sanitized_text(
        server, monkeypatch: pytest.MonkeyPatch) -> None:
    secret_line = "config: snmp-server community HUNTER2SECRET RO"
    monkeypatch.setattr(srv_mod.source_manager, "fetch", lambda *a, **k: _events(2, secret_line))
    out = call(server, "fetch_logs", {"source_id": "s"})
    assert "HUNTER2SECRET" not in str(out) and "<REDACTED>" in out["events"][0]["message"]
    found = call(server, "search_logs", {"source_id": "s", "pattern": "snmp-server community"})
    assert found["match_count"] == 2 and "HUNTER2SECRET" not in str(found)
    # a regex cannot be used as an oracle for the redacted value
    assert call(server, "search_logs", {"source_id": "s", "pattern": "HUNTER2"})["match_count"] == 0


def test_solarwinds_output_is_sanitized(server, monkeypatch: pytest.MonkeyPatch) -> None:
    class Conn:
        def pull_logs(self, **_k):
            return ["t h SolarWindsSyslog[err]: snmp-server community HUNTER2SECRET RO"]

        def fetch_active_alerts(self, **_k):
            return [{"TriggeredMessage": "snmp-server community HUNTER2SECRET RO", "n": 1}]

    monkeypatch.setattr(srv_mod, "_solarwinds_connector", lambda sid="": Conn())
    assert "HUNTER2SECRET" not in str(call(server, "fetch_solarwinds_logs"))
    assert "HUNTER2SECRET" not in str(call(server, "fetch_solarwinds_alerts"))


def test_search_logs_regex_timeout_is_reported(server, monkeypatch: pytest.MonkeyPatch) -> None:
    class Slow:
        def search(self, text, timeout=None):
            assert timeout and timeout <= 0.1          # a per-line deadline is always passed
            raise TimeoutError

    monkeypatch.setattr(srv_mod.regex, "compile", lambda *a, **k: Slow())
    monkeypatch.setattr(srv_mod.source_manager, "fetch", lambda *a, **k: _events(50))
    out = call(server, "search_logs", {"source_id": "s", "pattern": "(a+)+$"})
    assert out["ok"] is False and "expensive" in out["error"]


def test_search_logs_redos_pattern_is_bounded(server, monkeypatch: pytest.MonkeyPatch) -> None:
    if not hasattr(srv_mod.regex, "__version__"):
        pytest.skip("real `regex` module (with timeout support) not installed")
    monkeypatch.setattr(srv_mod.source_manager, "fetch",
                        lambda *a, **k: _events(50, "a" * 26 + "!"))
    start = time.monotonic()
    out = call(server, "search_logs", {"source_id": "s", "pattern": "(a+)+$"})
    assert time.monotonic() - start < 3.0               # was 5.7 s per 26-char line with stdlib re
    # The real `regex` engine may finish this input quickly or hit the timeout; either is bounded.
    assert out["ok"] is True or "expensive" in out["error"]


def test_search_logs_timeout_path_returns_an_error_and_passes_the_timeout(server, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    class _Slow:
        def search(self, text: str, timeout: float | None = None):
            seen["timeout"] = timeout
            raise TimeoutError

    monkeypatch.setattr(srv_mod.regex, "compile", lambda *a, **k: _Slow())
    monkeypatch.setattr(srv_mod.source_manager, "fetch", lambda *a, **k: _events(3, "x"))
    out = call(server, "search_logs", {"source_id": "s", "pattern": "x"})
    assert out["ok"] is False and "expensive" in out["error"]
    assert seen["timeout"] and seen["timeout"] > 0


def test_search_logs_pattern_cap_and_syntax_errors(server) -> None:
    assert call(server, "search_logs", {"source_id": "s", "pattern": "x" * 501})["ok"] is False
    assert call(server, "search_logs", {"source_id": "s", "pattern": "("})["ok"] is False


@pytest.mark.parametrize("exc", [
    requests.exceptions.HTTPError("503 Server Error"),
    requests.exceptions.ConnectionError("refused"),
    ValueError("bad window"),
    TimeoutError("slow"),
])
def test_connector_errors_are_contained(server, monkeypatch: pytest.MonkeyPatch, exc: Exception) -> None:
    def boom(*_a, **_k):
        raise exc

    monkeypatch.setattr(srv_mod.source_manager, "fetch", boom)
    for name, args in (("fetch_logs", {"source_id": "s"}),
                       ("search_logs", {"source_id": "s", "pattern": "x"}),
                       ("analyze_logs", {"source_id": "s"}),
                       ("get_top_offenders", {"source_id": "s"})):
        out = call(server, name, args)
        assert out["ok"] is False and out["error"], name


def test_list_sources_hides_url_credentials(server, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(srv_mod.source_manager, "describe", lambda: [
        {"id": "a", "type": "kibana", "url": "https://elastic:s3cr3t@es.example.com:9200/x", "extra": {}}])
    out = call(server, "list_sources")
    assert "s3cr3t" not in str(out)
    assert out["sources"][0]["url"] == "https://es.example.com:9200/x"


# ── C8: audit ────────────────────────────────────────────────────────────────

def test_tool_calls_are_audited_with_minimal_metadata(server, monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    from ai_log_analyzer import audit

    monkeypatch.setenv("AI_LOG_ANALYZER_AUDIT_DB", str(tmp_path / "audit.db"))
    monkeypatch.setattr(srv_mod.source_manager, "fetch", lambda *a, **k: _events())
    call(server, "list_connector_kinds")
    call(server, "add_source", {"source_id": "x", "source_type": "loki", "url": "https://l.example.com",
                                "extra": {"password": "SUPERSECRETVALUE"}})
    rows = audit.query(limit=10)
    actions = {(r["action"], r["outcome"]) for r in rows}
    assert ("mcp.list_connector_kinds", "ok") in actions
    assert ("mcp.add_source", "error") in actions          # write disabled
    assert "SUPERSECRETVALUE" not in str(rows)


# ── C2: transports ───────────────────────────────────────────────────────────

def test_http_transport_refuses_non_loopback_without_token(monkeypatch: pytest.MonkeyPatch) -> None:
    def never(*_a, **_k):
        raise AssertionError("server must not be built or started")

    monkeypatch.setattr(srv_mod, "_build_server", never)
    monkeypatch.setattr(srv_mod.source_manager, "load_from_env", lambda: [])
    for transport in ("streamable-http", "sse"):
        for host in ("0.0.0.0", "::", "192.0.2.10", "mcp.example.com"):
            monkeypatch.setenv("NETLOG_MCP_HOST", host)
            with pytest.raises(RuntimeError, match="NETLOG_MCP_TOKEN"):
                srv_mod.run(transport)
    with pytest.raises(ValueError):
        srv_mod.run("carrier-pigeon")


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1", "[::1]"])
def test_loopback_bind_is_allowed_without_token(host: str) -> None:
    srv_mod._check_http_exposure(host, "")
    srv_mod._check_http_exposure("0.0.0.0", "tok")


def _asgi(app, headers: list[tuple[bytes, bytes]], scope_type: str = "http") -> list[dict]:
    sent: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b""}

    async def send(message):
        sent.append(message)

    asyncio.run(app({"type": scope_type, "headers": headers, "path": "/mcp"}, receive, send))
    return sent


def test_bearer_middleware() -> None:
    reached: list[bool] = []

    async def inner(scope, receive, send):
        reached.append(True)
        if scope["type"] == "http":
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

    app = srv_mod._BearerAuthMiddleware(inner, "s3cret-token")
    for headers in ([], [(b"authorization", b"Bearer wrong")], [(b"authorization", b"s3cret-token")],
                    [(b"authorization", b"Basic czNjcmV0LXRva2Vu")], [(b"authorization", b"Bearer ")]):
        out = _asgi(app, headers)
        assert out[0]["status"] == 401, headers
        assert (b"www-authenticate", b"Bearer") in out[0]["headers"]
    assert reached == []
    out = _asgi(app, [(b"authorization", b"Bearer s3cret-token")])
    assert out[0]["status"] == 200 and reached == [True]
    assert _asgi(app, [], "websocket") == [{"type": "websocket.close", "code": 1008}]
    # lifespan events must reach the wrapped app untouched
    reached.clear()
    _asgi(app, [], "lifespan")
    assert reached == [True]


def test_http_run_wires_token_middleware(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("uvicorn")
    monkeypatch.setenv("NETLOG_MCP_TOKEN", "tok-123")
    monkeypatch.setenv("NETLOG_MCP_HOST", "0.0.0.0")
    monkeypatch.setenv("NETLOG_MCP_PORT", "9911")
    monkeypatch.setattr(srv_mod.source_manager, "load_from_env", lambda: [])
    started: dict[str, Any] = {}
    monkeypatch.setattr("uvicorn.run", lambda app, **kw: started.update(app=app, **kw))
    srv_mod.run("streamable-http")
    assert started["host"] == "0.0.0.0" and started["port"] == 9911
    classes = [m.cls for m in started["app"].user_middleware]
    assert srv_mod._BearerAuthMiddleware in classes


def test_list_sources_never_returns_extra_values(server, monkeypatch: pytest.MonkeyPatch) -> None:
    """list_sources is documented as "no secrets": connector options (API keys, key paths) are names only."""
    monkeypatch.setenv("NETLOG_MCP_ALLOW_WRITE", "1")
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port or 0))])
    call(server, "add_source", {"source_id": "mcp-secret", "source_type": "loki", "url": "https://loki.example.com",
                                "api_token": "t", "extra": {"api_key": "sk-live-SECRETVALUE", "org_id": "tenant-7"}})
    try:
        out = call(server, "list_sources")
        row = next(r for r in out["sources"] if r["id"] == "mcp-secret")
        assert "SECRETVALUE" not in str(out) and "tenant-7" not in str(out)
        assert set(row["extra"]) >= {"api_key", "org_id"} and set(row["extra"].values()) == {"***"}
    finally:
        srv_mod.source_manager.remove("mcp-secret")
