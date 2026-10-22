"""SolarWinds Orion + Observability SaaS connector — mocked, no network."""
from __future__ import annotations

import argparse
import base64
import json
import logging
import socket
from pathlib import Path
from typing import Any

import pytest
import requests

from ai_log_analyzer import __version__
from ai_log_analyzer.cli import cmd_analyze
from ai_log_analyzer.sources import SourceConfig, SourceError, registry
from ai_log_analyzer.sources.manager import SourceManager
from ai_log_analyzer.sources.solarwinds import (
    SolarWindsConfig,
    SolarWindsConnector,
    SolarWindsInterfaceTelemetry,
    build_site_manifest,
    fetch_interface_telemetry,
    normalize_alert,
    normalize_event,
    normalize_syslog,
)
from ai_log_analyzer.sources.telemetry import InterfaceTelemetrySnapshot
from ai_log_analyzer.web.app import create_app
from ai_log_analyzer.web.app import source_manager as web_manager


@pytest.fixture(autouse=True)
def _fake_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sources resolve + check hostnames at registration (fail closed); the
    example hosts used here must resolve to a public address, offline."""
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda host, port, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port or 0))],
    )


class _MockResponse:
    def __init__(self, status_code: int = 200, json_data: Any = None) -> None:
        self.status_code = status_code
        self._json = json_data if json_data is not None else {}
        self.text = json.dumps(self._json)
        self.content = self.text.encode("utf-8") if self._json != {} or status_code == 200 else b""

    def json(self) -> Any:
        return self._json

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"{self.status_code}")


def _joined_alert() -> dict[str, Any]:
    return {
        "AlertActiveID": 77,
        "AlertObjectID": 42,
        "TriggeredDateTime": "2026-10-15T08:00:00Z",
        "TriggeredMessage": "High Response Time",
        "Severity": "Warning",
        "Name": "Node Response Time",
        "EntityCaption": "core-sw-01",
        "RelatedNodeCaption": "core-sw-01",
    }


def _syslog_row() -> dict[str, Any]:
    return {
        "DateTime": "2026-10-15T08:01:00Z",
        "Caption": "leaf-01",
        "IPAddress": "192.0.2.10",
        "Message": "bgp peer 192.0.2.1 down hold timer expired",
        "LogLevel": "err",
        "SysLogSeverity": "err",
    }


def _event_row() -> dict[str, Any]:
    return {
        "EventTime": "2026-10-15T08:02:00Z",
        "Caption": "spine-01",
        "Message": "Interface Ethernet1 changed to down",
        "EventType": "warning",
    }


def _connector(**kwargs: Any) -> SolarWindsConnector:
    defaults: dict[str, Any] = {
        "endpoint_url": "https://orion.example.test:17778",
        "mode": "swis",
    }
    defaults.update(kwargs)
    return SolarWindsConnector(SolarWindsConfig(**defaults))


def _query_of(kwargs: dict[str, Any]) -> str:
    body = kwargs.get("json")
    if isinstance(body, dict):
        return str(body.get("query") or "")
    return ""


@pytest.mark.unit
def test_solarwinds_is_registered_as_source_kind() -> None:
    assert registry.is_registered("solarwinds")
    src = registry.create(
        SourceConfig(
            id="orion-lab",
            type="solarwinds",
            url="https://orion.example.test:17778",
            api_token="tok",
            auth_methods=("api_token",),
            extra={"mode": "swis"},
        )
    )
    assert src.kind == "solarwinds"
    assert src.name == "orion-lab"
    src.close()


@pytest.mark.unit
def test_from_env_reads_solarwinds_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOLARWINDS_URL", "https://orion.example.test:17778")
    monkeypatch.setenv("SOLARWINDS_USERNAME", "orion")
    monkeypatch.setenv("SOLARWINDS_PASSWORD", "s3cret")
    monkeypatch.setenv("SOLARWINDS_TOKEN", "tok-abc")
    monkeypatch.setenv("SOLARWINDS_MODE", "saas")
    monkeypatch.setenv("SOLARWINDS_VERIFY_SSL", "false")
    cfg = SolarWindsConfig.from_env()
    assert cfg.endpoint_url == "https://orion.example.test:17778"
    assert cfg.username == "orion"
    assert cfg.password == "s3cret"
    assert cfg.api_token == "tok-abc"
    assert cfg.mode == "saas"
    assert cfg.verify_ssl is False


@pytest.mark.unit
def test_from_env_missing_url_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SOLARWINDS_URL", raising=False)
    with pytest.raises(SourceError, match="SOLARWINDS_URL"):
        SolarWindsConfig.from_env()


@pytest.mark.unit
def test_swql_binds_parameters_never_interpolates() -> None:
    conn = _connector()
    captured: list[dict[str, Any]] = []

    def dummy_request(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        captured.append(kwargs.get("json") or {})
        return {"results": []}

    conn._request = dummy_request  # type: ignore[method-assign]
    evil = "leaf'; DROP TABLE Nodes--"
    conn.pull_logs(limit=10, since_seconds=120, host_filter=evil, include_alerts=True)
    assert captured, "expected SWQL POSTs"
    for body in captured:
        assert "query" in body
        assert "parameters" in body
        assert evil not in body["query"]
        assert "@since" in body["query"]
        assert body["parameters"]["host"] == evil
        assert "since" in body["parameters"]


@pytest.mark.unit
def test_alert_query_joins_alert_objects_and_configurations() -> None:
    conn = _connector()
    seen: list[str] = []

    def dummy_request(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        query = _query_of(kwargs)
        seen.append(query)
        if "AlertActive" in query:
            assert "Orion.AlertObjects" in query
            assert "Orion.AlertConfigurations" in query
            assert "AlertActiveID" in query
            assert "AlertObjectID" in query
            assert "TriggeredDateTime" in query
            assert "TriggeredMessage" in query
            assert "ac.Severity" in query
            assert "ac.Name" in query
            assert "ao.EntityCaption" in query
            assert "ao.RelatedNodeCaption" in query
            return {"results": [_joined_alert()]}
        return {"results": []}

    conn._request = dummy_request  # type: ignore[method-assign]
    lines = conn.pull_logs(limit=10, include_syslog=False, include_events=False)
    assert any("AlertActive" in q for q in seen)
    assert lines == [
        "2026-10-15T08:00:00Z core-sw-01 SolarWindsAlert[Warning]: High Response Time"
    ]


@pytest.mark.unit
def test_syslog_and_events_normalize_to_program_severity_shape() -> None:
    assert normalize_syslog(_syslog_row()) == (
        "2026-10-15T08:01:00Z leaf-01 SolarWindsSyslog[err]: "
        "bgp peer 192.0.2.1 down hold timer expired"
    )
    assert normalize_event(_event_row()) == (
        "2026-10-15T08:02:00Z spine-01 SolarWindsEvent[warning]: "
        "Interface Ethernet1 changed to down"
    )


@pytest.mark.unit
def test_orion_syslog_fallback_when_olm_http_errors() -> None:
    conn = _connector()
    queries: list[str] = []

    def dummy_request(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        query = _query_of(kwargs)
        queries.append(query)
        if "Orion.OLM.LogEntry" in query:
            raise requests.exceptions.HTTPError("404")
        if "Orion.SysLog" in query:
            assert "Orion.Nodes" in query
            assert "Caption" in query
            assert "IPAddress" in query
            return {"results": [_syslog_row()]}
        return {"results": []}

    conn._request = dummy_request  # type: ignore[method-assign]
    lines = conn.pull_logs(limit=10, include_alerts=False, include_events=False)
    assert any("Orion.OLM.LogEntry" in q for q in queries)
    assert any("Orion.SysLog" in q for q in queries)
    assert lines == [
        "2026-10-15T08:01:00Z leaf-01 SolarWindsSyslog[err]: "
        "bgp peer 192.0.2.1 down hold timer expired"
    ]


@pytest.mark.unit
def test_orion_events_query_joins_nodes() -> None:
    conn = _connector()
    queries: list[str] = []

    def dummy_request(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        query = _query_of(kwargs)
        queries.append(query)
        if "Orion.Events" in query:
            assert "Orion.Nodes" in query
            assert "EventTime" in query
            return {"results": [_event_row()]}
        return {"results": []}

    conn._request = dummy_request  # type: ignore[method-assign]
    lines = conn.pull_logs(limit=10, include_alerts=False, include_syslog=False)
    assert any("Orion.Events" in q for q in queries)
    assert "SolarWindsEvent[warning]" in lines[0]


@pytest.mark.unit
def test_saas_pagination_cursor_then_page() -> None:
    conn = _connector(mode="saas", api_token="tok")
    calls: list[dict[str, Any]] = []

    def dummy_request(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        params = dict(kwargs.get("params") or {})
        calls.append({"path": path, "params": params})
        if path == "v1/logs":
            if params.get("cursor") == "c1":
                return {"logs": [{"timestamp": "t2", "hostname": "h2", "message": "second", "severity": "info"}]}
            return {
                "logs": [{"timestamp": "t1", "hostname": "h1", "message": "first", "severity": "info"}],
                "nextCursor": "c1",
            }
        if path == "v1/alerts":
            if params.get("page") == 2:
                return {"alerts": []}
            return {
                "alerts": [{
                    "name": "Interface down",
                    "severity": "Critical",
                    "triggeredAt": "2026-10-15T12:00:00Z",
                    "entityName": "core-sw-01",
                }],
                "pageInfo": {"hasNextPage": False},
            }
        raise AssertionError(path)

    conn._request = dummy_request  # type: ignore[method-assign]
    lines = conn.pull_logs(limit=10)
    log_calls = [c for c in calls if c["path"] == "v1/logs"]
    assert any(c["params"].get("cursor") == "c1" for c in log_calls)
    assert any("SolarWindsLog[info]: first" in line or "h1" in line for line in lines)
    assert any("SolarWindsAlert[Critical]: Interface down" in line for line in lines)


@pytest.mark.unit
def test_build_site_manifest_shape() -> None:
    conn = _connector()

    def dummy_request(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        query = _query_of(kwargs)
        if "Orion.Nodes" in query:
            assert "parameters" in (kwargs.get("json") or {})
            return {"results": [
                {"NodeID": 1, "Caption": "leaf-01", "IPAddress": "192.0.2.10",
                 "Status": 1, "Vendor": "Arista", "MachineType": "DCS-7280", "Location": "AMS1"},
                {"NodeID": 2, "Caption": "spine-01", "IPAddress": "192.0.2.11",
                 "Status": 1, "Vendor": "Arista", "MachineType": "DCS-7800", "Location": "AMS1"},
            ]}
        if "Orion.TopologyConnections" in query:
            return {"results": [
                {"NodeID": 1, "DestNodeID": 2, "InterfaceID": "Eth1", "DestInterfaceID": "Eth49"},
            ]}
        return {"results": []}

    conn._request = dummy_request  # type: ignore[method-assign]
    manifest = build_site_manifest("AMS1", connector=conn)
    assert manifest["source"] == "solarwinds"
    assert manifest["site"] == "AMS1"
    assert manifest["configured"] is True
    hosts = {d["hostname"] for d in manifest["devices"]}
    assert hosts == {"leaf-01", "spine-01"}
    assert {"a": "leaf-01", "b": "spine-01", "a_iface": "Eth1", "b_iface": "Eth49"} in manifest["links"] \
        or {"a": "spine-01", "b": "leaf-01", "a_iface": "Eth49", "b_iface": "Eth1"} in manifest["links"] \
        or manifest["links"][0]["a"] in hosts
    assert "spine-01" in manifest["adjacency"]["leaf-01"]
    assert "skipped_terminations" in manifest


@pytest.mark.unit
def test_fetch_interface_telemetry_maps_npm_counters() -> None:
    conn = _connector()

    def dummy_request(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        body = kwargs.get("json") or {}
        assert body["parameters"] == {"device": "leaf-01", "interface": "Ethernet1"}
        assert "leaf-01" not in body["query"]
        assert "Orion.NPM.Interfaces" in body["query"]
        return {"results": [{
            "InErrorsToday": 4,
            "OutErrorsToday": 6,
            "InDiscardsToday": 12,
            "OutDiscardsToday": 8,
            "Status": 1,
            "Caption": "Ethernet1",
            "NodeCaption": "leaf-01",
        }]}

    conn._request = dummy_request  # type: ignore[method-assign]
    snap = fetch_interface_telemetry("leaf-01", "Ethernet1", connector=conn)
    assert isinstance(snap, InterfaceTelemetrySnapshot)
    assert isinstance(snap, SolarWindsInterfaceTelemetry)
    assert snap.device == "leaf-01"
    assert snap.interface == "Ethernet1"
    assert snap.fcs_crc_errors_delta == 10
    assert snap.in_discards_delta == 12
    assert snap.out_discards_delta == 8
    assert snap.status == "1"


@pytest.mark.unit
def test_writeback_invoke_payloads() -> None:
    conn = _connector()
    captured: list[tuple[str, Any]] = []

    def dummy_request(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        captured.append((path, kwargs.get("json")))
        return {"ok": True}

    conn._request = dummy_request  # type: ignore[method-assign]
    conn.append_alert_note(42, "RCA: fiber cut on leaf-01 Ethernet1")
    conn.acknowledge_alert([42, 43], "acked by netlog-ai")
    assert captured[0][0].endswith("Orion.AlertActive/AppendNote")
    assert captured[0][1] == [42, "RCA: fiber cut on leaf-01 Ethernet1"]
    assert captured[1][0].endswith("Orion.AlertActive/Acknowledge")
    assert captured[1][1] == [[42, 43], "acked by netlog-ai"]


@pytest.mark.unit
def test_writeback_does_not_log_credentials(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
) -> None:
    def fake_request(method: str, url: str, **req_kwargs: Any) -> _MockResponse:
        return _MockResponse(200, {"ok": True})

    conn = _connector(username="orion", password="s3cret-password")
    monkeypatch.setattr(conn.session, "request", fake_request)
    with caplog.at_level(logging.DEBUG, logger="ai_log_analyzer.sources.solarwinds"):
        conn.append_alert_note(1, "note")
    assert "s3cret-password" not in caplog.text


@pytest.mark.unit
def test_saas_writeback_rejected() -> None:
    conn = _connector(mode="saas", api_token="tok")
    with pytest.raises(SourceError, match="SWIS"):
        conn.append_alert_note(1, "nope")


@pytest.mark.unit
@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"api_token": "tok-abc"}, "Bearer tok-abc"),
        (
            {"username": "orion", "password": "s3cret"},
            "Basic " + base64.b64encode(b"orion:s3cret").decode("ascii"),
        ),
    ],
)
def test_request_sets_bearer_or_basic_authorization_header(
    monkeypatch: pytest.MonkeyPatch,
    kwargs: dict[str, str],
    expected: str,
) -> None:
    captured: dict[str, Any] = {}

    def fake_request(method: str, url: str, **req_kwargs: Any) -> _MockResponse:
        captured["method"] = method
        captured["url"] = url
        captured["headers"] = req_kwargs.get("headers") or {}
        return _MockResponse(200, {})

    conn = _connector(**kwargs)
    monkeypatch.setattr(conn.session, "request", fake_request)
    conn._request("GET", "v1/alerts")
    headers = captured["headers"]
    assert headers["Authorization"] == expected
    assert headers["User-Agent"] == f"netlog-ai/{__version__}"
    assert captured["url"].endswith("/v1/alerts")


@pytest.mark.unit
def test_from_config_fetch_yields_logevents() -> None:
    cfg = SourceConfig(
        id="sw1",
        type="solarwinds",
        url="https://orion.example.test:17778",
        api_token="tok",
        auth_methods=("api_token",),
    )
    src = SolarWindsConnector.from_config(cfg)

    def dummy_request(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        query = _query_of(kwargs)
        if "AlertActive" in query:
            return {"results": [_joined_alert()]}
        return {"results": []}

    src._request = dummy_request  # type: ignore[method-assign]
    events = list(src.fetch(limit=10, host_filter="core-sw-01"))
    assert len(events) == 1
    assert events[0].hostname == "core-sw-01"
    assert events[0].appname == "SolarWindsAlert"
    assert events[0].severity_raw == "Warning"
    assert events[0].message == "High Response Time"
    src.close()


@pytest.mark.unit
def test_manager_dispatches_solarwinds_fetch() -> None:
    mgr = SourceManager()
    mgr.add(SourceConfig(
        id="orion",
        type="solarwinds",
        url="https://orion.example.test:17778",
        api_token="tok",
        auth_methods=("api_token",),
    ))
    src = mgr.get("orion")
    assert src is not None

    def dummy_request(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        if "AlertActive" in _query_of(kwargs):
            return {"results": [_joined_alert()]}
        return {"results": []}

    src._request = dummy_request  # type: ignore[method-assign]
    events = mgr.fetch("orion", limit=5)
    assert len(events) == 1
    assert events[0].hostname == "core-sw-01"
    mgr.remove("orion")


@pytest.mark.unit
def test_manager_load_from_native_solarwinds_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOLARWINDS_URL", "https://orion.example.test:17778")
    monkeypatch.setenv("SOLARWINDS_TOKEN", "tok")
    monkeypatch.setenv("SOLARWINDS_MODE", "swis")
    mgr = SourceManager()
    added = mgr.load_from_env()
    assert "solarwinds" in added
    src = mgr.get("solarwinds")
    assert src is not None
    assert src.kind == "solarwinds"
    mgr.shutdown()


@pytest.mark.unit
def test_normalize_alert_saas_entity_object() -> None:
    line = normalize_alert(
        {
            "message": "Node is Down",
            "severity": "Critical",
            "triggeredAt": "2026-10-15T08:00:00Z",
            "entity": {"name": "leaf-01", "id": "e-9"},
        }
    )
    assert line == "2026-10-15T08:00:00Z leaf-01 SolarWindsAlert[Critical]: Node is Down"


@pytest.mark.unit
def test_cli_analyze_source_solarwinds(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("NETLOG_SOURCE_orion_TYPE", "solarwinds")
    monkeypatch.setenv("NETLOG_SOURCE_orion_URL", "https://orion.example.test:17778")
    monkeypatch.setenv("NETLOG_SOURCE_orion_API_TOKEN", "tok")

    def fake_pull(self: SolarWindsConnector, limit: int = 100, **kwargs: Any) -> list[str]:
        return [
            "2026-10-15T08:00:00Z core-sw SolarWindsAlert[Critical]: "
            "bgp peer 192.0.2.1 down hold timer expired"
        ]

    monkeypatch.setattr(SolarWindsConnector, "pull_logs", fake_pull)
    ns = argparse.Namespace(
        frr=None,
        file=None,
        stdin=False,
        tail=100,
        no_llm=True,
        dedup=False,
        evpn_causal=False,
        remediation=False,
        source="solarwinds",
    )
    rc = cmd_analyze(ns)
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["severity_counts"]["high"] == 1


@pytest.mark.unit
def test_cli_source_help_lists_solarwinds(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("sys.argv", ["ai-log-analyzer", "analyze", "--help"])
    with pytest.raises(SystemExit) as exc:
        from ai_log_analyzer.cli import main
        main()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "solarwinds" in out
    assert "SOLARWINDS_URL" in out


@pytest.mark.unit
def test_cli_source_unknown_exits_2(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ns = argparse.Namespace(
        frr=None,
        file=None,
        stdin=False,
        tail=100,
        no_llm=True,
        dedup=False,
        source="does-not-exist",
    )
    rc = cmd_analyze(ns)
    assert rc == 2
    assert "unknown source" in capsys.readouterr().err


@pytest.mark.unit
def test_connector_satisfies_logsource_protocol() -> None:
    from ai_log_analyzer.sources import LogSource

    src = _connector(api_token="tok")
    assert isinstance(src, LogSource)
    src.close()


@pytest.mark.unit
def test_api_sources_lists_solarwinds_kind() -> None:
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()
    resp = client.get("/api/sources")
    assert resp.status_code == 200
    body = resp.get_json()
    assert "solarwinds" in body["known_kinds"]


@pytest.mark.unit
def test_api_analyze_dispatches_solarwinds(monkeypatch: pytest.MonkeyPatch) -> None:
    app = create_app()
    app.config.update(TESTING=True)
    cfg = SourceConfig(
        id="orion-web",
        type="solarwinds",
        url="https://orion.example.test:17778",
        api_token="tok",
        auth_methods=("api_token",),
    )
    web_manager.add(cfg)
    src = web_manager.get("orion-web")
    assert src is not None

    def fake_pull(self: SolarWindsConnector, limit: int = 100, **kwargs: Any) -> list[str]:
        return [
            "2026-10-15T08:00:00Z core-sw SolarWindsAlert[Critical]: "
            "bgp peer 192.0.2.1 down hold timer expired"
        ]

    monkeypatch.setattr(SolarWindsConnector, "pull_logs", fake_pull)
    try:
        client = app.test_client()
        resp = client.post("/api/analyze", json={"source": "orion-web", "use_llm": False})
        assert resp.status_code == 200
        assert resp.get_json()["severity_counts"]["high"] == 1
    finally:
        web_manager.remove("orion-web")


@pytest.mark.unit
def test_index_html_lists_solarwinds_connector() -> None:
    html = (Path(__file__).resolve().parents[1]
            / "src/ai_log_analyzer/web/static/index.html").read_text(encoding="utf-8")
    js = (Path(__file__).resolve().parents[1]
          / "src/ai_log_analyzer/web/static/app.js").read_text(encoding="utf-8")
    assert "SolarWinds" in html
    assert "connector-source" in html
    assert "loadConnectorSources" in js
    assert "/api/sources" in js


@pytest.mark.unit
def test_mcp_solarwinds_tools_registered() -> None:
    pytest.importorskip("mcp")
    import asyncio

    from ai_log_analyzer.mcp_server.server import _build_server

    srv = _build_server()
    names = {tool.name for tool in asyncio.run(srv.list_tools())}
    assert "fetch_solarwinds_logs" in names
    assert "fetch_solarwinds_alerts" in names
    assert "push_solarwinds_alert_note" in names


@pytest.mark.unit
def test_mcp_fetch_and_explicit_push_note() -> None:
    pytest.importorskip("mcp")
    import asyncio

    from ai_log_analyzer.mcp_server.server import _build_server
    from ai_log_analyzer.mcp_server.server import source_manager as mcp_mgr

    cfg = SourceConfig(
        id="orion-mcp",
        type="solarwinds",
        url="https://orion.example.test:17778",
        api_token="tok",
        auth_methods=("api_token",),
    )
    mcp_mgr.add(cfg)
    src = mcp_mgr.get("orion-mcp")
    assert src is not None
    paths: list[str] = []

    def dummy_request(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        paths.append(path)
        query = _query_of(kwargs)
        if "Orion.SysLog" in query or "Orion.OLM" in query:
            return {"results": [_syslog_row()]}
        if "Orion.Events" in query:
            return {"results": [_event_row()]}
        if "AlertActive" in query and method == "POST" and "Query" in path:
            return {"results": [_joined_alert()]}
        if "AppendNote" in path:
            return {"ok": True}
        return {"results": []}

    src._request = dummy_request  # type: ignore[method-assign]
    try:
        srv = _build_server()
        logs = asyncio.run(srv.call_tool(
            "fetch_solarwinds_logs", {"source_id": "orion-mcp", "limit": 10},
        ))
        alerts = asyncio.run(srv.call_tool(
            "fetch_solarwinds_alerts", {"source_id": "orion-mcp"},
        ))
        note = asyncio.run(srv.call_tool(
            "push_solarwinds_alert_note",
            {"source_id": "orion-mcp", "alert_object_id": 42, "note": "RCA: fiber cut"},
        ))
        assert logs.is_error is False
        assert alerts.is_error is False
        assert note.is_error is False
        assert any("AppendNote" in p for p in paths)
        assert not any("Acknowledge" in p for p in paths)
    finally:
        mcp_mgr.remove("orion-mcp")
