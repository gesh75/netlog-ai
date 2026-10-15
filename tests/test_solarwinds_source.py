"""SolarWinds Orion + Observability SaaS connector — mocked, no network."""
from __future__ import annotations

import argparse
import base64
import json
import logging
from typing import Any

import pytest
import requests

from ai_log_analyzer import __version__
from ai_log_analyzer.cli import cmd_analyze
from ai_log_analyzer.sources import SourceConfig, registry
from ai_log_analyzer.sources.solarwinds import (
    SolarWindsConfig,
    SolarWindsConnector,
    normalize_alert,
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


def _orion_alert() -> dict[str, Any]:
    return {
        "AlertMessage": "High Response Time",
        "Severity": "Warning",
        "TriggerTime": "2026-10-15T08:00:00Z",
        "EntityNetObjectId": "N:1234",
    }


def _connector(**kwargs: Any) -> SolarWindsConnector:
    defaults: dict[str, Any] = {"endpoint_url": "https://orion.example.test:17778"}
    defaults.update(kwargs)
    return SolarWindsConnector(SolarWindsConfig(**defaults))


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
        )
    )
    assert src.kind == "solarwinds"
    assert src.name == "orion-lab"
    src.close()


@pytest.mark.unit
def test_pull_logs_dummy_request_normalizes_orion_alert() -> None:
    """The given dummy `_request` path: Orion SWQL results → syslog-shaped lines."""
    conn = _connector()

    def dummy_request(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        assert method == "POST"
        assert path == "/SolarWinds/InformationService/v3/Json/Query"
        assert kwargs.get("json", {}).get("query", "").startswith("SELECT AlertMessage")
        return {"results": [_orion_alert()]}

    conn._request = dummy_request  # type: ignore[method-assign]
    lines = conn.pull_logs(limit=100)
    assert lines == [
        "2026-10-15T08:00:00Z N:1234 SolarWindsAlert[Warning]: High Response Time"
    ]


@pytest.mark.unit
def test_fetch_active_alerts_http_error_falls_back_to_saas() -> None:
    conn = _connector()
    calls: list[tuple[str, str]] = []

    def dummy_request(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append((method, path))
        if "InformationService" in path:
            raise requests.exceptions.HTTPError("503 Server Error")
        assert method == "GET"
        assert path == "v1/alerts"
        assert kwargs.get("params") == {"status": "active"}
        return {
            "alerts": [
                {
                    "name": "Interface down",
                    "severity": "Critical",
                    "triggeredAt": "2026-10-15T12:00:00Z",
                    "entityName": "core-sw-01",
                }
            ]
        }

    conn._request = dummy_request  # type: ignore[method-assign]
    alerts = conn.fetch_active_alerts()
    assert len(alerts) == 1
    assert ("POST", "/SolarWinds/InformationService/v3/Json/Query") in calls
    assert ("GET", "v1/alerts") in calls
    assert conn.pull_logs() == [
        "2026-10-15T12:00:00Z core-sw-01 SolarWindsAlert[Critical]: Interface down"
    ]


@pytest.mark.unit
def test_fetch_active_alerts_does_not_fallback_on_generic_exception() -> None:
    conn = _connector()

    def dummy_request(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        raise ValueError("malformed SWIS payload")

    conn._request = dummy_request  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="malformed"):
        conn.fetch_active_alerts()


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
def test_request_does_not_log_credentials(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def fake_request(method: str, url: str, **req_kwargs: Any) -> _MockResponse:
        return _MockResponse(200, {})

    conn = _connector(username="orion", password="s3cret-password")
    monkeypatch.setattr(conn.session, "request", fake_request)
    with caplog.at_level(logging.DEBUG, logger="ai_log_analyzer.sources.solarwinds"):
        conn._request("GET", "v1/alerts")
    assert "s3cret-password" not in caplog.text
    assert "orion:s3cret" not in caplog.text


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
        return {"results": [_orion_alert()]}

    src._request = dummy_request  # type: ignore[method-assign]
    events = list(src.fetch(limit=10, host_filter="N:1234"))
    assert len(events) == 1
    assert events[0].hostname == "N:1234"
    assert events[0].appname == "solarwinds"
    assert events[0].severity_raw == "Warning"
    assert events[0].message == "High Response Time"
    src.close()


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

    def fake_pull(self: SolarWindsConnector, limit: int = 100) -> list[str]:
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
