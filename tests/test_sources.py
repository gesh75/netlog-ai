"""Tests for the pluggable LogSource Protocol + connector implementations.

External services (Kibana, Splunk, Loki, LibreNMS) are stubbed with
`requests-mock` style adapters using requests' transport_adapters. We don't
hit any real network — the goal is to lock down the contract.
"""
from __future__ import annotations

import json
import socket
import time
from typing import Any

import pytest

from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.sources import (
    LogSource,
    SourceAuthError,
    SourceConfig,
    SourceError,
    registry,
)
from ai_log_analyzer.sources.base import build_auth
from ai_log_analyzer.sources.manager import SourceManager


# ──────────────────────────────────────────────────────────────────────────────
# Protocol + registry
# ──────────────────────────────────────────────────────────────────────────────

class _StubSource:
    """Minimal LogSource implementation used by Protocol/registry tests."""
    kind = "stub"

    def __init__(self, config: SourceConfig) -> None:
        self.config = config
        self.name = config.id
        self._closed = False

    @classmethod
    def from_config(cls, config: SourceConfig) -> "_StubSource":
        return cls(config)

    def healthcheck(self) -> bool:
        return True

    def fetch(self, *, since_seconds: int = 3600, limit: int = 10000, host_filter: str = ""):
        yield LogEvent(timestamp="2026-01-01T00:00:00",
                       hostname="h1", appname="stub",
                       severity_raw="info", message="hello world")

    def close(self) -> None:
        self._closed = True


@pytest.mark.unit
def test_stub_source_satisfies_protocol():
    cfg = SourceConfig(id="s1", type="stub", url="http://x")
    src = _StubSource(cfg)
    assert isinstance(src, LogSource)


@pytest.mark.unit
def test_registry_register_and_create():
    registry.register("stub-test", _StubSource.from_config)
    cfg = SourceConfig(id="r1", type="stub-test", url="http://x")
    src = registry.create(cfg)
    assert src.name == "r1"
    assert "stub-test" in registry.known()
    assert registry.is_registered("stub-test")


@pytest.mark.unit
def test_registry_unknown_type_raises():
    with pytest.raises(SourceError, match="Unknown source type"):
        registry.create(SourceConfig(id="x", type="does-not-exist", url=""))


# ──────────────────────────────────────────────────────────────────────────────
# Auth helper
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_build_auth_api_token_wins():
    cfg = SourceConfig(id="x", type="t", url="u", api_token="abc",
                       auth_methods=("api_token", "basic"), username="u", password="p")
    headers, cookies, basic = build_auth(cfg)
    assert headers == {"Authorization": "Bearer abc"}
    assert basic is None
    assert cookies == {}


@pytest.mark.unit
def test_build_auth_basic_fallback():
    cfg = SourceConfig(id="x", type="t", url="u",
                       auth_methods=("api_token", "basic"),
                       username="u", password="p")
    headers, cookies, basic = build_auth(cfg)
    assert basic == ("u", "p")
    assert headers == {} and cookies == {}


@pytest.mark.unit
def test_build_auth_cookie_fallback():
    cfg = SourceConfig(id="x", type="t", url="u",
                       auth_methods=("api_token", "basic", "cookie"),
                       cookies={"sid": "abc"})
    headers, cookies, basic = build_auth(cfg)
    assert cookies == {"sid": "abc"}


@pytest.mark.unit
def test_build_auth_all_fail_raises():
    cfg = SourceConfig(id="x", type="t", url="u",
                       auth_methods=("api_token", "basic", "cookie"))
    with pytest.raises(SourceAuthError):
        build_auth(cfg)


# ──────────────────────────────────────────────────────────────────────────────
# Kibana / Elasticsearch — stubbed responses
# ──────────────────────────────────────────────────────────────────────────────

class _MockResponse:
    def __init__(self, status_code: int = 200, json_data: Any = None) -> None:
        self.status_code = status_code
        self._json = json_data or {}
        self.text = json.dumps(self._json)

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            from requests.exceptions import HTTPError
            raise HTTPError(f"{self.status_code}")


@pytest.mark.unit
def test_kibana_healthcheck_green(monkeypatch):
    from ai_log_analyzer.sources.kibana import KibanaSource

    cfg = SourceConfig(id="es1", type="kibana", url="https://es.example.com",
                       api_token="x", auth_methods=("api_token",))
    src = KibanaSource(cfg)
    monkeypatch.setattr(src.session, "get",
                        lambda *a, **k: _MockResponse(200, {"status": "green"}))
    assert src.healthcheck() is True


@pytest.mark.unit
def test_kibana_fetch_normalizes_documents(monkeypatch):
    from ai_log_analyzer.sources.kibana import KibanaSource

    cfg = SourceConfig(id="es1", type="kibana", url="https://es.example.com",
                       api_token="x", auth_methods=("api_token",),
                       extra={"index_pattern": "logs-*"})
    src = KibanaSource(cfg)

    docs = {
        "hits": {
            "hits": [
                {"_source": {
                    "@timestamp": "2026-05-17T10:00:00Z",
                    "host": {"name": "fra4-fw-01"},
                    "process": {"name": "rpd"},
                    "log": {"syslog": {"severity": {"name": "err"}}},
                    "message": "bgp peer 10.0.0.1 down (hold timer expired)",
                }},
                {"_source": {
                    "@timestamp": "2026-05-17T10:00:01Z",
                    "host": {"name": "fra4-fw-01"},
                    "message": "another event with default fields",
                }},
                # Empty message — should be skipped
                {"_source": {"@timestamp": "2026-05-17T10:00:02Z"}},
            ]
        }
    }
    monkeypatch.setattr(src.session, "post", lambda *a, **k: _MockResponse(200, docs))
    events = list(src.fetch(since_seconds=300, limit=10))
    assert len(events) == 2
    assert events[0].hostname == "fra4-fw-01"
    assert events[0].appname == "rpd"
    assert events[0].severity_raw == "err"
    assert "bgp peer" in events[0].message
    assert events[1].appname == "kibana"  # default
    assert events[1].severity_raw == "info"  # default


# ──────────────────────────────────────────────────────────────────────────────
# Splunk
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_splunk_fetch_yields_events(monkeypatch):
    from ai_log_analyzer.sources.splunk import SplunkSource

    cfg = SourceConfig(id="sp1", type="splunk", url="https://splunk.example.com",
                       api_token="t", auth_methods=("api_token",))
    src = SplunkSource(cfg)
    monkeypatch.setattr(src.session, "post", lambda *a, **k: _MockResponse(200, {
        "results": [
            {"_raw": "Jan 1 link down ge-0/0/1", "_time": "2026-05-17",
             "host": "sw-01", "sourcetype": "junos:syslog", "severity": "warn"},
            {"_raw": "bgp peer 10.0.0.1 down", "_time": "2026-05-17",
             "host": "rt-01"},
            {"_time": "missing-raw"},  # skipped
        ]
    }))
    events = list(src.fetch(since_seconds=600, limit=100))
    assert len(events) == 2
    assert events[0].hostname == "sw-01"
    assert events[0].appname == "junos:syslog"
    assert events[1].appname == "splunk"  # fallback


# ──────────────────────────────────────────────────────────────────────────────
# Loki
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_loki_fetch_flattens_streams(monkeypatch):
    from ai_log_analyzer.sources.loki import LokiSource

    cfg = SourceConfig(id="lk1", type="loki", url="https://loki.example.com",
                       api_token="x", auth_methods=("api_token",))
    src = LokiSource(cfg)
    monkeypatch.setattr(src.session, "get", lambda *a, **k: _MockResponse(200, {
        "data": {
            "result": [
                {
                    "stream": {"host": "fra4-fw-01", "job": "syslog", "level": "err"},
                    "values": [
                        ["1700000000000000000", "bgp peer 10.0.0.1 down"],
                        ["1700000001000000000", "ospf neighbor 10.0.0.5 down"],
                    ],
                },
                {
                    "stream": {"hostname": "lhr3-rt-01", "service": "frr"},
                    "values": [["1700000002000000000", "%bgp-3-notification"]],
                },
            ]
        }
    }))
    events = list(src.fetch(since_seconds=600, limit=100))
    assert len(events) == 3
    assert events[0].hostname == "fra4-fw-01"
    assert events[0].appname == "syslog"
    assert events[2].hostname == "lhr3-rt-01"
    assert events[2].appname == "frr"


# ──────────────────────────────────────────────────────────────────────────────
# LibreNMS
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_librenms_fetch_maps_eventlog(monkeypatch):
    from ai_log_analyzer.sources.librenms import LibreNMSSource

    cfg = SourceConfig(id="ln1", type="librenms", url="https://librenms.example.com",
                       api_token="abc")
    src = LibreNMSSource(cfg)
    monkeypatch.setattr(src.session, "get", lambda *a, **k: _MockResponse(200, {
        "logs": [
            {"datetime": "2026-05-17 10:00:00", "hostname": "sw-01",
             "type": "interface", "severity": "5", "message": "ge-0/0/1 link down"},
            {"datetime": "2026-05-17 10:01:00", "hostname": "rt-01",
             "type": "bgp", "severity": "3", "message": "bgp peer 10.0.0.1 down"},
        ]
    }))
    events = list(src.fetch(since_seconds=600, limit=10))
    assert len(events) == 2
    assert events[0].hostname == "sw-01"
    assert events[1].appname == "bgp"


@pytest.mark.unit
def test_librenms_requires_api_token():
    from ai_log_analyzer.sources.librenms import LibreNMSSource

    with pytest.raises(SourceError, match="requires api_token"):
        LibreNMSSource(SourceConfig(id="x", type="librenms", url="http://x"))


# ──────────────────────────────────────────────────────────────────────────────
# Syslog UDP listener — actual loopback round-trip
# ──────────────────────────────────────────────────────────────────────────────

def _free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.mark.unit
def test_syslog_udp_listener_receives_messages():
    from ai_log_analyzer.sources.syslog import SyslogListenerSource

    port = _free_udp_port()
    cfg = SourceConfig(id="sl1", type="syslog", url="udp://127.0.0.1",
                       extra={"port": str(port), "proto": "udp",
                              "bind": "127.0.0.1", "buffer_size": "100"})
    src = SyslogListenerSource(cfg)
    try:
        assert src.healthcheck() is True
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sender.sendto(b"<22>Jan  1 12:00:00 fra4-fw-01 rpd: bgp peer 10.0.0.1 down\n",
                          ("127.0.0.1", port))
            sender.sendto(b"<22>Jan  1 12:00:01 fra4-fw-01 ospf: neighbor 10.0.0.5 down\n",
                          ("127.0.0.1", port))
        finally:
            sender.close()
        # Give the listener thread a moment to drain
        time.sleep(0.3)
        events = list(src.fetch(since_seconds=60, limit=100))
        assert len(events) >= 2
        # parser splits "app: message" — check both fields
        joined = " ".join(f"{e.appname} {e.message}" for e in events)
        assert "bgp peer" in joined
        assert "ospf" in joined
        # Hostname should be parsed out from the RFC3164 frame
        assert any(e.hostname == "fra4-fw-01" for e in events)
    finally:
        src.close()


# ──────────────────────────────────────────────────────────────────────────────
# Manager
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_manager_add_get_remove():
    m = SourceManager()
    m.add(SourceConfig(id="m1", type="stub-test", url="http://x"))
    assert "m1" in m.list_ids()
    assert m.get("m1") is not None
    assert m.healthcheck("m1") == {"ok": True}
    assert m.remove("m1") is True
    assert m.remove("m1") is False
    assert m.list_ids() == []


@pytest.mark.unit
def test_manager_fetch_returns_list_not_iterator():
    m = SourceManager()
    m.add(SourceConfig(id="m2", type="stub-test", url="http://x"))
    events = m.fetch("m2", since_seconds=60, limit=10)
    assert isinstance(events, list)
    assert len(events) == 1
    assert events[0].hostname == "h1"
    m.remove("m2")


@pytest.mark.unit
def test_manager_load_from_env(monkeypatch):
    monkeypatch.setenv("NETLOG_SOURCE_envone_TYPE", "stub-test")
    monkeypatch.setenv("NETLOG_SOURCE_envone_URL", "http://env.example.com")
    m = SourceManager()
    added = m.load_from_env()
    assert "envone" in added
    assert "envone" in m.list_ids()


@pytest.mark.unit
def test_manager_healthcheck_unknown():
    m = SourceManager()
    out = m.healthcheck("missing")
    assert out["ok"] is False
    assert "unknown source" in out["error"]


@pytest.mark.unit
def test_manager_fetch_unknown_raises():
    m = SourceManager()
    with pytest.raises(SourceError):
        m.fetch("missing")
