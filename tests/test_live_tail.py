"""Live tail: syslog fetch_new() cursor semantics + the SSE web endpoint."""
from __future__ import annotations

import json
import socket
import time

import pytest

from ai_log_analyzer.sources import SourceConfig
from ai_log_analyzer.sources.syslog import SyslogListenerSource
from tests._helpers import listen_on_free_port, wait_for

pytestmark = pytest.mark.unit


def _mk_source(port: int, source_id: str = "tail-test") -> SyslogListenerSource:
    cfg = SourceConfig(id=source_id, type="syslog", url="udp://127.0.0.1",
                       extra={"port": str(port), "proto": "udp",
                              "bind": "127.0.0.1", "buffer_size": "100"})
    return SyslogListenerSource(cfg)


def _send(port: int, line: bytes) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.sendto(line, ("127.0.0.1", port))
    finally:
        s.close()


def test_fetch_new_cursor_returns_only_new_lines():
    port, src = listen_on_free_port(_mk_source)
    try:
        _send(port, b"<22>Jan  1 12:00:00 r1 rpd: bgp peer 10.0.0.1 down\n")
        assert wait_for(lambda: len(src.fetch_new(0)[0]) >= 1), "first datagram never arrived"
        events, cursor = src.fetch_new(0)
        assert len(events) == 1
        # No new lines → empty batch, cursor stable
        events2, cursor2 = src.fetch_new(cursor)
        assert events2 == [] and cursor2 == cursor
        # One more line → exactly one new event
        _send(port, b"<22>Jan  1 12:00:01 r1 rpd: ospf neighbor 10.0.0.5 down\n")
        assert wait_for(lambda: len(src.fetch_new(cursor)[0]) >= 1), "second datagram never arrived"
        events3, cursor3 = src.fetch_new(cursor)
        assert len(events3) == 1 and cursor3 == cursor + 1
        assert "ospf" in f"{events3[0].appname} {events3[0].message}"
    finally:
        src.close()


def test_sse_tail_streams_classified_events():
    from ai_log_analyzer.sources.manager import manager as source_manager
    from ai_log_analyzer.web.app import create_app

    def _register(p: int) -> SourceConfig:
        cfg = SourceConfig(id="sse-test", type="syslog", url="udp://127.0.0.1",
                           extra={"port": str(p), "proto": "udp",
                                  "bind": "127.0.0.1", "buffer_size": "100"})
        source_manager.add(cfg)
        return cfg

    port, _cfg = listen_on_free_port(_register)
    app = create_app()
    app.testing = True
    client = app.test_client()
    try:
        resp = client.get("/api/tail/sse-test?poll=0.2&min_severity=info",
                          buffered=False)
        assert resp.status_code == 200
        assert resp.mimetype == "text/event-stream"
        def _chunks():
            for c in resp.response:
                yield c.decode() if isinstance(c, bytes) else c
        chunks = _chunks()
        assert "hello" in next(chunks)  # greeting frame

        _send(port, b"<22>Jan  1 12:00:00 r1 rpd: bgp peer 10.0.0.1 down hold timer\n")
        payload = ""
        deadline = time.time() + 5
        while time.time() < deadline:
            chunk = next(chunks)
            if chunk.startswith("data: {"):
                payload = chunk
                break
        assert payload, "no event frame arrived within 5s"
        event = json.loads(payload[len("data: "):].strip())
        assert event["severity"] == "high"
        assert event["description"] == "BGP peer down / connect failure"
        resp.close()
    finally:
        source_manager.remove("sse-test")


def test_sse_tail_unknown_source_404_and_non_syslog_400():
    from ai_log_analyzer.web.app import create_app
    app = create_app()
    app.testing = True
    client = app.test_client()
    assert client.get("/api/tail/nope").status_code == 404


def test_sse_tail_requires_token_when_configured(monkeypatch):
    import ai_log_analyzer.web.app as web_app
    from ai_log_analyzer.web.app import create_app
    monkeypatch.setattr(web_app, "API_TOKEN", "sekrit-token-0123456789")
    app = create_app()
    app.testing = True
    client = app.test_client()
    assert client.get("/api/tail/whatever").status_code == 401
    # the API token is never accepted from the URL (it would land in access logs)
    assert client.get("/api/tail/whatever?token=sekrit-token-0123456789").status_code == 401
    assert client.get("/api/tail/whatever",
                      headers={"Authorization": "Bearer sekrit-token-0123456789"}).status_code == 404
