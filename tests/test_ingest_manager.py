"""SourceManager: idempotent add / load_from_env (the web app reloads per request) and exit hook."""
from __future__ import annotations

import socket
import time

import pytest

from ai_log_analyzer import _shutdown
from ai_log_analyzer.sources import SourceConfig
from ai_log_analyzer.sources.manager import SourceManager

pytestmark = pytest.mark.unit


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _cfg(port: int, **extra) -> SourceConfig:
    return SourceConfig(id="sl", type="syslog", url="",
                        extra={"port": str(port), "bind": "127.0.0.1", **extra})


def _send(port: int, payload: bytes) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(payload, ("127.0.0.1", port))
    s.close()


def _wait_for(predicate, timeout: float = 3.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def test_add_with_an_unchanged_config_keeps_the_live_source():
    """Regression: add() closed and recreated the source, dropping buffered lines and connections."""
    mgr = SourceManager()
    port = _free_port()
    try:
        first = mgr.add(_cfg(port))
        _send(port, b"<13>Oct 20 10:00:00 r1 a: buffered\n")
        assert _wait_for(lambda: first.stats().get("received") == 1)
        assert mgr.add(_cfg(port)) is first
        assert first.stats()["received"] == 1 and first.healthcheck()
    finally:
        mgr.shutdown()


def test_add_with_a_changed_config_replaces_the_source():
    mgr = SourceManager()
    port = _free_port()
    try:
        first = mgr.add(_cfg(port))
        second = mgr.add(_cfg(port, buffer_size="10"))
        assert second is not first and mgr.get("sl") is second
        assert not first.healthcheck()                      # the old listener was closed
        assert second.healthcheck()
    finally:
        mgr.shutdown()


def test_load_from_env_twice_returns_the_same_live_source(monkeypatch):
    port = _free_port()
    monkeypatch.setenv("NETLOG_SOURCE_sl_TYPE", "syslog")
    monkeypatch.setenv("NETLOG_SOURCE_sl_URL", "udp://localhost")
    monkeypatch.setenv("NETLOG_SOURCE_sl_PORT", str(port))
    monkeypatch.setenv("NETLOG_SOURCE_sl_BIND", "127.0.0.1")
    mgr = SourceManager()
    try:
        assert mgr.load_from_env() == ["sl"]
        first = mgr.get("sl")
        _send(port, b"<13>Oct 20 10:00:00 r1 a: kept\n")
        assert _wait_for(lambda: first.stats().get("received") == 1)
        assert mgr.load_from_env() == ["sl"]
        assert mgr.get("sl") is first and first.stats()["received"] == 1
        monkeypatch.setenv("NETLOG_SOURCE_sl_BUFFER_SIZE", "25")           # a real change still applies
        mgr.load_from_env()
        assert mgr.get("sl") is not first
    finally:
        mgr.shutdown()


def test_add_registers_an_exit_hook_and_shutdown_is_idempotent(monkeypatch):
    calls = []
    monkeypatch.setattr(_shutdown, "register", lambda obj, method: calls.append((obj, method)))
    mgr = SourceManager()
    mgr.add(_cfg(_free_port()))
    assert calls and calls[0][0] is mgr and calls[0][1] == "shutdown"
    mgr.shutdown()
    mgr.shutdown()
    assert mgr.list_ids() == []
