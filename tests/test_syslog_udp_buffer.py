"""Each UDP syslog listener reads datagrams into its own buffer.

The receive buffer was a class attribute shared by every listener in the process while the kernel writes
into it with the GIL released, so one listener could ingest another socket's datagram under the sender
address of its own.
"""
from __future__ import annotations

import socket

import pytest

from ai_log_analyzer.sources import SourceConfig
from ai_log_analyzer.sources.syslog import SyslogListenerSource

pytestmark = pytest.mark.unit


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _source(source_id: str) -> SyslogListenerSource:
    return SyslogListenerSource(SourceConfig(
        id=source_id, type="syslog", url="",
        extra={"port": str(_free_port()), "proto": "udp", "bind": "127.0.0.1"}))


class _FakeSock:
    """A socket whose one datagram lands in the caller's buffer; ``during`` runs after the kernel wrote
    it and before the listener copied it out (the window in which another thread can overwrite it)."""

    def __init__(self, payload: bytes, addr: tuple[str, int], during=None) -> None:
        self.payload, self.addr, self.during, self.used = payload, addr, during, False

    def recvmsg_into(self, buffers, _ancbufsize):
        if self.used:
            raise BlockingIOError
        self.used = True
        buffers[0][:len(self.payload)] = self.payload
        if self.during is not None:
            self.during()
        return len(self.payload), [], 0, self.addr


def test_listeners_do_not_share_a_receive_buffer():
    a, b = _source("a"), _source("b")
    try:
        assert a._udp_buf is not b._udp_buf
    finally:
        a.close()
        b.close()


def test_a_datagram_overwritten_by_another_listener_is_not_ingested_by_this_one():
    a, b = _source("a"), _source("b")
    legit = b"<13>Oct 20 10:00:00 dev1 app: legitimate datagram for listener b"
    forged = b"<13>Oct 20 10:00:00 dev1 app: FORGED LINE ARRIVED ON LISTENER A!!"
    real_a, real_b = a._sock, b._sock
    try:
        a._sock = _FakeSock(forged, ("203.0.113.66", 4000))
        # While b's kernel write is "in flight", a's thread receives and writes its own datagram.
        b._sock = _FakeSock(legit, ("192.0.2.20", 514), during=a._udp_readable)
        b._udp_readable()
        assert [line for line, _sender in b._buffer] == [legit.decode()]
        assert list(a._buffer) == [(forged.decode(), "203.0.113.66")]
    finally:
        a._sock, b._sock = real_a, real_b
        a.close()
        b.close()
