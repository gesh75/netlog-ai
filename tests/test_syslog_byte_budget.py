"""Syslog listener memory is bounded in bytes, not only in lines.

Every retained line can be ~64 KiB, so the 50,000-line ring and the 200,000-row writer queue could pin
gigabytes. Both now also have a byte budget, lines over it are dropped and counted, and in spool mode
(where nothing reads the ring) no line is kept in memory at all.
"""
from __future__ import annotations

import socket
import threading

import pytest

from ai_log_analyzer.sources import SourceConfig
from ai_log_analyzer.sources.syslog import SyslogListenerSource

pytestmark = pytest.mark.unit

SENDER = "192.0.2.10"


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _source(**extra) -> SyslogListenerSource:
    return SyslogListenerSource(SourceConfig(
        id="t", type="syslog", url="",
        extra={"port": str(_free_port()), "proto": "udp", "bind": "127.0.0.1",
               **{k: str(v) for k, v in extra.items()}}))


def _big(i: int) -> bytes:
    return b"<13>Oct 20 10:00:00 r1 app: " + str(i).encode() + b" " + b"x" * 60_000


def test_memory_ring_is_bounded_by_bytes():
    src = _source(max_bytes=1_000_000)
    try:
        for i in range(100):
            src._ingest(_big(i), SENDER)
        held = sum(len(line) for line, _sender in src._buffer)
        assert held <= 1_000_000, f"ring holds {held} bytes against a 1,000,000 byte budget"
        st = src.stats()
        assert st["received"] == 100
        assert st["ring_evicted"] > 0                      # counted, not silent
        assert st["ring_bytes"] > 0
        assert " 99 " in src._buffer[-1][0]               # the newest line is the one kept
        assert len(list(src.fetch())) == len(src._buffer)
    finally:
        src.close()


def test_default_byte_budget_holds_the_ring_far_below_fifty_thousand_full_lines():
    src = _source()
    try:
        for i in range(1_500):   # 90 MB of 60 KB lines; 50,000 of them would be ~3 GB
            src._ingest(_big(i), SENDER)
        held = sum(len(line) for line, _sender in src._buffer)
        assert held <= 70_000_000, f"ring holds {held} bytes"
        assert src.stats()["ring_evicted"] > 0
    finally:
        src.close()


def test_spool_mode_keeps_no_in_memory_ring(tmp_path):
    src = _source(spool=tmp_path / "s.db")
    try:
        for i in range(20):
            src._ingest(f"<13>Oct 20 10:00:00 r1 a: line {i}".encode(), SENDER)
        assert len(src._buffer) == 0, "the ring is never read in spool mode"
        assert src.stats()["ring_bytes"] == 0
        assert len(list(src.fetch())) == 20                      # still served from the spool
        events, cursor = src.fetch_new(0)
        assert len(events) == 20 and cursor > 0
    finally:
        src.close()


def test_writer_queue_is_bounded_by_bytes_and_counts_what_it_drops(tmp_path):
    src = _source(spool=tmp_path / "s.db", queue_max_bytes=1_000_000)
    gate = threading.Event()
    real = src._db.spool_append

    def stalled(source, rows, cap):
        gate.wait(15)
        return real(source, rows, cap)

    src._db.spool_append = stalled   # the writer cannot drain: lines wait in memory
    try:
        for i in range(60):          # 3.6 MB of lines against a 1 MB queue budget
            src._ingest(_big(i), SENDER)
        src._flush()
        st = src.stats()
        assert st["writer_queue_rows"] < 60, f"{st['writer_queue_rows']} of 60 full-size lines queued"
        assert st["writer_queue_bytes"] <= 1_000_000
        assert st["queue_overflow"] == 60 - st["writer_queue_rows"] > 0
        assert st["queue_overflow_bytes"] > 0
        assert st["spool_lines_lost"] == st["queue_overflow"]    # the existing loss counter agrees
    finally:
        gate.set()
        src.close()
    st = src.stats()
    assert st["writer_queue_bytes"] == 0 and st["writer_queue_rows"] == 0   # drained, books balance
