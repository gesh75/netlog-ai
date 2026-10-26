"""Syslog listener reliability: bind-error roles, UDP loss visibility, a writer thread that keeps
the event loop free, flush retry, RFC 6587 framing edge cases and connection caps."""
from __future__ import annotations

import logging
import socket
import sqlite3
import threading
import time

import pytest

from ai_log_analyzer.sources import SourceConfig
from ai_log_analyzer.sources.base import SourceError
from ai_log_analyzer.sources.syslog import SyslogListenerSource
from ai_log_analyzer.state_store import StateDB

pytestmark = pytest.mark.unit


def _free_port(kind: int = socket.SOCK_DGRAM) -> int:
    s = socket.socket(socket.AF_INET, kind)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _source(port: int, proto: str = "udp", source_id: str = "t", **extra) -> SyslogListenerSource:
    return SyslogListenerSource(SourceConfig(
        id=source_id, type="syslog", url="",
        extra={"port": str(port), "proto": proto, "bind": "127.0.0.1", **{k: str(v) for k, v in extra.items()}}))


def _wait_for(predicate, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def _udp(port: int, payload: bytes, n: int = 1) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for _ in range(n):
            s.sendto(payload, ("127.0.0.1", port))
    finally:
        s.close()


# ── bind errors ─────────────────────────────────────────────────────────────

def test_a_bind_typo_with_a_spool_is_an_error_not_a_silent_reader(tmp_path, caplog):
    """Regression: ANY OSError with a state DB became role=reader, so a bad address or EACCES
    on port 514 gave healthcheck True and no ingest at all."""
    with caplog.at_level(logging.ERROR), pytest.raises(SourceError, match="Could not bind"):
        SyslogListenerSource(SourceConfig(id="t", type="syslog", url="", extra={
            "port": "5514", "bind": "203.0.113.77", "spool": str(tmp_path / "s.db")}))   # not a local address
    assert any("bind" in r.getMessage().lower() for r in caplog.records)


def test_only_address_in_use_makes_a_reader_and_it_takes_over_when_the_owner_exits(tmp_path):
    spool = tmp_path / "s.db"
    port = _free_port()
    owner = _source(port, spool=spool)
    reader = _source(port, spool=spool, reader_retry=0.1)
    try:
        assert owner.role == "listener" and reader.role == "reader"
        owner.close()                                   # the listener worker exits (deploy / crash)
        assert _wait_for(lambda: reader.role == "listener")
        _udp(port, b"<13>Oct 20 10:00:00 r1 rpd: after takeover\n")
        assert _wait_for(lambda: [e.message for e in reader.fetch()] == ["after takeover"])
        assert reader.healthcheck() is True
    finally:
        reader.close()
        owner.close()


def test_reader_health_follows_listener_heartbeat_or_spool_freshness(tmp_path):
    spool = tmp_path / "s.db"
    port = _free_port()
    squatter = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)    # something else owns the port
    squatter.bind(("127.0.0.1", port))
    reader = _source(port, spool=spool)
    try:
        assert reader.role == "reader"
        assert reader.healthcheck() is False            # no listener heartbeat, nothing ever spooled
        StateDB(spool).spool_append("t", [(time.time(), "1.1.1.1", "<13>Oct 20 10:00:00 r1 a: fresh")], cap=100)
        assert reader.healthcheck() is True             # the spool is moving
        StateDB(spool).conn().execute("DELETE FROM syslog_spool")
        StateDB(spool).spool_append("t", [(time.time() - 3600, "1.1.1.1", "x")], cap=100)
        assert reader.healthcheck() is False            # stale
    finally:
        reader.close()
        squatter.close()


# ── UDP visibility and the writer thread ────────────────────────────────────

def test_effective_rcvbuf_is_reported_and_warned_when_below_the_request(caplog):
    port = _free_port()
    with caplog.at_level(logging.WARNING):
        src = _source(port, rcvbuf=1 << 30)
    try:
        st = src.stats()
        assert st["rcvbuf_requested"] == 1 << 30 and 0 < st["rcvbuf_effective"] < 1 << 30
        assert any("SO_RCVBUF" in r.getMessage() and "rmem_max" in r.getMessage() for r in caplog.records)
    finally:
        src.close()


def test_udp_kernel_drops_are_counted():
    port = _free_port()
    src = _source(port, rcvbuf=4096)
    try:
        assert _wait_for(lambda: src._loop is not None)
        src._loop.call_soon_threadsafe(time.sleep, 1.0)             # stall the receive loop
        time.sleep(0.1)
        _udp(port, b"<13>Oct 20 10:00:00 r1 a: " + b"x" * 400, n=4000)
        time.sleep(1.2)
        _udp(port, b"<13>Oct 20 10:00:00 r1 a: tail marker")         # the next delivery carries the drop count
        assert _wait_for(lambda: src.stats().get("udp_drops", 0) > 0)
        assert src.stats()["udp_drops"] + src.stats()["received"] >= 3900
    finally:
        src.close()


def test_a_locked_database_does_not_stall_the_receive_loop(tmp_path):
    """Regression: the spool write ran on the event loop, so a held write lock froze datagram
    intake and the kernel dropped what the buffer could not hold."""
    spool = tmp_path / "s.db"
    port = _free_port()
    src = _source(port, spool=spool)
    locker = sqlite3.connect(str(spool), isolation_level=None)
    try:
        locker.execute("BEGIN IMMEDIATE")                            # hold the write lock
        _udp(port, b"<13>Oct 20 10:00:00 r1 a: held back", n=1500)
        assert _wait_for(lambda: src.stats().get("received") == 1500, timeout=2.0)   # loop kept reading
        assert src.stats().get("spooled", 0) == 0
        locker.execute("COMMIT")
        assert _wait_for(lambda: src.stats().get("spooled") == 1500, timeout=8.0)
        assert src.stats().get("spool_lines_lost", 0) == 0
    finally:
        locker.close()
        src.close()


# ── flush failures ──────────────────────────────────────────────────────────

def test_a_failed_flush_requeues_the_rows_instead_of_dropping_the_batch(tmp_path):
    port = _free_port()
    src = _source(port, spool=tmp_path / "s.db")
    real, calls = src._db.spool_append, {"n": 0}

    def flaky(source, rows, cap):
        calls["n"] += 1
        if calls["n"] <= 2:
            raise sqlite3.OperationalError("disk I/O error")
        return real(source, rows, cap)

    src._db.spool_append = flaky
    try:
        _udp(port, b"<13>Oct 20 10:00:00 r1 a: survive", n=40)
        assert _wait_for(lambda: src.stats().get("spooled") == 40, timeout=10.0)
        assert src.stats()["spool_errors"] >= 1 and src.stats().get("spool_lines_lost", 0) == 0
    finally:
        src.close()


def test_lines_lost_to_a_dead_database_are_counted_per_line(tmp_path):
    port = _free_port()
    src = _source(port, spool=tmp_path / "s.db", queue_max=100)

    def dead(source, rows, cap):
        raise sqlite3.OperationalError("disk full")

    src._db.spool_append = dead
    try:
        _udp(port, b"<13>Oct 20 10:00:00 r1 a: doomed", n=300)
        assert _wait_for(lambda: src.stats().get("received") == 300)
        assert _wait_for(lambda: src.stats().get("queue_overflow", 0) >= 200)
        assert _wait_for(lambda: src.stats().get("spool_errors", 0) >= 1)
        assert src.stats()["spool_errors"] >= 1
    finally:
        src.close()
    st = src.stats()
    assert st["spool_lines_lost"] == st["received"] and st.get("spooled", 0) == 0   # overflow + close()


# ── TCP framing ─────────────────────────────────────────────────────────────

def test_pri_less_lf_lines_starting_with_a_number_are_not_octet_counts():
    """Regression: NX-OS ``2026 Oct 22 ...`` was read as an octet count of 2026."""
    port = _free_port(socket.SOCK_STREAM)
    src = _source(port, "tcp")
    try:
        conn = socket.create_connection(("127.0.0.1", port))
        for i in range(5):
            conn.sendall(f"2026 Oct 22 10:00:0{i} nx-1 %ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/{i} is down\n"
                         .encode())
        conn.close()
        assert _wait_for(lambda: src.stats().get("received") == 5)
        assert all(e.message for e in src.fetch())
    finally:
        src.close()


def test_octet_counting_still_works_next_to_number_led_lines():
    port = _free_port(socket.SOCK_STREAM)
    src = _source(port, "tcp")
    try:
        msg = b"<13>Oct 20 10:00:00 sw1 app: counted"
        conn = socket.create_connection(("127.0.0.1", port))
        conn.sendall(b"2026 Oct 22 10:00:00 nx-1 lf line\n" + str(len(msg)).encode() + b" " + msg
                     + b"5 \n<13>Oct 20 10:00:01 sw1 app: after\n")
        conn.close()
        assert _wait_for(lambda: src.stats().get("received") == 4)
    finally:
        src.close()


def test_truncated_octet_frames_are_counted():
    port = _free_port(socket.SOCK_STREAM)
    src = _source(port, "tcp")
    try:
        conn = socket.create_connection(("127.0.0.1", port))
        conn.sendall(b"90 <13>Oct 20 10:00:00 sw1 app: cut short")
        conn.close()
        assert _wait_for(lambda: src.stats().get("truncated_frames") == 1)
    finally:
        src.close()


def test_per_source_ip_connection_cap():
    port = _free_port(socket.SOCK_STREAM)
    src = _source(port, "tcp", max_connections_per_ip=2)
    conns = []
    try:
        for _ in range(3):
            c = socket.create_connection(("127.0.0.1", port))
            c.sendall(b"<13>Oct 20 10:00:00 a app: hi\n")
            conns.append(c)
            time.sleep(0.05)
        assert _wait_for(lambda: src.stats().get("rejected_ip_limit") == 1)
        assert src.stats().get("rejected_conn_limit", 0) == 0
    finally:
        for c in conns:
            c.close()
        src.close()


def test_background_threads_stop_on_close(tmp_path):
    before = {t.name for t in threading.enumerate()}
    port = _free_port()
    src = _source(port, spool=tmp_path / "s.db")
    src.close()
    src.close()                                                  # idempotent
    assert {t.name for t in threading.enumerate() if t.name.startswith("syslog")} <= before
