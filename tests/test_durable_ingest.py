"""Durable ingest + multi-worker shared state.

Covers SQLite WAL concurrency across real worker processes (incident store,
JSONL locking, LLM runtime toggles), syslog sender-IP attribution, RFC 6587
TCP framing with concurrent connections, TLS (RFC 5425), the sender
allow-list, and the durable / shared syslog spool.
"""
from __future__ import annotations

import json
import multiprocessing
import os
import shutil
import socket
import sqlite3
import ssl
import subprocess
import time
from pathlib import Path

import pytest

from ai_log_analyzer import llm, memory
from ai_log_analyzer.sources import SourceConfig
from ai_log_analyzer.sources.base import SourceError
from ai_log_analyzer.sources.syslog import SyslogListenerSource
from ai_log_analyzer.state_store import StateDB, open_db

pytestmark = pytest.mark.unit

_CTX = multiprocessing.get_context("fork" if "fork" in multiprocessing.get_all_start_methods() else "spawn")


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


def _wait_for(predicate, timeout: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def _udp(port: int, payload: bytes) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.sendto(payload, ("127.0.0.1", port))
    finally:
        s.close()


# ── SQLite WAL state store ──────────────────────────────────────────────────

def test_state_db_uses_wal(tmp_path):
    db = StateDB(tmp_path / "state.db")
    assert db.journal_mode() == "wal"
    db.kv_set("llm", "provider", "local")
    assert StateDB(tmp_path / "state.db").kv_get_all("llm") == {"provider": "local"}


def _sqlite_worker(path: str, worker: int, rounds: int) -> None:
    store = memory.SqliteIncidentStore(open_db(path))
    for i in range(rounds):
        store.record([{"description": f"w{worker}-r{i}-{k}", "severity": "high", "devices": [f"h{worker}"]}
                      for k in range(3)], f"2026-10-20T10:{i % 60:02d}:00+00:00")


def test_sqlite_incident_store_concurrent_workers(tmp_path):
    path = str(tmp_path / "state.db")
    StateDB(path)  # create schema before the race
    procs = [_CTX.Process(target=_sqlite_worker, args=(path, w, 40)) for w in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(30)
        assert p.exitcode == 0
    store = memory.SqliteIncidentStore(StateDB(path))
    assert len(store) == 4 * 40 * 3
    assert store.recurrence("w3-r39-2")["count"] == 1


def test_sqlite_reload_failure_does_not_undo_a_committed_append(tmp_path):
    """A failed SELECT after COMMIT must not look like a lost write."""
    db = StateDB(tmp_path / "state.db")
    store = memory.SqliteIncidentStore(db)

    def boom(_limit: int):
        raise sqlite3.OperationalError("disk I/O error")

    db.incidents_all = boom  # type: ignore[method-assign]
    assert store.record([{"description": "reload-after-write", "devices": ["r1"]}], "t") == 1
    assert StateDB(tmp_path / "state.db").incidents_count() == 1


def test_analyze_survives_incident_store_persist_error(tmp_path, monkeypatch):
    from ai_log_analyzer.analyzer import analyze
    from ai_log_analyzer.classifier import LogEvent

    monkeypatch.setenv("AI_LOG_ANALYZER_STATE_DB", str(tmp_path / "state.db"))

    def boom(self, *args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(memory.SqliteIncidentStore, "record", boom)
    ev = LogEvent(
        timestamp="Jan  1 00:00:01", hostname="spine-01", appname="rpd",
        severity_raw="err", message="bgp peer 10.0.0.1 down hold timer expired",
    )
    result = analyze(iter([ev]), use_llm=False)
    assert result.action_items


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork only")
def test_no_sqlite_connection_survives_a_fork(tmp_path):
    """Regression: a connection still open at fork() (e.g. unreachable but not
    yet garbage-collected) was inherited; when the child finalized it, the
    close dropped the child's POSIX locks on the database and sibling
    workers lost committed rows."""
    db = StateDB(tmp_path / "state.db")
    inherited = db.conn()
    pid = os.fork()
    if pid == 0:  # child: the inherited handle must be closed, a fresh one must work
        code = 1
        try:
            try:
                inherited.execute("SELECT 1")
            except sqlite3.ProgrammingError:
                db.kv_set("t", "child", 1)
                code = 0
        finally:
            os._exit(code)
    _, status = os.waitpid(pid, 0)
    assert os.WEXITSTATUS(status) == 0
    assert db.kv_get_all("t") == {"child": 1}      # the parent reopens transparently too


def _jsonl_worker(path: str, worker: int, rounds: int, cap: int) -> None:
    memory._MAX_RECORDS = cap
    for i in range(rounds):
        memory.IncidentStore(path).record([{"description": f"w{worker}-r{i}"}], f"2026-10-20T10:00:{i % 60:02d}")


@pytest.mark.parametrize("cap,rounds", [(10_000, 30), (50, 40)])
def test_jsonl_incident_store_locks_appends_and_rewrites(tmp_path, cap, rounds):
    path = str(tmp_path / "incidents.jsonl")
    procs = [_CTX.Process(target=_jsonl_worker, args=(path, w, rounds, cap)) for w in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(30)
        assert p.exitcode == 0
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    records = [json.loads(line) for line in lines]  # no torn / interleaved lines
    assert len(records) == min(cap, 4 * rounds)
    if cap >= 4 * rounds:  # nothing may be lost to a concurrent rewrite
        assert {r["description"] for r in records} == {f"w{w}-r{i}" for w in range(4) for i in range(rounds)}


def test_get_store_prefers_explicit_path_then_shared_db(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_STATE_DB", str(tmp_path / "shared.db"))
    assert isinstance(memory.get_store(), memory.SqliteIncidentStore)
    monkeypatch.setenv("AI_LOG_ANALYZER_INCIDENT_STORE", str(tmp_path / "j.jsonl"))
    store = memory.get_store()
    assert type(store) is memory.IncidentStore
    monkeypatch.setenv("AI_LOG_ANALYZER_INCIDENT_STORE", str(tmp_path / "inc.sqlite"))
    assert isinstance(memory.get_store(), memory.SqliteIncidentStore)


def _llm_worker(path: str) -> None:
    import os
    os.environ["AI_LOG_ANALYZER_STATE_DB"] = path
    from ai_log_analyzer import llm as worker_llm
    worker_llm.set_provider("local")
    worker_llm.set_allow_cloud_fallback(True)
    worker_llm.set_enabled(False)


def test_llm_runtime_toggles_are_shared_across_workers(tmp_path, monkeypatch):
    path = str(tmp_path / "state.db")
    snap = dict(llm._state)
    monkeypatch.setenv("AI_LOG_ANALYZER_STATE_DB", path)
    try:
        llm._state.update({"provider": "ollama", "enabled": True, "allow_cloud_fallback": False})
        proc = _CTX.Process(target=_llm_worker, args=(path,))
        proc.start()
        proc.join(30)
        assert proc.exitcode == 0
        llm._sync_shared_state(force=True)
        assert llm._state["provider"] == "local"
        assert llm._state["allow_cloud_fallback"] is True
        assert llm.is_enabled() is False
    finally:
        llm._state.clear()
        llm._state.update(snap)


# ── Syslog: sender attribution, allow-list, rcvbuf ──────────────────────────

def test_udp_sender_ip_attribution():
    port = _free_port()
    src = _source(port)
    try:
        _udp(port, b"BGP peer 10.0.0.1 down (hold timer expired)\n")
        _udp(port, b"<22>Jan  1 12:00:00 fra4-fw-01 rpd: bgp peer 10.0.0.2 down\n")
        assert _wait_for(lambda: len(list(src.fetch())) == 2)
        headerless, framed = src.fetch()
        assert headerless.hostname == "127.0.0.1"            # was the literal "syslog"
        assert headerless.attrs["sender_ip"] == "127.0.0.1"
        assert framed.hostname == "fra4-fw-01"               # header still wins
        assert framed.attrs["sender_ip"] == "127.0.0.1"
    finally:
        src.close()


def test_udp_datagram_with_several_lines_and_rcvbuf_stat():
    port = _free_port()
    src = _source(port, rcvbuf=1 << 20)
    try:
        _udp(port, b"<13>Oct 20 10:00:00 r1 a: one\n<13>Oct 20 10:00:01 r1 a: two\n")
        assert _wait_for(lambda: src.stats().get("received") == 2)
        assert src.stats()["role"] == "listener"
    finally:
        src.close()


def test_allow_list_drops_other_senders():
    port = _free_port()
    src = _source(port, allow="10.99.0.0/16, 192.0.2.10")
    try:
        _udp(port, b"<13>Oct 20 10:00:00 r1 a: from localhost\n")
        assert _wait_for(lambda: src.stats().get("rejected_sender") == 1)
        assert list(src.fetch()) == []
    finally:
        src.close()
    with pytest.raises(SourceError):
        _source(_free_port(), allow="not-a-cidr")


def test_udp_port_cannot_be_split_between_workers_without_a_spool():
    port = _free_port()
    first = _source(port)
    try:
        with pytest.raises(SourceError, match="Could not bind"):
            _source(port, source_id="second")  # no SO_REUSEADDR on UDP
    finally:
        first.close()


# ── TCP: RFC 6587 framing + concurrency ─────────────────────────────────────

def _octet(msg: bytes) -> bytes:
    return str(len(msg)).encode() + b" " + msg


def test_tcp_octet_counting_split_across_writes_and_lf_framing():
    port = _free_port(socket.SOCK_STREAM)
    src = _source(port, "tcp", max_frame=256)
    try:
        conn = socket.create_connection(("127.0.0.1", port))
        m1 = b"<13>Oct 20 10:00:00 sw1 app: first, with a newline\ninside"
        m2 = b"<13>Oct 20 10:00:01 sw1 app: second"
        framed = _octet(m1)
        conn.sendall(framed[:9])
        time.sleep(0.05)
        conn.sendall(framed[9:] + _octet(m2))
        conn.sendall(b"<13>Oct 20 10:00:02 sw1 app: lf framed\n")
        conn.sendall(b"300 " + b"x" * 300)                      # over max_frame → dropped
        conn.sendall(b"<13>Oct 20 10:00:03 sw1 app: after oversize\n")
        conn.close()
        assert _wait_for(lambda: src.stats().get("received") == 4)
        msgs = [e.message for e in src.fetch()]
        # the LF inside the octet-counted frame is data, not a frame boundary
        assert msgs == ["first, with a newline inside", "second", "lf framed", "after oversize"]
        assert src.stats()["dropped_oversize"] == 1
    finally:
        src.close()


def test_tcp_idle_connection_does_not_block_other_senders():
    port = _free_port(socket.SOCK_STREAM)
    src = _source(port, "tcp")
    try:
        idle = socket.create_connection(("127.0.0.1", port))
        idle.sendall(b"<13>Oct 20 10:00:00 slow app: half a line")    # never finished
        others = [socket.create_connection(("127.0.0.1", port)) for _ in range(5)]
        for i, s in enumerate(others):
            s.sendall(f"<13>Oct 20 10:00:0{i} fast{i} app: hello\n".encode())
        assert _wait_for(lambda: src.stats().get("received") == 5)
        assert src.stats()["active_connections"] >= 1
        for s in others:
            s.close()
        idle.close()  # EOF flushes the partial line
        assert _wait_for(lambda: src.stats().get("received") == 6)
        assert any(e.message == "half a line" for e in src.fetch())
        assert {e.attrs["sender_ip"] for e in src.fetch()} == {"127.0.0.1"}
    finally:
        src.close()


def test_tcp_max_connections():
    port = _free_port(socket.SOCK_STREAM)
    src = _source(port, "tcp", max_connections=1)
    try:
        a = socket.create_connection(("127.0.0.1", port))
        a.sendall(b"<13>Oct 20 10:00:00 a app: hi\n")
        assert _wait_for(lambda: src.stats().get("received") == 1)
        b = socket.create_connection(("127.0.0.1", port))
        assert _wait_for(lambda: src.stats().get("rejected_conn_limit") == 1)
        a.close()
        b.close()
    finally:
        src.close()


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI needed to mint a test certificate")
def test_tls_syslog_rfc5425(tmp_path):
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=netlog-test", "-addext", "subjectAltName=IP:127.0.0.1",
                    "-keyout", str(key), "-out", str(cert)],
                   check=True, capture_output=True)
    port = _free_port(socket.SOCK_STREAM)
    src = _source(port, "tls", tls_cert=cert, tls_key=key)
    try:
        # Full verification: the test cert is the trust anchor and carries an IP SAN.
        ctx = ssl.create_default_context(cafile=str(cert))
        with socket.create_connection(("127.0.0.1", port)) as raw, \
                ctx.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
            tls.sendall(_octet(b"<13>Oct 20 10:00:00 fw1 app: over tls"))
            assert _wait_for(lambda: src.stats().get("received") == 1)
        assert [e.message for e in src.fetch()] == ["over tls"]
    finally:
        src.close()
    with pytest.raises(SourceError, match="tls_cert"):
        _source(_free_port(socket.SOCK_STREAM), "tls")


# ── Durable / shared spool ──────────────────────────────────────────────────

def test_spool_survives_restart(tmp_path):
    spool = tmp_path / "spool.db"
    port = _free_port()
    src = _source(port, spool=spool)
    try:
        _udp(port, b"<13>Oct 20 10:00:00 r1 rpd: before restart\n")
        assert _wait_for(lambda: src.stats().get("spooled") == 1)
    finally:
        src.close()
    restarted = _source(port, spool=spool)
    try:
        assert [e.message for e in restarted.fetch()] == ["before restart"]
        assert restarted.fetch()[0].attrs["sender_ip"] == "127.0.0.1"
    finally:
        restarted.close()


def test_second_worker_reads_the_shared_spool_instead_of_splitting(tmp_path):
    spool = tmp_path / "spool.db"
    port = _free_port()
    owner = _source(port, spool=spool)
    reader = _source(port, spool=spool)  # same port: bind fails → reader role
    try:
        assert owner.role == "listener" and reader.role == "reader"
        assert reader.healthcheck() is True
        _udp(port, b"<13>Oct 20 10:00:00 r1 rpd: seen by every worker\n")
        assert _wait_for(lambda: [e.message for e in reader.fetch()] == ["seen by every worker"])
        events, cursor = reader.fetch_new(0)
        assert len(events) == 1 and cursor > 0
        _udp(port, b"<13>Oct 20 10:00:01 r1 rpd: second\n")
        assert _wait_for(lambda: reader.fetch_new(cursor)[0] != [])
        new, cursor2 = reader.fetch_new(cursor)
        assert [e.message for e in new] == ["second"] and cursor2 > cursor
        assert reader.fetch_new(cursor2) == ([], cursor2)
    finally:
        reader.close()
        owner.close()


def test_spool_is_capped_per_source(tmp_path):
    db = StateDB(tmp_path / "s.db")
    db.spool_append("a", [(0.0, "1.1.1.1", f"line {i}") for i in range(30)], cap=10)
    assert [line for _id, _s, line in db.spool_tail("a", 100)] == [f"line {i}" for i in range(20, 30)]
    db.spool_append("b", [(0.0, "", "other")], cap=10)
    assert len(db.spool_tail("a", 100)) == 10 and len(db.spool_tail("b", 100)) == 1
