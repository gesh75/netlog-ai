"""SNMP trap receiver — UDP 162, SNMPv1/v2c/v3.

Listens for traps on UDP (default ``0.0.0.0:162``) and feeds them into the
same pipeline as syslog: each trap is rendered as a syslog-like line
(``sources/snmp_proto.py:render_trap_line``) and written to the shared
durable spool by the shared ``SpoolSink`` (``sources/spool_sink.py``), so
the classifier, triage worker, live tail, dashboard spool view and
``/api/metrics`` all see traps exactly like syslog lines — no parallel
pipeline. The only SNMP-specific parts are the wire parser and the
community / USM trust checks.

Trust model:
  * **v2c / v1** — the community string must be in the configured
    ``community`` list (default ``public``). Anything else is rejected and
    counted (``rejected_auth``).
  * **v3 / USM** — ``noAuthNoPriv`` and ``authNoPriv`` (HMAC-MD5/SHA1/
    SHA-224/256/384/512, RFC 3414 key localisation). ``authPriv``
    (encrypted) traps are rejected explicitly and counted
    (``dropped_unsupported``); see ``snmp_proto`` for why.
  * **Allow-list** — optional sender IP / CIDR allow-list (``allow`` or
    ``AI_LOG_ANALYZER_SNMP_ALLOW``), same shape as the syslog listener's.

Like the syslog listener, a second worker whose bind fails with EADDRINUSE
becomes a reader of the shared spool and retries the bind every
``reader_retry`` seconds. Port 162 is privileged: binding it needs root or
``CAP_NET_BIND_SERVICE`` (or a redirect from an unprivileged port).

Config ``extra`` keys: bind, port, community, v3_users, allow, rcvbuf,
spool, queue_max, buffer_size, reader_retry.

``v3_users`` format (one user per ``;``): ``name:auth_proto:auth_pass`` —
``name`` alone means noAuthNoPriv; ``auth_proto`` is one of ``md5``,
``sha``/``sha1``, ``sha224``, ``sha256``, ``sha384``, ``sha512``.
"""
from __future__ import annotations

import asyncio
import dataclasses
import errno
import ipaddress
import logging
import os
import socket
import struct
import sys
import threading
import time
from collections import Counter, deque
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from typing import Any

from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.ingest import sanitize_raw_line
from ai_log_analyzer.parsers import registry as parser_registry
from ai_log_analyzer.sources.base import SourceConfig, SourceError, registry
from ai_log_analyzer.sources.snmp_proto import (
    SnmpAuthError,
    SnmpError,
    SnmpUnsupportedError,
    V3User,
    parse_trap,
    render_trap_line,
)
from ai_log_analyzer.sources.spool_sink import SpoolSink
from ai_log_analyzer.sources.syslog import (
    _norm_ip,
    _parse_allow,
    _system_udp_rcvbuf_errors,
)

log = logging.getLogger(__name__)

_DEFAULT_BIND = "0.0.0.0"
_DEFAULT_PORT = 162
_DEFAULT_COMMUNITY = "public"
_DEFAULT_BUFFER_SIZE = 50_000  # lines kept (memory ring or spool rows per source)
_DEFAULT_RCVBUF = 4 * 1024 * 1024
_DEFAULT_QUEUE_MAX = 200_000
_DEFAULT_READER_RETRY = 5.0
_FLUSH_INTERVAL_S = 0.05
_HEARTBEAT_EVERY_S = 5.0
_HEARTBEAT_STALE_S = 30.0
_HEARTBEAT_NS = "snmp-listener"
_SO_RXQ_OVFL = 40              # Linux: ancillary message with the socket's cumulative drop count
_ADDR_IN_USE = {errno.EADDRINUSE, getattr(errno, "WSAEADDRINUSE", errno.EADDRINUSE)}

_AUTH_PROTOS = {"md5", "sha", "sha1", "sha224", "sha256", "sha384", "sha512"}


def _parse_communities(raw: str | None) -> frozenset[str]:
    items = {item.strip() for item in (raw or "").replace(";", ",").split(",") if item.strip()}
    return frozenset(items) if items else frozenset({_DEFAULT_COMMUNITY})


def _parse_v3_users(raw: str | None) -> dict[str, V3User]:
    """``name:auth_proto:auth_pass;name2:...`` — ``name`` alone is noAuthNoPriv."""
    users: dict[str, V3User] = {}
    for entry in (raw or "").split(";"):
        entry = entry.strip()
        if not entry:
            continue
        parts = entry.split(":", 2)
        name = parts[0].strip()
        if not name:
            raise SourceError(f"invalid SNMP v3 user entry {entry!r}: empty name")
        if len(parts) == 1:
            users[name] = V3User(name)
            continue
        proto = parts[1].strip().lower()
        if proto not in _AUTH_PROTOS:
            raise SourceError(f"invalid SNMP v3 auth protocol {proto!r} for user {name!r} "
                              f"(expected one of {sorted(_AUTH_PROTOS)})")
        if len(parts) != 3 or not parts[2]:
            raise SourceError(f"SNMP v3 user {name!r} needs a passphrase "
                              f"('name:auth_proto:auth_pass')")
        users[name] = V3User(name, proto, parts[2])
    return users


class _UdpProtocol(asyncio.DatagramProtocol):
    """Fallback receive path for event loops without ``add_reader`` (no ancillary drop counter)."""

    def __init__(self, owner: SnmpTrapSource) -> None:
        self.owner = owner

    def datagram_received(self, data: bytes, addr: Any) -> None:
        self.owner._datagram(data, addr)


class SnmpTrapSource:
    """SNMP trap UDP listener with an in-memory ring or durable spool."""
    kind = "snmp"

    def __init__(self, config: SourceConfig) -> None:
        extra = config.extra or {}
        self.config = config
        self.name = config.id
        self.bind = extra.get("bind", _DEFAULT_BIND)
        self.port = int(extra.get("port", _DEFAULT_PORT))
        self.capacity = int(extra.get("buffer_size", _DEFAULT_BUFFER_SIZE))
        self.rcvbuf = int(extra.get("rcvbuf", os.environ.get("AI_LOG_ANALYZER_SNMP_RCVBUF", _DEFAULT_RCVBUF)))
        self.queue_max = int(extra.get("queue_max", _DEFAULT_QUEUE_MAX))
        self.reader_retry = float(extra.get("reader_retry", _DEFAULT_READER_RETRY))
        self._communities = _parse_communities(
            extra.get("community") or os.environ.get("AI_LOG_ANALYZER_SNMP_COMMUNITY"))
        self._v3_users = _parse_v3_users(
            extra.get("v3_users") or os.environ.get("AI_LOG_ANALYZER_SNMP_V3_USERS"))
        self._allow = _parse_allow(extra.get("allow") or os.environ.get("AI_LOG_ANALYZER_SNMP_ALLOW"))

        self._buffer: deque[tuple[str, str]] = deque(maxlen=self.capacity)
        self._total_ingested = 0  # monotonic — cursor base for fetch_new() (memory mode)
        self._lock = threading.Lock()
        self._stats: Counter[str] = Counter()
        self._db = self._open_spool(extra)

        # Durable spool: the shared SpoolSink owns the writer thread and the
        # drop counters (shared Counter, so stats()/backpressure see them).
        self._sink = (SpoolSink(self.name, self._db, capacity=self.capacity,
                                queue_max=self.queue_max, stats=self._stats,
                                on_heartbeat=self._heartbeat)
                      if self._db is not None else None)

        self._sock: socket.socket | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._retry_thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._stop = threading.Event()
        self._closed = False
        self._rxq_ovfl = False
        self._snmp_base = _system_udp_rcvbuf_errors()
        self.role = "listener"
        try:
            self._sock = self._open_socket()
        except OSError as exc:
            if self._db is None or exc.errno not in _ADDR_IN_USE:
                msg = f"Could not bind SNMP trap receiver {self.bind}:{self.port}: {exc}"
                log.error("snmp source %s: %s", self.name, msg)
                raise SourceError(msg) from exc
            # Another worker owns the port; share its spool instead of splitting traffic, and
            # take the port over if that worker goes away.
            self.role = "reader"
            log.info("snmp source %s: port %s busy (%s) — reading shared spool", self.name, self.port, exc)
            if self._sink is not None:
                self._sink.start()
            self._retry_thread = threading.Thread(target=self._reader_retry_loop, name=f"snmp-retry-{self.name}",
                                                  daemon=True)
            self._retry_thread.start()
            return
        if self._sink is not None:
            self._sink.start()
        self._start_loop()

    @classmethod
    def from_config(cls, config: SourceConfig) -> SnmpTrapSource:
        return cls(config)

    # ── setup ───────────────────────────────────────────────────────────────
    def _open_spool(self, extra: dict):
        from ai_log_analyzer.state_store import get_state_db, open_db
        path = extra.get("spool") or os.environ.get("AI_LOG_ANALYZER_SNMP_SPOOL", "").strip()
        if path:
            return open_db(path)
        return get_state_db()

    def _open_socket(self) -> socket.socket:
        family = socket.AF_INET6 if ":" in str(self.bind) else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        # No SO_REUSEADDR: on Linux it lets a second worker bind the same
        # port and silently take half the datagrams.
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.rcvbuf)
        except OSError:
            log.warning("snmp %s: could not set SO_RCVBUF=%d", self.name, self.rcvbuf)
        if sys.platform.startswith("linux"):
            try:
                sock.setsockopt(socket.SOL_SOCKET, _SO_RXQ_OVFL, 1)
                self._rxq_ovfl = True
            except OSError:
                self._rxq_ovfl = False
        try:
            sock.bind((self.bind, self.port))
        except OSError:
            sock.close()
            raise
        effective = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        # Linux reports twice the (clamped) value it applied; anything below the request means clamped.
        if effective < self.rcvbuf:
            log.warning("snmp %s: SO_RCVBUF requested %d but the kernel granted %d; raise net.core.rmem_max "
                        "(sysctl) to absorb bursts without UDP loss", self.name, self.rcvbuf, effective)
        self._stats["rcvbuf_effective"] = effective
        sock.setblocking(False)
        return sock

    def _start_loop(self) -> None:
        self._thread = threading.Thread(target=self._run, name=f"snmp-{self.name}", daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=5.0):
            raise SourceError(f"snmp listener {self.name} failed to start")
        self._heartbeat()
        log.info("snmp source %s listening on udp://%s:%d", self.name, self.bind, self.port)

    def _reader_retry_loop(self) -> None:
        """A reader keeps trying to bind so it takes over when the listener worker exits."""
        warned = False
        while not self._stop.wait(self.reader_retry):
            try:
                sock = self._open_socket()
            except OSError as exc:
                if exc.errno not in _ADDR_IN_USE and not warned:
                    warned = True
                    log.error("snmp source %s: still cannot bind %s:%s: %s", self.name, self.bind, self.port, exc)
                continue
            if self._stop.is_set():
                sock.close()
                return
            self._sock = sock
            self.role = "listener"
            log.info("snmp source %s: port %s is free — taking over as listener", self.name, self.port)
            try:
                self._start_loop()
            except SourceError:
                log.exception("snmp source %s: takeover failed", self.name)
                self.role = "reader"
                try:
                    sock.close()
                except OSError:
                    pass
                self._sock = None
                self._ready.clear()
                continue
            return

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._serve())
        except Exception:
            log.exception("snmp listener %s crashed", self.name)
        finally:
            self._flush()
            loop.close()

    async def _serve(self) -> None:
        loop = asyncio.get_running_loop()
        assert self._sock is not None
        self._stop_async = asyncio.Event()
        sock = self._sock
        try:
            loop.add_reader(sock.fileno(), self._udp_readable)
            # remove_reader() returns bool; the closer's return is discarded.
            closer: Callable[[], object] = lambda: loop.remove_reader(sock.fileno())  # noqa: E731
        except NotImplementedError:   # Windows proactor loop: no drop counters on this path
            transport, _ = await loop.create_datagram_endpoint(lambda: _UdpProtocol(self), sock=sock)
            closer = transport.close
        self._ready.set()
        try:
            while not self._stop_async.is_set():
                try:
                    await asyncio.wait_for(self._stop_async.wait(), timeout=_FLUSH_INTERVAL_S)
                except asyncio.TimeoutError:
                    pass
                self._flush()
        finally:
            closer()

    # ── UDP ─────────────────────────────────────────────────────────────────
    _udp_buf = bytearray(65_535)
    _ANC = socket.CMSG_SPACE(4) if hasattr(socket, "CMSG_SPACE") else 0

    def _udp_readable(self) -> None:
        sock = self._sock
        if sock is None:
            return
        for _ in range(512):   # bounded so timers (flush, stop) still run under a flood
            try:
                n, anc, _flags, addr = sock.recvmsg_into([self._udp_buf], self._ANC)
            except (BlockingIOError, InterruptedError):
                return
            except OSError as exc:   # e.g. ICMP-induced ECONNREFUSED: not fatal for a listener
                self._stats["udp_recv_errors"] += 1
                log.debug("snmp %s: recv error %s", self.name, exc)
                return
            for level, ctype, cdata in anc:
                if level == socket.SOL_SOCKET and ctype == _SO_RXQ_OVFL and len(cdata) >= 4:
                    drops = struct.unpack("=I", cdata[:4])[0]
                    if drops > self._stats["udp_drops"]:
                        self._stats["udp_drops"] = drops
            self._datagram(bytes(self._udp_buf[:n]), addr)

    def _datagram(self, data: bytes, addr: Any) -> None:
        sender = _norm_ip(addr[0]) if addr else ""
        if not self._allowed(sender):
            self._stats["rejected_sender"] += 1
            return
        self._stats["received"] += 1
        try:
            trap = parse_trap(data, communities=self._communities, v3_users=self._v3_users)
        except SnmpAuthError as exc:
            self._stats["rejected_auth"] += 1
            log.debug("snmp %s: rejected trap from %s: %s", self.name, sender, exc)
            return
        except SnmpUnsupportedError as exc:
            self._stats["dropped_unsupported"] += 1
            log.warning("snmp %s: unsupported trap from %s: %s", self.name, sender, exc)
            return
        except SnmpError as exc:
            self._stats["parse_errors"] += 1
            log.debug("snmp %s: unparsable datagram from %s: %s", self.name, sender, exc)
            return
        self._stats["traps"] += 1
        self._ingest(render_trap_line(trap, sender, now=datetime.now(timezone.utc)), sender)

    # ── ingest / spool ──────────────────────────────────────────────────────
    def _allowed(self, sender: str) -> bool:
        if not self._allow:
            return True
        try:
            ip = ipaddress.ip_address(sender)
        except ValueError:
            return False
        return any(ip in net for net in self._allow)

    def _ingest(self, line: str, sender: str = "") -> None:
        try:
            line = sanitize_raw_line(line)
        except Exception:
            return
        if not line.strip():
            return
        with self._lock:
            self._buffer.append((line, sender))
            self._total_ingested += 1
        sink = getattr(self, "_sink", None)
        if sink is not None:
            sink.append(time.time(), sender, line)

    def _flush(self) -> None:
        """Hand pending lines to the spool writer (cheap; never touches SQLite)."""
        sink = getattr(self, "_sink", None)
        if sink is not None:
            sink.flush()

    def _flush_sync(self, timeout: float = 5.0) -> bool:
        """Enqueue pending lines and wait until the writer has settled them (fetch / close)."""
        sink = getattr(self, "_sink", None)
        if sink is None:
            return True
        return sink.flush_sync(timeout)

    def _heartbeat(self) -> None:
        """Listener liveness for reader workers' healthcheck."""
        if self._db is None or self.role != "listener":
            return
        try:
            self._db.kv_set(_HEARTBEAT_NS, self.name, {"at": time.time(), "pid": os.getpid()})
        except Exception:
            log.debug("snmp %s: heartbeat write failed", self.name, exc_info=True)
        self._publish_backpressure()

    def _publish_backpressure(self) -> None:
        """Persist drop counters + audit threshold crossings (P3 item 13).

        Runs on the listener's heartbeat (every ~5 s); readers never publish,
        so the counters always describe the worker that owns the socket.
        """
        if self._db is None or self.role != "listener":
            return
        from ai_log_analyzer.backpressure import DROP_KEYS, publish

        counters = {key: int(self._stats.get(key, 0)) for key in DROP_KEYS}
        system = _system_udp_rcvbuf_errors()
        if system is not None and self._snmp_base is not None:
            counters["udp_rcvbuf_errors_system"] = max(0, system - self._snmp_base)
        publish(self._db, self.name, counters, action="snmp_backpressure")

    # ── LogSource interface ─────────────────────────────────────────────────
    def healthcheck(self) -> bool:
        if self.role == "reader":
            # Healthy while a listener worker heartbeats or the spool is receiving lines.
            try:
                now = time.time()
                beat = self._db.kv_get_all(_HEARTBEAT_NS).get(self.name)   # type: ignore[union-attr]
                if isinstance(beat, dict) and now - float(beat.get("at", 0)) < _HEARTBEAT_STALE_S:
                    return True
                last = self._db.spool_last_received(self.name)             # type: ignore[union-attr]
                return last > 0 and now - last < _HEARTBEAT_STALE_S
            except Exception:
                return False
        return self._sock is not None and self._thread is not None and self._thread.is_alive()

    def stats(self) -> dict[str, Any]:
        sink = getattr(self, "_sink", None)
        out: dict[str, Any] = {"role": self.role, "proto": "udp", "port": self.port,
                               "spool": bool(self._db),
                               "rcvbuf_requested": self.rcvbuf,
                               "writer_queue_rows": sink.writer_queue_rows() if sink else 0,
                               **dict(self._stats)}
        now = _system_udp_rcvbuf_errors()
        if now is not None and self._snmp_base is not None:
            out["udp_rcvbuf_errors_system"] = max(0, now - self._snmp_base)
        return out

    def _events(self, items: Iterable[tuple[str, str]], host_filter: str = "") -> list[LogEvent]:
        out: list[LogEvent] = []
        for line, sender in items:
            ev = parser_registry.parse(line, default_host=sender or "snmp")
            if ev is None:
                continue
            if sender:
                ev = dataclasses.replace(ev, attrs={**ev.attrs, "sender_ip": sender})
            if host_filter and ev.hostname and host_filter not in ev.hostname:
                continue
            out.append(ev)
        return out

    def fetch(self, *, since_seconds: int = 3600, limit: int = 10_000,
              host_filter: str = "") -> Iterable[LogEvent]:
        # Snapshot WITHOUT draining: every connector is idempotent, so a
        # correlate → triage sequence on the same source sees the same events.
        limit = int(limit) if limit else self.capacity
        if self._sink is not None:
            self._flush_sync()
            items = [(line, sender) for _id, sender, line in self._db.spool_tail(self.name, limit)]
        else:
            with self._lock:
                items = list(self._buffer)
            items = items[-limit:]
        return self._events(items, host_filter)

    def fetch_new(self, cursor: int, limit: int = 1000) -> tuple[list[LogEvent], int]:
        """Incremental read for live tailing: lines ingested since `cursor`.

        Returns (events, new_cursor). In memory mode the cursor is the
        monotonic ingest counter; with a spool it is the spool row id, so
        every worker can tail the same stream.
        """
        if self._sink is not None:
            self._flush_sync()
            rows = self._db.spool_after(self.name, int(cursor), int(limit) or self.capacity)
            new_cursor = rows[-1][0] if rows else max(int(cursor), 0)
            return self._events((line, sender) for _id, sender, line in rows), new_cursor
        with self._lock:
            total = self._total_ingested
            n_new = min(total - cursor, len(self._buffer))
            items = list(self._buffer)[-n_new:] if n_new > 0 else []
        if limit and len(items) > limit:
            items = items[-int(limit):]
        return self._events(items), total

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        retry = self._retry_thread
        if retry is not None and retry is not threading.current_thread():
            retry.join(timeout=3.0)
        loop = self._loop
        if loop is not None and getattr(self, "_stop_async", None) is not None and not loop.is_closed():
            try:
                loop.call_soon_threadsafe(self._stop_async.set)
            except RuntimeError:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        self._thread = None
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        sink = getattr(self, "_sink", None)
        if sink is not None:
            sink.close()
            self._sink = None


registry.register("snmp", SnmpTrapSource.from_config)
