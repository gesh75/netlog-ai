"""Syslog listener — UDP, TCP (RFC 6587) and TLS (RFC 5425).

An asyncio event loop on one background thread serves:

* **UDP** with a tuned ``SO_RCVBUF`` (default 4 MiB) so a burst is queued by
  the kernel instead of dropped. The effective buffer is logged when the
  kernel clamps it (``net.core.rmem_max``) and kernel drops are counted
  (``udp_drops`` from ``SO_RXQ_OVFL`` on Linux; ``udp_rcvbuf_errors_system``
  is the host-wide ``RcvbufErrors`` delta from ``/proc/net/snmp``).
* **TCP / TLS** with any number of concurrent, non-blocking connections. A
  slow or idle sender never blocks the others. Per message, both RFC 6587
  framings are accepted: octet-counting (``<len> <msg>``, only when the body
  starts with ``<PRI>`` and ``len`` <= ``max_frame``) and non-transparent LF
  framing, so a PRI-less line such as NX-OS ``2026 Oct 22 ...`` is not read
  as an octet count. ``max_connections`` caps the listener,
  ``max_connections_per_ip`` caps one sender address.
* **Sender attribution**: every line keeps the sender's IP. Lines without a
  hostname header get the sender IP as hostname (was the literal "syslog").
  Every event carries ``attrs["sender_ip"]``.
* **Allow-list**: optional sender IP / CIDR allow-list (``allow`` or
  ``AI_LOG_ANALYZER_SYSLOG_ALLOW``). Other senders are dropped and counted.
* **Durable spool**: with a spool DB (``spool`` / ``AI_LOG_ANALYZER_SYSLOG_SPOOL``
  or the shared ``AI_LOG_ANALYZER_STATE_DB``), lines are batched into SQLite
  WAL by a writer thread behind a bounded queue (``queue_max`` lines;
  ``queue_overflow`` counts what a stalled database could not absorb), so a
  slow or locked database never blocks the receive loop. A failed write is
  retried, not dropped; ``spool_lines_lost`` counts lines actually lost.
  They survive restarts and are shared by every worker. A second worker
  whose bind fails with EADDRINUSE (the port is owned by another worker)
  becomes a reader of the same spool and retries the bind every
  ``reader_retry`` seconds, taking over when the listener worker exits. Any
  other bind error (bad address, EACCES) raises instead of idling silently.
  UDP no longer sets ``SO_REUSEADDR``, which on Linux let two workers bind
  the same port and split datagrams between them.

Without a spool, lines live in an in-memory ring buffer exactly as before. With a spool nothing is
kept in the ring (it is never read), so memory is the writer queue alone.

Memory is bounded in bytes as well as in lines (a line can be 64 KiB): the ring by ``max_bytes`` (oldest
lines are evicted, ``ring_evicted`` counts them) and the writer queue by ``queue_max_bytes`` (new lines
are dropped, ``queue_overflow``, ``queue_overflow_bytes`` and ``spool_lines_lost`` count them).

File paths in ``extra`` (spool, tls_*) are the operator's: a source created over the web API or MCP may
only name a spool database inside the directory of the operator's spool / state DB and no TLS files
(see ``check_untrusted_extra``).

Config ``extra`` keys: bind, port, proto (udp|tcp|tls), buffer_size, max_bytes, rcvbuf,
max_frame, max_connections, max_connections_per_ip, idle_timeout, allow,
tls_cert, tls_key, tls_ca, spool, queue_max, queue_max_bytes, reader_retry.
"""
from __future__ import annotations

import asyncio
import dataclasses
import errno
import ipaddress
import logging
import os
import socket
import sqlite3
import ssl
import struct
import sys
import threading
import time
from collections import Counter, deque
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.ingest import decode_bytes, sanitize_raw_line
from ai_log_analyzer.parsers import registry as parser_registry
from ai_log_analyzer.sources.base import SourceConfig, SourceError, registry

log = logging.getLogger(__name__)

_DEFAULT_BIND = "127.0.0.1"
_DEFAULT_PORT = 5514
_DEFAULT_PROTO = "udp"
_DEFAULT_BUFFER_SIZE = 50_000  # lines kept (memory ring or spool rows per source)
_DEFAULT_RCVBUF = 4 * 1024 * 1024
_DEFAULT_MAX_FRAME = 65_536
_DEFAULT_MAX_CONNECTIONS = 512
_DEFAULT_MAX_CONNECTIONS_PER_IP = 128
_DEFAULT_IDLE_TIMEOUT = 300.0
_DEFAULT_QUEUE_MAX = 200_000   # lines waiting for the spool writer before new ones are dropped (counted)
_DEFAULT_MAX_BYTES = 64 * 1024 * 1024         # ring: bytes kept before the oldest lines are evicted
_DEFAULT_QUEUE_MAX_BYTES = 128 * 1024 * 1024  # writer queue: bytes waiting before new lines are dropped
_ROW_OVERHEAD = 120            # tuple, sender string and list slot around one retained line
_DEFAULT_READER_RETRY = 5.0
_FLUSH_INTERVAL_S = 0.05
_FLUSH_BATCH = 512
_WRITE_BATCH = 5_000           # lines coalesced into one SQLite transaction
_MAX_LEN_DIGITS = 10
_HEARTBEAT_EVERY_S = 5.0
_HEARTBEAT_STALE_S = 30.0
_HEARTBEAT_NS = "syslog-listener"
_SO_RXQ_OVFL = 40              # Linux: ancillary message with the socket's cumulative drop count
_ADDR_IN_USE = {errno.EADDRINUSE, getattr(errno, "WSAEADDRINUSE", errno.EADDRINUSE)}


def _parse_allow(raw: str | None) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    nets = []
    for item in (raw or "").replace(";", ",").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError as exc:
            raise SourceError(f"invalid syslog allow-list entry {item!r}") from exc
    return nets


def _norm_ip(addr: str) -> str:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return addr
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return str(ip.ipv4_mapped)
    return str(ip)


# ── what a web / MCP caller may name ───────────────────────────────────────────
# ``extra`` values that are host file paths (spool database, TLS files) come from the operator
# (NETLOG_SOURCE_<id>_* environment, or code calling SourceManager.add). A source created through a
# request (POST /api/sources, MCP add_source) goes through check_untrusted_extra first.
_UNTRUSTED_TLS_KEYS = ("tls_cert", "tls_key", "tls_ca")
_SPOOL_SUFFIXES = (".db", ".sqlite", ".sqlite3")
_NO_TLS_FILES = ("syslog TLS files are set by the operator (NETLOG_SOURCE_<id>_TLS_CERT / _TLS_KEY / "
                 "_TLS_CA), not over the API")
_NO_SPOOL_PATH = ("syslog spool path is not allowed here: over the API a spool must be a .db / .sqlite file "
                  "inside the directory of AI_LOG_ANALYZER_SYSLOG_SPOOL or AI_LOG_ANALYZER_STATE_DB")


def _spool_roots() -> list[Path]:
    """Directories an API-chosen spool may live in: where the operator's own spool / state DB lives."""
    roots = []
    for name in ("AI_LOG_ANALYZER_SYSLOG_SPOOL", "AI_LOG_ANALYZER_STATE_DB"):
        raw = os.environ.get(name, "").strip()
        if raw:
            roots.append(Path(raw).expanduser().resolve().parent)
    return roots


def _is_spool_db(path: Path) -> bool:
    try:
        con = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True, timeout=1.0)
        try:
            return con.execute("SELECT 1 FROM sqlite_master WHERE name = 'syslog_spool'").fetchone() is not None
        finally:
            con.close()
    except (sqlite3.Error, ValueError):
        return False


def _spool_path_allowed(raw: str) -> bool:
    """Inside a spool root after resolving ``..`` and symlinks, a database file name, and either new or
    already a spool database: never a file this service did not create as a spool."""
    roots = _spool_roots()
    path = Path(raw).expanduser()
    if not roots or ".." in path.parts or path.suffix.lower() not in _SPOOL_SUFFIXES:
        return False
    try:
        target = path.resolve()
    except (OSError, RuntimeError):
        return False
    if not any(target != root and target.is_relative_to(root) for root in roots):
        return False
    if target.exists():
        return target.is_file() and _is_spool_db(target)
    return True


def check_untrusted_extra(extra: Mapping[str, str]) -> None:
    """Refuse the file-path options of a syslog source that a request (not the operator) is creating.

    One message per kind of refusal whatever the path is: nothing here tells a caller whether a path
    exists, is a directory or is a PEM file.
    """
    if any(extra.get(key) for key in _UNTRUSTED_TLS_KEYS):
        raise SourceError(_NO_TLS_FILES)
    spool = extra.get("spool")
    if spool and not _spool_path_allowed(str(spool)):
        raise SourceError(_NO_SPOOL_PATH)


def _row_bytes(line: str, sender: str) -> int:
    """Memory one retained line costs: the str object itself (not its length) plus fixed overhead."""
    return sys.getsizeof(line) + len(sender) + _ROW_OVERHEAD


def _system_udp_rcvbuf_errors() -> int | None:
    """Host-wide UDP ``RcvbufErrors`` from /proc/net/snmp (Linux), or None."""
    try:
        with open("/proc/net/snmp", encoding="ascii") as fh:
            rows = [line.split() for line in fh if line.startswith("Udp:")]
        if len(rows) >= 2 and "RcvbufErrors" in rows[0]:
            return int(rows[1][rows[0].index("RcvbufErrors")])
    except (OSError, ValueError, IndexError):
        pass
    return None


class _UdpProtocol(asyncio.DatagramProtocol):
    """Fallback receive path for event loops without ``add_reader`` (no ancillary drop counter)."""

    def __init__(self, owner: SyslogListenerSource) -> None:
        self.owner = owner

    def datagram_received(self, data: bytes, addr: Any) -> None:
        self.owner._datagram(data, addr)


class SyslogListenerSource:
    """Syslog UDP / TCP / TLS listener with an in-memory ring or durable spool."""
    kind = "syslog"
    # Class-level defaults so a bare instance (tests build one with object.__new__) still ingests.
    max_bytes = _DEFAULT_MAX_BYTES
    queue_max_bytes = _DEFAULT_QUEUE_MAX_BYTES
    _buffer_bytes = 0
    _wq_bytes = 0

    def __init__(self, config: SourceConfig) -> None:
        extra = config.extra or {}
        self.config = config
        self.name = config.id
        self.bind = extra.get("bind", _DEFAULT_BIND)
        self.port = int(extra.get("port", _DEFAULT_PORT))
        self.proto = (extra.get("proto") or _DEFAULT_PROTO).lower()
        if self.proto not in {"udp", "tcp", "tls"}:
            raise SourceError(f"Unsupported syslog proto {self.proto!r}")
        if extra.get("tls_cert") and self.proto == "tcp":
            self.proto = "tls"
        self.capacity = int(extra.get("buffer_size", _DEFAULT_BUFFER_SIZE))
        self.rcvbuf = int(extra.get("rcvbuf", os.environ.get("AI_LOG_ANALYZER_SYSLOG_RCVBUF", _DEFAULT_RCVBUF)))
        self.max_frame = int(extra.get("max_frame", _DEFAULT_MAX_FRAME))
        self.max_connections = int(extra.get("max_connections", _DEFAULT_MAX_CONNECTIONS))
        self.max_connections_per_ip = int(extra.get("max_connections_per_ip", _DEFAULT_MAX_CONNECTIONS_PER_IP))
        self.idle_timeout = float(extra.get("idle_timeout", _DEFAULT_IDLE_TIMEOUT))
        self.queue_max = int(extra.get("queue_max", _DEFAULT_QUEUE_MAX))
        self.max_bytes = int(extra.get("max_bytes", _DEFAULT_MAX_BYTES))
        self.queue_max_bytes = int(extra.get("queue_max_bytes", _DEFAULT_QUEUE_MAX_BYTES))
        self.reader_retry = float(extra.get("reader_retry", _DEFAULT_READER_RETRY))
        self._allow = _parse_allow(extra.get("allow") or os.environ.get("AI_LOG_ANALYZER_SYSLOG_ALLOW"))
        self._ssl = self._tls_context(extra) if self.proto == "tls" else None

        # Per listener: the kernel fills this buffer with the GIL released, so one shared by several
        # listener threads would hand one socket's datagram to another.
        self._udp_buf = bytearray(65_535)
        self._buffer: deque[tuple[str, str]] = deque(maxlen=self.capacity)
        self._buffer_bytes = 0     # bytes the ring retains (see max_bytes)
        self._total_ingested = 0  # monotonic — cursor base for fetch_new() (memory mode)
        self._lock = threading.Lock()
        self._stats: Counter[str] = Counter()
        self._active_conns = 0
        self._conns_by_ip: Counter[str] = Counter()
        self._pending: list[tuple[float, str, str]] = []
        self._db = self._open_spool(extra)

        # Spool writer: batches wait here (bounded) so SQLite never runs on the event loop.
        self._wq: deque[list[tuple[float, str, str]]] = deque()
        self._wq_rows = 0          # lines queued, including a batch the writer is retrying
        self._wq_bytes = 0         # bytes of those lines (see queue_max_bytes)
        self._enq_rows = 0         # lines ever accepted into the queue
        self._done_rows = 0        # lines written or abandoned
        self._wcv = threading.Condition()
        self._writer: threading.Thread | None = None
        self._writer_stop = False

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
                msg = f"Could not bind syslog {self.proto.upper()} {self.bind}:{self.port}: {exc}"
                log.error("syslog source %s: %s", self.name, msg)
                raise SourceError(msg) from exc
            # Another worker owns the port; share its spool instead of splitting traffic, and
            # take the port over if that worker goes away.
            self.role = "reader"
            log.info("syslog source %s: port %s busy (%s) — reading shared spool", self.name, self.port, exc)
            self._start_writer()
            self._retry_thread = threading.Thread(target=self._reader_retry_loop, name=f"syslog-retry-{self.name}",
                                                  daemon=True)
            self._retry_thread.start()
            return
        self._start_writer()
        self._start_loop()

    @classmethod
    def from_config(cls, config: SourceConfig) -> SyslogListenerSource:
        return cls(config)

    # ── setup ───────────────────────────────────────────────────────────────
    @staticmethod
    def _tls_context(extra: dict) -> ssl.SSLContext:
        cert, key = extra.get("tls_cert"), extra.get("tls_key")
        if not cert:
            raise SourceError("syslog proto=tls needs tls_cert (and tls_key)")
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            ctx.load_cert_chain(cert, key or None)
            if extra.get("tls_ca"):
                ctx.load_verify_locations(extra["tls_ca"])
                ctx.verify_mode = ssl.CERT_REQUIRED  # mutual TLS: senders must present a cert
        except (OSError, ssl.SSLError) as exc:
            raise SourceError(f"syslog TLS setup failed: {exc}") from exc
        return ctx

    def _open_spool(self, extra: dict):
        from ai_log_analyzer.state_store import get_state_db, open_db
        path = extra.get("spool") or os.environ.get("AI_LOG_ANALYZER_SYSLOG_SPOOL", "").strip()
        if path:
            return open_db(path)
        return get_state_db()

    def _open_socket(self) -> socket.socket:
        family = socket.AF_INET6 if ":" in str(self.bind) else socket.AF_INET
        if self.proto == "udp":
            sock = socket.socket(family, socket.SOCK_DGRAM)
            # No SO_REUSEADDR on UDP: on Linux it lets a second worker bind the
            # same port and silently take half the datagrams.
        else:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # TIME_WAIT only, safe for TCP
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.rcvbuf)
        except OSError:
            log.warning("syslog %s: could not set SO_RCVBUF=%d", self.name, self.rcvbuf)
        if self.proto == "udp" and sys.platform.startswith("linux"):
            try:
                sock.setsockopt(socket.SOL_SOCKET, _SO_RXQ_OVFL, 1)
                self._rxq_ovfl = True
            except OSError:
                self._rxq_ovfl = False
        try:
            sock.bind((self.bind, self.port))
            if self.proto != "udp":
                sock.listen(128)
        except OSError:
            sock.close()
            raise
        effective = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        # Linux reports twice the (clamped) value it applied; anything below the request means clamped.
        if effective < self.rcvbuf:
            log.warning("syslog %s: SO_RCVBUF requested %d but the kernel granted %d; raise net.core.rmem_max "
                        "(sysctl) to absorb bursts without UDP loss", self.name, self.rcvbuf, effective)
        self._stats["rcvbuf_effective"] = effective
        sock.setblocking(False)
        return sock

    def _start_loop(self) -> None:
        self._thread = threading.Thread(target=self._run, name=f"syslog-{self.name}", daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=5.0):
            raise SourceError(f"syslog listener {self.name} failed to start")
        self._heartbeat()
        log.info("syslog source %s listening on %s://%s:%d", self.name, self.proto, self.bind, self.port)

    def _reader_retry_loop(self) -> None:
        """A reader keeps trying to bind so it takes over when the listener worker exits."""
        warned = False
        while not self._stop.wait(self.reader_retry):
            try:
                sock = self._open_socket()
            except OSError as exc:
                if exc.errno not in _ADDR_IN_USE and not warned:
                    warned = True
                    log.error("syslog source %s: still cannot bind %s:%s: %s", self.name, self.bind, self.port, exc)
                continue
            if self._stop.is_set():
                sock.close()
                return
            self._sock = sock
            self.role = "listener"
            log.info("syslog source %s: port %s is free — taking over as listener", self.name, self.port)
            try:
                self._start_loop()
            except SourceError:
                log.exception("syslog source %s: takeover failed", self.name)
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
            log.exception("syslog listener %s crashed", self.name)
        finally:
            self._flush()
            loop.close()

    async def _serve(self) -> None:
        loop = asyncio.get_running_loop()
        assert self._sock is not None
        self._stop_async = asyncio.Event()
        if self.proto == "udp":
            sock = self._sock
            try:
                loop.add_reader(sock.fileno(), self._udp_readable)
                closer = lambda: loop.remove_reader(sock.fileno())  # noqa: E731
            except NotImplementedError:   # Windows proactor loop: no drop counters on this path
                transport, _ = await loop.create_datagram_endpoint(lambda: _UdpProtocol(self), sock=sock)
                closer = transport.close
        else:
            server = await asyncio.start_server(
                self._handle_conn, sock=self._sock, ssl=self._ssl,
                limit=self.max_frame + 64,
                **({"ssl_handshake_timeout": 10.0} if self._ssl else {}),
            )
            closer = server.close
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
            # Cancel in-flight connection handlers so shutdown is clean.
            current = asyncio.current_task()
            pending = [t for t in asyncio.all_tasks() if t is not current]
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)

    # ── UDP ─────────────────────────────────────────────────────────────────
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
                log.debug("syslog %s: recv error %s", self.name, exc)
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
        # One datagram may carry several LF-separated messages.
        for part in data.split(b"\n"):
            if part.strip():
                self._ingest(part, sender)

    # ── TCP / TLS ───────────────────────────────────────────────────────────
    async def _handle_conn(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        sender = _norm_ip(peer[0]) if peer else ""
        if not self._allowed(sender):
            self._stats["rejected_sender"] += 1
            writer.close()
            return
        if self._active_conns >= self.max_connections:
            self._stats["rejected_conn_limit"] += 1
            writer.close()
            return
        if self.max_connections_per_ip > 0 and self._conns_by_ip[sender] >= self.max_connections_per_ip:
            self._stats["rejected_ip_limit"] += 1
            writer.close()
            return
        self._active_conns += 1
        self._conns_by_ip[sender] += 1
        self._stats["connections"] += 1
        try:
            while True:
                frame = await asyncio.wait_for(self._read_frame(reader), timeout=self.idle_timeout)
                if frame is None:
                    break
                if frame:
                    self._ingest(frame, sender)
        except asyncio.IncompleteReadError:
            self._stats["truncated_frames"] += 1
        except (asyncio.TimeoutError, ConnectionError, ssl.SSLError, OSError):
            pass
        except asyncio.CancelledError:
            pass  # listener shutting down
        finally:
            self._active_conns -= 1
            self._conns_by_ip[sender] -= 1
            if self._conns_by_ip[sender] <= 0:
                del self._conns_by_ip[sender]
            writer.close()

    async def _read_frame(self, reader: asyncio.StreamReader) -> bytes | None:
        """One RFC 6587 frame: octet-counted ``LEN SP MSG`` or LF-terminated.

        Octet counting is accepted only when ``LEN`` <= ``max_frame`` or the body visibly starts
        with ``<PRI>`` (``<`` and a digit); any other ``<digits><space>...`` start is an
        LF-framed line, e.g. NX-OS ``2026 Oct 22 ...``. Returns b"" for a dropped (oversized)
        frame and None at EOF.
        """
        digits = b""
        while True:
            ch = await reader.read(1)
            if not ch:
                return None
            if ch.isdigit() and len(digits) < _MAX_LEN_DIGITS and not (not digits and ch == b"0"):
                digits += ch
                continue
            if ch == b" " and digits:
                return await self._after_length(reader, digits)
            break
        # Non-transparent framing: everything up to LF (the digits were data).
        if ch in (b"\n", b"\x00"):
            return digits
        return await self._read_lf_tail(reader, digits + ch)

    async def _after_length(self, reader: asyncio.StreamReader, digits: bytes) -> bytes | None:
        """``<digits><space>`` was read: decide between an octet-counted frame and a plain line."""
        length = int(digits)
        prefix = digits + b" "
        head = b""
        for _ in range(2):   # read at most two bytes, stopping at an LF so no following line is eaten
            b1 = await reader.read(1)
            if not b1:
                return prefix + head if head.strip() else None
            if b1 == b"\n":
                return prefix + head
            head += b1
        if length >= 3 and head[:1] == b"<" and head[1:2].isdigit():
            if length > self.max_frame:
                self._stats["dropped_oversize"] += 1
                remaining = length - 2
                while remaining:
                    chunk = await reader.read(min(remaining, 65_536))
                    if not chunk:
                        return None
                    remaining -= len(chunk)
                return b""
            try:
                return head + await reader.readexactly(length - 2)
            except asyncio.IncompleteReadError as exc:
                self._stats["truncated_frames"] += 1
                return head + exc.partial
        return await self._read_lf_tail(reader, prefix + head)

    async def _read_lf_tail(self, reader: asyncio.StreamReader, prefix: bytes) -> bytes | None:
        try:
            rest = await reader.readuntil(b"\n")
        except asyncio.LimitOverrunError:
            self._stats["dropped_oversize"] += 1
            while True:  # discard to the end of the oversized line
                try:
                    await reader.readuntil(b"\n")
                    return b""
                except asyncio.LimitOverrunError as exc:
                    await reader.readexactly(exc.consumed)
        except asyncio.IncompleteReadError as exc:
            rest = exc.partial  # sender closed without a trailing LF
            if not rest and prefix.isspace():
                return None
        return prefix + rest

    # ── ingest / spool ──────────────────────────────────────────────────────
    def _allowed(self, sender: str) -> bool:
        if not self._allow:
            return True
        try:
            ip = ipaddress.ip_address(sender)
        except ValueError:
            return False
        return any(ip in net for net in self._allow)

    def _ingest(self, raw: bytes, sender: str = "") -> None:
        try:
            text = decode_bytes(raw).rstrip("\r\n\x00")
            # An octet-counted frame may carry embedded line breaks (multi-line
            # messages); fold them so the syslog header still parses.
            if "\n" in text:
                text = " ".join(part.strip("\r") for part in text.split("\n"))
            line = sanitize_raw_line(text)
        except Exception:
            return
        if not line.strip():
            return
        with self._lock:
            self._total_ingested += 1
            self._stats["received"] += 1
            if self._db is not None:
                # Spool mode: fetch / fetch_new read the spool, so a ring copy would be dead memory.
                self._pending.append((time.time(), sender, line))
                flush_now = len(self._pending) >= _FLUSH_BATCH
            else:
                self._ring_append(line, sender)
                flush_now = False
        if flush_now:
            self._flush()

    def _ring_append(self, line: str, sender: str) -> None:
        """Append to the memory ring, evicting the oldest lines past ``max_bytes`` (caller holds the lock)."""
        buf = self._buffer
        cap = getattr(buf, "maxlen", None)
        if cap == 0:
            return
        if cap is not None and len(buf) == cap:
            self._buffer_bytes -= _row_bytes(*buf[0])    # the deque is about to drop its oldest line
        buf.append((line, sender))
        self._buffer_bytes += _row_bytes(line, sender)
        while self._buffer_bytes > self.max_bytes and len(buf) > 1:
            self._buffer_bytes -= _row_bytes(*buf.popleft())
            self._stats["ring_evicted"] += 1

    def _flush(self) -> None:
        """Hand pending lines to the spool writer (cheap; never touches SQLite)."""
        if self._db is None:
            return
        with self._lock:
            rows, self._pending = self._pending, []
        if not rows:
            return
        with self._wcv:
            # Room is a line count AND a byte budget: a line can be 64 KiB, so a count alone is gigabytes.
            room = max(0, self.queue_max - self._wq_rows)
            room_bytes = max(0, self.queue_max_bytes - self._wq_bytes)
            keep = kept_bytes = 0
            for _ts, sender, line in rows[:room]:
                cost = _row_bytes(line, sender)
                if kept_bytes + cost > room_bytes:
                    break
                kept_bytes += cost
                keep += 1
            if keep < len(rows):   # the writer cannot keep up: drop the newest, loudly counted
                over = len(rows) - keep
                if not self._stats["queue_overflow"]:
                    log.error("syslog %s: spool queue is full (%d lines, %d bytes); dropping new lines",
                              self.name, self.queue_max, self.queue_max_bytes)
                self._stats["queue_overflow"] += over
                self._stats["queue_overflow_bytes"] += sum(_row_bytes(r[2], r[1]) for r in rows[keep:])
                self._stats["spool_lines_lost"] += over
                self._enq_rows += over
                self._done_rows += over
                rows = rows[:keep]
            if rows:
                self._wq.append(rows)
                self._wq_rows += len(rows)
                self._wq_bytes += kept_bytes
                self._enq_rows += len(rows)
            self._wcv.notify_all()

    def _flush_sync(self, timeout: float = 5.0) -> bool:
        """Enqueue pending lines and wait until the writer has settled them (fetch / close)."""
        self._flush()
        if self._db is None:
            return True
        deadline = time.monotonic() + timeout
        with self._wcv:
            target = self._enq_rows
            while self._done_rows < target:
                if self._writer is None or not self._writer.is_alive():
                    break
                left = deadline - time.monotonic()
                if left <= 0:
                    return False
                self._wcv.wait(min(left, 0.2))
            return self._done_rows >= target

    def _start_writer(self) -> None:
        if self._db is None:
            return
        self._writer = threading.Thread(target=self._writer_loop, name=f"syslog-spool-{self.name}", daemon=True)
        self._writer.start()

    def _writer_loop(self) -> None:
        last_beat = 0.0
        delay = 0.25
        failing_since = 0.0
        while True:
            with self._wcv:
                while not self._wq and not self._writer_stop:
                    self._wcv.wait(0.5)
                    if time.monotonic() - last_beat >= _HEARTBEAT_EVERY_S:
                        break
                stopping = self._writer_stop
                batch: list[tuple[float, str, str]] = []
                taken = 0
                while self._wq and len(batch) < _WRITE_BATCH:
                    part = self._wq.popleft()
                    batch.extend(part)
                    taken += 1
            if time.monotonic() - last_beat >= _HEARTBEAT_EVERY_S:
                last_beat = time.monotonic()
                self._heartbeat()
            if not batch:
                if stopping:
                    return
                continue
            try:
                self._db.spool_append(self.name, batch, cap=self.capacity)   # type: ignore[union-attr]
            except Exception as exc:
                self._stats["spool_errors"] += 1
                now = time.monotonic()
                if not failing_since or now - failing_since > 30:
                    failing_since = failing_since or now
                    log.error("syslog %s: spool write failed (%d lines kept for retry): %s", self.name,
                              len(batch), exc)
                with self._wcv:
                    self._wq.appendleft(batch)   # re-queue: the rows stay counted in _wq_rows
                    if stopping:                 # last chance failed: these lines are gone
                        lost = sum(len(b) for b in self._wq)
                        self._abandon(lost)
                        return
                self._writer_wait(delay)
                delay = min(delay * 2, 5.0)
                continue
            if failing_since:
                log.info("syslog %s: spool writes recovered", self.name)
                failing_since = 0.0
            delay = 0.25
            with self._wcv:
                self._wq_rows -= len(batch)
                self._wq_bytes -= sum(_row_bytes(line, sender) for _ts, sender, line in batch)
                self._done_rows += len(batch)
                self._stats["spooled"] += len(batch)
                self._wcv.notify_all()

    def _writer_wait(self, seconds: float) -> None:
        with self._wcv:
            if not self._writer_stop:
                self._wcv.wait(seconds)

    def _abandon(self, lost: int) -> None:
        """Count lines that could not be written before shutdown (caller holds ``_wcv``)."""
        self._wq.clear()
        self._wq_rows = 0
        self._wq_bytes = 0
        self._done_rows += lost
        self._stats["spool_lines_lost"] += lost
        log.error("syslog %s: %d line(s) could not be written to the spool and were lost", self.name, lost)
        self._wcv.notify_all()

    def _heartbeat(self) -> None:
        """Listener liveness for reader workers' healthcheck."""
        if self._db is None or self.role != "listener":
            return
        try:
            self._db.kv_set(_HEARTBEAT_NS, self.name, {"at": time.time(), "pid": os.getpid()})
        except Exception:
            log.debug("syslog %s: heartbeat write failed", self.name, exc_info=True)

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
        out: dict[str, Any] = {"role": self.role, "proto": self.proto, "port": self.port,
                               "active_connections": self._active_conns, "spool": bool(self._db),
                               "rcvbuf_requested": self.rcvbuf, "writer_queue_rows": self._wq_rows,
                               "writer_queue_bytes": self._wq_bytes, "ring_bytes": self._buffer_bytes,
                               **dict(self._stats)}
        now = _system_udp_rcvbuf_errors()
        if self.proto == "udp" and now is not None and self._snmp_base is not None:
            out["udp_rcvbuf_errors_system"] = max(0, now - self._snmp_base)
        return out

    def _events(self, items: Iterable[tuple[str, str]], host_filter: str = "") -> list[LogEvent]:
        out: list[LogEvent] = []
        for line, sender in items:
            ev = parser_registry.parse(line, default_host=sender or "syslog")
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
        if self._db is not None:
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
        every worker can tail the same stream. Lines that scrolled out of the
        buffer between polls are skipped rather than duplicated.
        """
        if self._db is not None:
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
        self._flush()
        if self._writer is not None:
            with self._wcv:
                self._writer_stop = True
                self._wcv.notify_all()
            self._writer.join(timeout=10.0)
            with self._wcv:   # the writer is stuck or gone: whatever is still queued will not be written
                lost = sum(len(b) for b in self._wq)
                if lost:
                    self._abandon(lost)
            self._writer = None


registry.register("syslog", SyslogListenerSource.from_config)
