"""Syslog listener — UDP, TCP (RFC 6587) and TLS (RFC 5425).

An asyncio event loop on one background thread serves:

* **UDP** with a tuned ``SO_RCVBUF`` (default 4 MiB) so a burst is queued by
  the kernel instead of dropped.
* **TCP / TLS** with any number of concurrent, non-blocking connections. A
  slow or idle sender never blocks the others. Per message, both RFC 6587
  framings are accepted: octet-counting (``<len> <msg>``) and non-transparent
  LF framing.
* **Sender attribution**: every line keeps the sender's IP. Lines without a
  hostname header get the sender IP as hostname (was the literal "syslog").
  Every event carries ``attrs["sender_ip"]``.
* **Allow-list**: optional sender IP / CIDR allow-list (``allow`` or
  ``AI_LOG_ANALYZER_SYSLOG_ALLOW``). Other senders are dropped and counted.
* **Durable spool**: with a spool DB (``spool`` / ``AI_LOG_ANALYZER_SYSLOG_SPOOL``
  or the shared ``AI_LOG_ANALYZER_STATE_DB``), lines are batched into SQLite
  WAL. They survive restarts and are shared by every worker. A second worker
  whose bind fails (the port is owned by another worker) becomes a reader
  of the same spool instead of erroring or splitting the traffic. UDP no
  longer sets ``SO_REUSEADDR``, which on Linux let two workers bind the same
  port and split datagrams between them.

Without a spool, lines live in an in-memory ring buffer exactly as before.

Config ``extra`` keys: bind, port, proto (udp|tcp|tls), buffer_size, rcvbuf,
max_frame, max_connections, idle_timeout, allow, tls_cert, tls_key, tls_ca,
spool.
"""
from __future__ import annotations

import asyncio
import dataclasses
import ipaddress
import logging
import os
import socket
import ssl
import threading
import time
from collections import Counter, deque
from collections.abc import Iterable
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
_DEFAULT_IDLE_TIMEOUT = 300.0
_FLUSH_INTERVAL_S = 0.05
_FLUSH_BATCH = 512
_MAX_LEN_DIGITS = 10


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


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, owner: SyslogListenerSource) -> None:
        self.owner = owner

    def datagram_received(self, data: bytes, addr: Any) -> None:
        sender = _norm_ip(addr[0]) if addr else ""
        if not self.owner._allowed(sender):
            self.owner._stats["rejected_sender"] += 1
            return
        # One datagram may carry several LF-separated messages.
        for part in data.split(b"\n"):
            if part.strip():
                self.owner._ingest(part, sender)


class SyslogListenerSource:
    """Syslog UDP / TCP / TLS listener with an in-memory ring or durable spool."""
    kind = "syslog"

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
        self.idle_timeout = float(extra.get("idle_timeout", _DEFAULT_IDLE_TIMEOUT))
        self._allow = _parse_allow(extra.get("allow") or os.environ.get("AI_LOG_ANALYZER_SYSLOG_ALLOW"))
        self._ssl = self._tls_context(extra) if self.proto == "tls" else None

        self._buffer: deque[tuple[str, str]] = deque(maxlen=self.capacity)
        self._total_ingested = 0  # monotonic — cursor base for fetch_new() (memory mode)
        self._lock = threading.Lock()
        self._stats: Counter[str] = Counter()
        self._active_conns = 0
        self._pending: list[tuple[float, str, str]] = []
        self._db = self._open_spool(extra)

        self._sock: socket.socket | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._stop = threading.Event()
        self.role = "listener"
        try:
            self._sock = self._open_socket()
        except OSError as exc:
            if self._db is None:
                raise SourceError(
                    f"Could not bind syslog {self.proto.upper()} {self.bind}:{self.port}: {exc}"
                ) from exc
            # Another worker owns the port; share its spool instead of splitting traffic.
            self.role = "reader"
            log.info("syslog source %s: port %s busy (%s) — reading shared spool", self.name, self.port, exc)
            return
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
        try:
            sock.bind((self.bind, self.port))
            if self.proto != "udp":
                sock.listen(128)
        except OSError:
            sock.close()
            raise
        sock.setblocking(False)
        return sock

    def _start_loop(self) -> None:
        self._thread = threading.Thread(target=self._run, name=f"syslog-{self.name}", daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=5.0):
            raise SourceError(f"syslog listener {self.name} failed to start")
        log.info("syslog source %s listening on %s://%s:%d", self.name, self.proto, self.bind, self.port)

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
            transport, _ = await loop.create_datagram_endpoint(lambda: _UdpProtocol(self), sock=self._sock)
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
        self._active_conns += 1
        self._stats["connections"] += 1
        try:
            while True:
                frame = await asyncio.wait_for(self._read_frame(reader), timeout=self.idle_timeout)
                if frame is None:
                    break
                if frame:
                    self._ingest(frame, sender)
        except (asyncio.TimeoutError, ConnectionError, ssl.SSLError, asyncio.IncompleteReadError, OSError):
            pass
        except asyncio.CancelledError:
            pass  # listener shutting down
        finally:
            self._active_conns -= 1
            writer.close()

    async def _read_frame(self, reader: asyncio.StreamReader) -> bytes | None:
        """One RFC 6587 frame: octet-counted ``LEN SP MSG`` or LF-terminated.

        Returns b"" for a dropped (oversized) frame and None at EOF.
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
                length = int(digits)
                if length > self.max_frame:
                    self._stats["dropped_oversize"] += 1
                    remaining = length
                    while remaining:
                        chunk = await reader.read(min(remaining, 65_536))
                        if not chunk:
                            return None
                        remaining -= len(chunk)
                    return b""
                return await reader.readexactly(length)
            break
        # Non-transparent framing: everything up to LF (the digits were data).
        if ch in (b"\n", b"\x00"):
            return digits
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
            if not rest and not digits and ch.isspace():
                return None
        return digits + ch + rest

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
            self._buffer.append((line, sender))
            self._total_ingested += 1
            self._stats["received"] += 1
            if self._db is not None:
                self._pending.append((time.time(), sender, line))
                flush_now = len(self._pending) >= _FLUSH_BATCH
            else:
                flush_now = False
        if flush_now:
            self._flush()

    def _flush(self) -> None:
        if self._db is None:
            return
        with self._lock:
            rows, self._pending = self._pending, []
        if not rows:
            return
        try:
            self._db.spool_append(self.name, rows, cap=self.capacity)
            self._stats["spooled"] += len(rows)
        except Exception:
            log.exception("syslog %s: spool write failed (%d lines kept in memory only)", self.name, len(rows))
            self._stats["spool_errors"] += 1

    # ── LogSource interface ─────────────────────────────────────────────────
    def healthcheck(self) -> bool:
        if self.role == "reader":
            try:
                self._db.spool_max_id(self.name)  # type: ignore[union-attr]
                return True
            except Exception:
                return False
        return self._sock is not None and self._thread is not None and self._thread.is_alive()

    def stats(self) -> dict[str, Any]:
        return {"role": self.role, "proto": self.proto, "port": self.port,
                "active_connections": self._active_conns, "spool": bool(self._db),
                **dict(self._stats)}

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
            self._flush()
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
            self._flush()
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
        self._stop.set()
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


registry.register("syslog", SyslogListenerSource.from_config)
