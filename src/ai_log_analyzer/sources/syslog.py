"""Syslog UDP/TCP listener — zero-config demo connector.

Spins up a background socket listener that buffers incoming syslog lines into
a thread-safe ring buffer. `fetch()` drains the buffer, parses each line via
the existing `adapters.file` parser, and yields LogEvents.

Default UDP port is 5514 (unprivileged). Override via env or SourceConfig.

This is the connector that makes the "point a real device at netlog-ai and
watch it light up" demo possible without any cloud/aggregator dependency.
"""
from __future__ import annotations

import logging
import socket
import threading
from collections import deque
from typing import Iterable

from ai_log_analyzer.adapters.file import parse_lines
from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.sources.base import LogSource, SourceConfig, SourceError, registry

log = logging.getLogger(__name__)

_DEFAULT_BIND = "127.0.0.1"
_DEFAULT_PORT = 5514
_DEFAULT_PROTO = "udp"
_DEFAULT_BUFFER_SIZE = 50_000  # ~50k lines in memory before oldest are dropped


class SyslogListenerSource:
    """Syslog UDP (default) or TCP listener with an in-memory ring buffer."""
    kind = "syslog"

    def __init__(self, config: SourceConfig) -> None:
        self.config = config
        self.name = config.id
        self.bind = config.extra.get("bind", _DEFAULT_BIND)
        self.port = int(config.extra.get("port", _DEFAULT_PORT))
        self.proto = (config.extra.get("proto") or _DEFAULT_PROTO).lower()
        if self.proto not in {"udp", "tcp"}:
            raise SourceError(f"Unsupported syslog proto {self.proto!r}")
        capacity = int(config.extra.get("buffer_size", _DEFAULT_BUFFER_SIZE))
        self._buffer: deque[str] = deque(maxlen=capacity)
        self._lock = threading.Lock()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._start_listener()

    @classmethod
    def from_config(cls, config: SourceConfig) -> "SyslogListenerSource":
        return cls(config)

    # ── LogSource interface ──────────────────────────────────────────────────
    def healthcheck(self) -> bool:
        return self._sock is not None and self._thread is not None and self._thread.is_alive()

    def fetch(self, *, since_seconds: int = 3600, limit: int = 10_000,
              host_filter: str = "") -> Iterable[LogEvent]:
        # Drain up to `limit` lines from the buffer (newest-last order preserved).
        with self._lock:
            lines = list(self._buffer)
            self._buffer.clear()
        if limit and len(lines) > limit:
            lines = lines[-int(limit):]
        for ev in parse_lines(lines, default_host=host_filter or "syslog"):
            if host_filter and ev.hostname and host_filter not in ev.hostname:
                continue
            yield ev

    def close(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._thread = None

    # ── private listener loop ────────────────────────────────────────────────
    def _start_listener(self) -> None:
        try:
            if self.proto == "udp":
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._sock.bind((self.bind, self.port))
                self._sock.settimeout(0.5)
                target = self._run_udp
            else:
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._sock.bind((self.bind, self.port))
                self._sock.listen(8)
                self._sock.settimeout(0.5)
                target = self._run_tcp
        except OSError as exc:
            raise SourceError(
                f"Could not bind syslog {self.proto.upper()} {self.bind}:{self.port}: {exc}"
            ) from exc
        self._thread = threading.Thread(target=target, name=f"syslog-{self.name}", daemon=True)
        self._thread.start()
        log.info("syslog source %s listening on %s://%s:%d", self.name, self.proto, self.bind, self.port)

    def _run_udp(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                data, _addr = self._sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            self._ingest(data)

    def _run_tcp(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                conn.settimeout(2.0)
                buf = b""
                try:
                    while not self._stop.is_set():
                        chunk = conn.recv(8192)
                        if not chunk:
                            break
                        buf += chunk
                        while b"\n" in buf:
                            line, _, buf = buf.partition(b"\n")
                            self._ingest(line)
                    if buf:
                        self._ingest(buf)
                except socket.timeout:
                    pass

    def _ingest(self, raw: bytes) -> None:
        try:
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
        except Exception:
            return
        if not line:
            return
        with self._lock:
            self._buffer.append(line)


registry.register("syslog", SyslogListenerSource.from_config)
