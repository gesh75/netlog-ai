"""Durable spool sink — shared by the UDP listeners (syslog, SNMP traps).

One listener thread receives datagrams; SQLite must never run on that
thread. ``SpoolSink`` owns the hand-off: pending lines are batched into a
bounded in-memory queue, and a writer thread drains it into the shared
spool table (``StateDB.spool_append``) in large transactions. A failed
write is re-queued and retried with backoff, never silently dropped;
``spool_lines_lost`` counts only lines that could not be written before
shutdown. Drop/queue counters live in the caller's shared ``Counter`` so
the listener's ``stats()`` and backpressure publishing see them directly.

The heartbeat callback (if given) runs on the writer thread about every
5 s — listeners use it for their liveness heartbeat + backpressure publish.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import Counter, deque
from collections.abc import Callable
from typing import Any

log = logging.getLogger(__name__)

_FLUSH_BATCH = 512
_WRITE_BATCH = 5_000           # lines coalesced into one SQLite transaction
_HEARTBEAT_EVERY_S = 5.0


class SpoolSink:
    """Bounded-queue writer from a listener into the shared spool table."""

    def __init__(self, source: str, db: Any, *, capacity: int, queue_max: int,
                 stats: Counter[str] | None = None,
                 on_heartbeat: Callable[[], None] | None = None) -> None:
        self.source = source
        self._db = db
        self.capacity = capacity
        self.queue_max = queue_max
        self._stats: Counter[str] = stats if stats is not None else Counter()
        self._on_heartbeat = on_heartbeat
        self._pending: list[tuple[float, str, str]] = []
        self._lock = threading.Lock()
        self._wq: deque[list[tuple[float, str, str]]] = deque()
        self._wq_rows = 0          # lines queued, including a batch the writer is retrying
        self._enq_rows = 0         # lines ever accepted into the queue
        self._done_rows = 0        # lines written or abandoned
        self._wcv = threading.Condition()
        self._writer: threading.Thread | None = None
        self._writer_stop = False
        self._closed = False

    # ── producer side (listener thread) ────────────────────────────────────
    def append(self, received_at: float, sender: str, line: str) -> None:
        """Queue one line; hands a full batch to the writer thread."""
        with self._lock:
            self._pending.append((received_at, sender, line))
            flush_now = len(self._pending) >= _FLUSH_BATCH
        if flush_now:
            self.flush()

    def flush(self) -> None:
        """Hand pending lines to the spool writer (cheap; never touches SQLite)."""
        with self._lock:
            rows, self._pending = self._pending, []
        if not rows:
            return
        with self._wcv:
            room = max(0, self.queue_max - self._wq_rows)
            if len(rows) > room:   # the writer cannot keep up: drop the newest, loudly counted
                over = len(rows) - room
                if not self._stats["queue_overflow"]:
                    log.error("spool %s: queue is full (%d lines); dropping new lines",
                              self.source, self.queue_max)
                self._stats["queue_overflow"] += over
                self._stats["spool_lines_lost"] += over
                self._enq_rows += over
                self._done_rows += over
                rows = rows[:room]
            if rows:
                self._wq.append(rows)
                self._wq_rows += len(rows)
                self._enq_rows += len(rows)
            self._wcv.notify_all()

    def flush_sync(self, timeout: float = 5.0) -> bool:
        """Enqueue pending lines and wait until the writer has settled them (fetch / close)."""
        self.flush()
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

    # ── writer thread ──────────────────────────────────────────────────────
    def start(self) -> None:
        if self._writer is not None:
            return
        self._writer = threading.Thread(target=self._writer_loop,
                                        name=f"spool-{self.source}", daemon=True)
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
                while self._wq and len(batch) < _WRITE_BATCH:
                    batch.extend(self._wq.popleft())
            if time.monotonic() - last_beat >= _HEARTBEAT_EVERY_S:
                last_beat = time.monotonic()
                if self._on_heartbeat is not None:
                    try:
                        self._on_heartbeat()
                    except Exception:
                        log.debug("spool %s: heartbeat callback failed", self.source, exc_info=True)
            if not batch:
                if stopping:
                    return
                continue
            try:
                self._db.spool_append(self.source, batch, cap=self.capacity)
            except Exception as exc:
                self._stats["spool_errors"] += 1
                now = time.monotonic()
                if not failing_since or now - failing_since > 30:
                    failing_since = failing_since or now
                    log.error("spool %s: write failed (%d lines kept for retry): %s",
                              self.source, len(batch), exc)
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
                log.info("spool %s: writes recovered", self.source)
                failing_since = 0.0
            delay = 0.25
            with self._wcv:
                self._wq_rows -= len(batch)
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
        self._done_rows += lost
        self._stats["spool_lines_lost"] += lost
        log.error("spool %s: %d line(s) could not be written to the spool and were lost",
                  self.source, lost)
        self._wcv.notify_all()

    # ── lifecycle / inspection ─────────────────────────────────────────────
    def writer_queue_rows(self) -> int:
        with self._wcv:
            return self._wq_rows

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.flush()
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
