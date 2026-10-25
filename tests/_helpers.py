"""Shared helpers for tests that touch sockets and background threads.

Two classic flaky patterns live here so they are fixed once:

* ``time.sleep(N)`` followed by an assertion  ->  :func:`wait_for` (poll until true).
* "ask the OS for a free port, close it, bind it again" races  ->  :func:`free_port`
  (picks below the ephemeral range, so outgoing connections cannot steal it) and
  :func:`listen_on_free_port` (retries with a fresh port on EADDRINUSE).
"""
from __future__ import annotations

import errno
import random
import socket
import time
from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T")

# Linux hands out ephemeral (client-side) ports from 32768-60999 by default. Test listeners
# choose from below that range so a concurrent outgoing connection cannot grab the port
# between probing it and binding it for real.
_LOW_PORT_RANGE = (20000, 32000)


def wait_for(predicate: Callable[[], object], timeout: float = 3.0, interval: float = 0.02) -> bool:
    """Poll ``predicate`` until it is truthy or ``timeout`` seconds pass."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return bool(predicate())


def _probe(port: int, kind: int) -> bool:
    s = socket.socket(socket.AF_INET, kind)
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def free_port(kind: int = socket.SOCK_DGRAM) -> int:
    """A currently-free loopback port (UDP by default; pass ``socket.SOCK_STREAM`` for TCP)."""
    for _ in range(50):
        port = random.randint(*_LOW_PORT_RANGE)
        if _probe(port, kind):
            return port
    s = socket.socket(socket.AF_INET, kind)  # last resort: whatever the OS offers
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def _is_addr_in_use(exc: BaseException) -> bool:
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if isinstance(cur, OSError) and cur.errno == errno.EADDRINUSE:
            return True
        if "address already in use" in str(cur).lower():
            return True
        cur = cur.__cause__ or cur.__context__
    return False


def listen_on_free_port(
    factory: Callable[[int], T],
    kind: int = socket.SOCK_DGRAM,
    attempts: int = 5,
    accept: Callable[[T], bool] | None = None,
) -> tuple[int, T]:
    """Create a listener on a free port, retrying on a fresh port if the bind loses a race.

    ``factory(port)`` builds the listener (it should bind in its constructor). ``accept``
    can reject a result that "succeeded" without owning the port (e.g. a source that
    silently degrades to a reader when the bind fails); the rejected object is closed.
    """
    last: BaseException | None = None
    for _ in range(attempts):
        port = free_port(kind)
        try:
            obj = factory(port)
        except Exception as exc:
            if not _is_addr_in_use(exc):
                raise
            last = exc
            continue
        if accept is not None and not accept(obj):
            close = getattr(obj, "close", None)
            if callable(close):
                close()
            continue
        return port, obj
    raise RuntimeError(f"could not bind a free port after {attempts} attempts") from last
