"""The shared socket/polling helpers used by the syslog and live-tail tests."""
from __future__ import annotations

import errno
import socket

import pytest

from tests._helpers import free_port, listen_on_free_port, wait_for

pytestmark = pytest.mark.unit


def test_wait_for_returns_true_once_condition_holds_and_false_on_timeout():
    ticks = iter([False, False, True])
    assert wait_for(lambda: next(ticks), timeout=1.0, interval=0.001)
    assert wait_for(lambda: False, timeout=0.05, interval=0.01) is False


@pytest.mark.parametrize("kind", [socket.SOCK_DGRAM, socket.SOCK_STREAM])
def test_free_port_is_bindable(kind):
    port = free_port(kind)
    s = socket.socket(socket.AF_INET, kind)
    try:
        s.bind(("127.0.0.1", port))
    finally:
        s.close()


def test_listen_on_free_port_retries_on_address_in_use():
    seen: list[int] = []

    def factory(port: int) -> str:
        seen.append(port)
        if len(seen) < 3:
            raise OSError(errno.EADDRINUSE, "Address already in use")
        return "listener"

    port, obj = listen_on_free_port(factory)
    assert obj == "listener" and port == seen[-1] and len(seen) == 3


def test_listen_on_free_port_recognises_wrapped_bind_errors():
    calls = {"n": 0}

    class Wrapped(Exception):
        pass

    def factory(port: int) -> str:
        calls["n"] += 1
        if calls["n"] == 1:
            try:
                raise OSError(errno.EADDRINUSE, "busy")
            except OSError as exc:
                raise Wrapped("could not bind") from exc
        return "ok"

    assert listen_on_free_port(factory)[1] == "ok"


def test_listen_on_free_port_does_not_swallow_other_errors():
    def factory(port: int) -> str:
        raise ValueError("bad config")

    with pytest.raises(ValueError):
        listen_on_free_port(factory)


def test_listen_on_free_port_rejects_and_closes_degraded_results():
    class Fake:
        closed = 0

        def __init__(self, ok: bool) -> None:
            self.ok = ok

        def close(self) -> None:
            Fake.closed += 1

    made: list[Fake] = []

    def factory(port: int) -> Fake:
        made.append(Fake(ok=len(made) >= 1))
        return made[-1]

    _, obj = listen_on_free_port(factory, accept=lambda f: f.ok)
    assert obj is made[1] and Fake.closed == 1
