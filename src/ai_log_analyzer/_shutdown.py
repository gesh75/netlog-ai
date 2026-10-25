"""Process-exit hooks for long-lived workers and sources.

Gunicorn stops a worker with SIGTERM and then exits normally, which runs ``atexit`` handlers,
but nothing in the app called ``manager.shutdown()`` or ``worker.stop()``: up to 512 buffered
syslog lines were lost and the triage lease stayed held for its whole TTL (a blind window per
deploy). ``register(obj, "method")`` arranges for ``obj.method()`` to run once at exit.

* Holds only a weak reference, so registering never keeps an object alive.
* Idempotent per (object, method) and per process: a forked child runs only hooks registered in
  that child, never the parent's (the parent's threads and lease are not the child's).
* SIGTERM: when the process still has the default disposition (plain ``python``, no server that
  installed its own handler) a handler runs the hooks and then re-delivers the default action.
  An existing handler (Gunicorn, uvicorn, pytest) is left alone.
"""
from __future__ import annotations

import atexit
import logging
import os
import signal
import threading
import weakref
from typing import Any

log = logging.getLogger(__name__)

_LOCK = threading.Lock()
_HOOKS: dict[tuple[int, str], tuple[weakref.ref, str, int]] = {}
_INSTALLED_PID = 0


def register(obj: Any, method: str) -> None:
    """Call ``obj.method()`` at interpreter exit (once; safe to call repeatedly)."""
    global _INSTALLED_PID
    pid = os.getpid()
    with _LOCK:
        _HOOKS[(id(obj), method)] = (weakref.ref(obj), method, pid)
        if _INSTALLED_PID != pid:
            _INSTALLED_PID = pid
            atexit.register(run_all)
            _install_sigterm()


def run_all() -> None:
    """Run every live hook registered by this process, once."""
    pid = os.getpid()
    with _LOCK:
        hooks = [h for h in _HOOKS.values() if h[2] == pid]
        _HOOKS.clear()
    for ref, method, _pid in hooks:
        obj = ref()
        if obj is None:
            continue
        try:
            getattr(obj, method)()
        except Exception:   # pragma: no cover - exit path, never raise
            log.exception("exit hook %s.%s failed", type(obj).__name__, method)


def _install_sigterm() -> None:
    if threading.current_thread() is not threading.main_thread():
        return
    try:
        if signal.getsignal(signal.SIGTERM) is not signal.SIG_DFL:
            return

        def _on_term(signum: int, _frame: Any) -> None:
            run_all()
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            os.kill(os.getpid(), signal.SIGTERM)

        signal.signal(signal.SIGTERM, _on_term)
    except (ValueError, OSError):   # not the main interpreter thread / unsupported platform
        pass
