"""``requests`` transport that only connects to addresses it has just checked.

``validate_outbound_url`` at registration is not enough for a long-lived source: a name that resolves to a
public address then can resolve to loopback / link-local / metadata when the request is made (DNS rebinding),
and the stdlib and ``requests`` encode some Unicode names differently (IDNA 2003 vs UTS46), so the name that
was checked is not always the name that gets connected. ``PinnedAdapter`` closes both: every new TCP
connection resolves the exact name the transport would use, checks EVERY answer (``resolve_checked``) and
connects to those addresses, never resolving a second time. TLS SNI, certificate checks and the Host header
stay on the original name because only the socket is replaced. The URL is also re-validated on every request
(each redirect hop is one), not only when the source is registered.

Behind an HTTP(S) proxy the proxy resolves and connects, so only the URL is validated (as ``safe_urlopen``).
"""
from __future__ import annotations

import socket

from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, NewConnectionError

from ai_log_analyzer.sources.base import SourceError, validate_outbound_url
from ai_log_analyzer.sources.outbound import _guarded_create_connection


def _new_pinned_conn(self) -> socket.socket:
    """Replacement for urllib3's ``_new_conn``: same errors, but the connect goes to checked addresses."""
    host = (getattr(self, "_dns_host", None) or self.host).strip("[]")
    try:
        sock = _guarded_create_connection(self._allow_private)(
            (host, self.port), self.timeout, self.source_address)
        for opt in self.socket_options or ():
            sock.setsockopt(*opt)
        return sock
    except SourceError:
        raise                                   # refused by the SSRF guard: not a transport error
    except TimeoutError as exc:
        raise ConnectTimeoutError(
            self, f"Connection to {self.host} timed out. (connect timeout={self.timeout})") from exc
    except OSError as exc:
        raise NewConnectionError(self, f"Failed to establish a new connection: {exc}") from exc


def _pool_classes(allow_private: bool) -> dict[str, type]:
    attrs = {"_new_conn": _new_pinned_conn, "_allow_private": allow_private}
    http_conn = type("PinnedHTTPConnection", (HTTPConnection,), attrs)
    https_conn = type("PinnedHTTPSConnection", (HTTPSConnection,), attrs)
    return {
        "http": type("PinnedHTTPPool", (HTTPConnectionPool,), {"ConnectionCls": http_conn}),
        "https": type("PinnedHTTPSPool", (HTTPSConnectionPool,), {"ConnectionCls": https_conn}),
    }


class PinnedAdapter(HTTPAdapter):
    __attrs__ = [*HTTPAdapter.__attrs__, "_allow_private"]

    def __init__(self, allow_private: bool = False, **kwargs) -> None:
        self._allow_private = allow_private     # before super().__init__, which builds the pool manager
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs) -> None:
        super().init_poolmanager(*args, **kwargs)
        # a fresh dict on this manager only: urllib3's module-level default stays untouched
        self.poolmanager.pool_classes_by_scheme = _pool_classes(self._allow_private)

    def send(self, request, *args, **kwargs):
        validate_outbound_url(request.url, allow_private=self._allow_private, resolve=False)
        return super().send(request, *args, **kwargs)
