"""Hardened outbound HTTP for credentialed calls (ITSM, ServiceNow, NetBox).

Three guarantees the stdlib ``urlopen`` does not give:

  * the target passes the SSRF guard (``validate_outbound_url``) before any
    socket opens, and the TCP connect itself re-checks every address it is
    about to use, so DNS rebinding between check and connect cannot reach an
    internal host;
  * redirects are never followed (a 302 would forward ``Authorization`` to
    the redirect target);
  * credentials supplied by the server environment are only ever sent to the
    endpoint the same environment names (``require_env_bound_target``).

Tests monkeypatch ``ai_log_analyzer.sources.outbound.safe_urlopen``.
"""
from __future__ import annotations

import functools
import http.client
import os
import socket
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping

from ai_log_analyzer.sources.base import (
    SourceError,
    resolve_checked,
    validate_outbound_url,
)

__all__ = [
    "endpoints_match",
    "env_values",
    "require_env_bound_target",
    "safe_urlopen",
    "uses_env_credentials",
]


def env_values(*names: str) -> tuple[str, ...]:
    """Every non-empty, stripped value among the named environment variables."""
    return tuple(v for v in (os.environ.get(n, "").strip() for n in names) if v)


def _endpoint_key(url: str) -> tuple[str, str, int, str] | None:
    try:
        parsed = urllib.parse.urlparse((url or "").strip())
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme not in {"http", "https"} or not host:
            return None
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return None
    return (parsed.scheme, host, port, parsed.path.rstrip("/"))


def endpoints_match(left: str, right: str) -> bool:
    """Same scheme, host, port and path (trailing slash and case-insensitive host)."""
    a, b = _endpoint_key(left), _endpoint_key(right)
    return a is not None and a == b


def uses_env_credentials(supplied: Mapping[str, str], env_creds: Mapping[str, tuple[str, ...]]) -> bool:
    """True when any supplied credential equals a server-environment value for
    the same field. A caller's own credentials never match, so providing them
    lifts the pin; pointing a server-credential request elsewhere does not."""
    return any(value and value in env_creds.get(name, ()) for name, value in supplied.items())


def require_env_bound_target(
    service: str,
    url: str,
    *,
    supplied: Mapping[str, str],
    env_creds: Mapping[str, tuple[str, ...]],
    env_urls: tuple[str, ...],
) -> bool:
    """Refuse to send server-environment credentials to a caller-chosen URL.

    Returns True when ``url`` is the operator-configured endpoint (a trusted,
    possibly private, on-prem instance). Raises ``SourceError`` when the
    credentials come from the environment but the URL differs from every
    configured one. Returns False for caller-supplied credentials and URL
    (still subject to the full SSRF guard).
    """
    if not uses_env_credentials(supplied, env_creds):
        return False
    if any(env_url and endpoints_match(url, env_url) for env_url in env_urls):
        return True
    raise SourceError(
        f"{service}: refusing to send server-configured credentials to a URL that is not the "
        "configured one; supply your own credentials with the URL, or use the configured endpoint"
    )


# ── connection-level guard ───────────────────────────────────────────────────

def _guarded_create_connection(allow_private: bool):
    """``socket.create_connection`` replacement that connects only to addresses
    it has itself just checked (closes the DNS-rebinding window)."""
    def create(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
        host, port = address
        last: OSError | None = None
        for family, kind, proto, _canon, sockaddr in resolve_checked(
                host, port, allow_private=allow_private):
            sock = None
            try:
                sock = socket.socket(family, kind, proto)
                if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                    sock.settimeout(timeout)
                if source_address:
                    sock.bind(source_address)
                sock.connect(sockaddr)
                return sock
            except OSError as exc:
                last = exc
                if sock is not None:
                    sock.close()
        raise last or OSError("no usable address")
    return create


class _GuardedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, *args, allow_private: bool = False, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._create_connection = _guarded_create_connection(allow_private)


class _GuardedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args, allow_private: bool = False, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._create_connection = _guarded_create_connection(allow_private)


class _GuardedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, allow_private: bool) -> None:
        super().__init__()
        self._allow_private = allow_private

    def http_open(self, req):
        return self.do_open(functools.partial(_GuardedHTTPConnection, allow_private=self._allow_private), req)


class _GuardedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, allow_private: bool, context=None) -> None:
        super().__init__(context=context)
        self._allow_private = allow_private

    def https_open(self, req):
        return self.do_open(
            functools.partial(_GuardedHTTPSConnection, allow_private=self._allow_private),
            req, context=self._context)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: the credentialed request must not be replayed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SourceError(
            f"refusing to follow HTTP {code} redirect from {req.full_url.split('?', 1)[0]}; "
            "configure the final URL instead")


def _proxied(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in urllib.request.getproxies():
        return False
    return not urllib.request.proxy_bypass(parsed.hostname or "")


def safe_urlopen(req: urllib.request.Request, timeout: float = 15, *, context=None,
                 allow_private: bool = False, require_https: bool = True):
    """``urlopen`` for credentialed requests: SSRF-validated, no redirects.

    Behind an HTTP(S) proxy the proxy performs name resolution and the
    connect, so only the URL itself is validated (no local DNS lookup).
    """
    url = req.full_url
    proxied = _proxied(url)
    validate_outbound_url(url, allow_private=allow_private, require_https=require_https,
                          resolve=not proxied)
    handlers: list = [_NoRedirect()]
    if not proxied:
        handlers += [_GuardedHTTPHandler(allow_private), _GuardedHTTPSHandler(allow_private, context)]
    elif context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    opener = urllib.request.build_opener(*handlers)
    try:
        return opener.open(req, timeout=timeout)
    except urllib.error.URLError as exc:
        # A SourceError raised inside connect() arrives wrapped as URLError.
        if isinstance(exc.reason, SourceError):
            raise exc.reason from None
        raise
