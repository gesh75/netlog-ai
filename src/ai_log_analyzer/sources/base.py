"""LogSource Protocol — the contract every external connector must satisfy.

Design goals:
  - Sync iterators (matches existing analyzer pipeline, no asyncio surprises).
  - Graceful auth fallback (api_token → basic → cookie) — declarative, like the
    pattern proven at scale in the prior closed-source version of this tool.
  - Lightweight: no extra runtime deps beyond `requests` (already in pyproject).
  - Output: existing `LogEvent` dataclass from `classifier.py` — connectors are
    plain producers, the rest of the pipeline (classifier → dedup → LLM)
    needs no changes.
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import urllib.parse
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from ai_log_analyzer.classifier import LogEvent

# ──────────────────────────────────────────────────────────────────────────────
# Exceptions
# ──────────────────────────────────────────────────────────────────────────────

class SourceError(RuntimeError):
    """Generic source failure (network, parse, downstream API error)."""


class SourceTimeoutError(SourceError):
    """Source did not respond within the configured timeout."""


class SourceAuthError(SourceError):
    """All configured auth methods failed for this source."""


_METADATA_HOSTS = frozenset({
    "metadata.google.internal",
    "metadata.google.com",
    "metadata",
    "instance-data",
    "instance-data.ec2.internal",
})

# Never reachable, even with allow_private: cloud metadata services and
# addresses that are never a legitimate log/ITSM endpoint.
_ALWAYS_BLOCKED_NETS = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8",           # "this network" (0.0.0.0 reaches localhost on Linux)
    "169.254.0.0/16",      # link-local incl. 169.254.169.254 (AWS/GCP/Azure metadata)
    "100.100.100.200/32",  # Alibaba Cloud metadata (inside CGNAT space)
    "168.63.129.16/32",    # Azure WireServer
    "fd00:ec2::/32",       # AWS IPv6 metadata
))
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_NUM_PART = re.compile(r"^(?:0[xX][0-9a-fA-F]*|[0-9]+)$")
_TRUE = {"1", "true", "yes", "on"}

# Host-filter allowlist shared by every connector: hostnames, IPs, ``*`` globs.
_HOST_FILTER_RE = re.compile(r"^[A-Za-z0-9._:*-]{1,255}$")


def env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in _TRUE


def validate_host_filter(host_filter: str) -> str:
    """Strict allowlist for the ``host_filter`` every connector interpolates
    into a path, LogQL, SPL or encoded-query string (blocks ``..`` traversal,
    quote breakout and ServiceNow ``^OR`` injection)."""
    value = (host_filter or "").strip()
    if not value:
        return ""
    if not _HOST_FILTER_RE.match(value) or ".." in value:
        raise SourceError("host_filter may only contain letters, digits and . _ : * -")
    return value


def _parse_ipv4_loose(host: str) -> ipaddress.IPv4Address | None:
    """Parse the legacy ``inet_aton`` spellings (``2130706433``, ``127.1``,
    ``0x7f.0.0.1``, ``0177.0.0.1``) that ``ipaddress`` rejects but every libc
    resolver and most HTTP stacks accept."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4 or not all(_NUM_PART.match(p) for p in parts):
        return None
    nums: list[int] = []
    for part in parts:
        try:
            if part[:2] in ("0x", "0X"):
                nums.append(int(part[2:] or "0", 16))
            elif len(part) > 1 and part.startswith("0"):
                nums.append(int(part, 8))
            else:
                nums.append(int(part))
        except ValueError:
            return None
    last_bits = 8 * (5 - len(parts))
    if any(n > 255 for n in nums[:-1]) or nums[-1] >= 1 << last_bits:
        return None
    value = 0
    for n in nums[:-1]:
        value = (value << 8) | n
    return ipaddress.IPv4Address((value << last_bits) | nums[-1])


def _literal_address(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return _parse_ipv4_loose(host)


def address_problem(addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
                    allow_private: bool = False) -> str | None:
    """Why ``addr`` must not be contacted, or None. ``allow_private`` permits
    loopback/private/CGNAT/reserved ranges only; link-local, metadata,
    unspecified and multicast stay blocked."""
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        elif addr in _NAT64:
            addr = ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    if (addr.is_unspecified or addr.is_multicast or addr.is_link_local
            or any(addr in net for net in _ALWAYS_BLOCKED_NETS if net.version == addr.version)):
        return "a blocked address (link-local, metadata, unspecified or multicast)"
    if allow_private:
        return None
    if addr.is_loopback:
        return "a loopback address"
    if addr.is_private or addr.is_reserved or not addr.is_global or (
            addr.version == 4 and addr in _CGNAT):
        return "a private or non-routable address"
    return None


def resolve_checked(host: str, port: int | None, *, allow_private: bool = False) -> list[tuple]:
    """Resolve ``host`` and check EVERY returned address. Fails closed: a name
    that does not resolve is rejected rather than trusted. Returns getaddrinfo
    tuples so a caller can connect to exactly what was checked."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError) as exc:
        raise SourceError(f"outbound host {host!r} does not resolve ({exc}); refusing") from exc
    if not infos:
        raise SourceError(f"outbound host {host!r} resolved to no addresses; refusing")
    for info in infos:
        raw = str(info[4][0]).split("%", 1)[0]
        try:
            addr = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise SourceError(f"outbound host {host!r} resolved to an unparseable address") from exc
        problem = address_problem(addr, allow_private)
        if problem:
            raise SourceError(f"outbound URL host {host!r} resolves to {problem}")
    return list(infos)


def validate_outbound_url(url: str, *, allow_private: bool = False,
                          require_https: bool = False, resolve: bool = True) -> str:
    """Reject non-HTTP(S) URLs and SSRF targets before any outbound request.

    Numeric host spellings (``2130706433``, ``127.1``, ``0x7f.0.0.1``) are
    normalised, and DNS names are resolved with every returned address
    checked (loopback, link-local/metadata, unspecified, multicast, and
    private/CGNAT/reserved unless ``allow_private``). A name that does not
    resolve is rejected (fail closed). ``NETLOG_ALLOW_PRIVATE_OUTBOUND=1`` is
    the operator-wide equivalent of ``allow_private``.

    ``require_https`` is for credentialed ITSM calls: plain http is accepted
    only when ``NETLOG_ALLOW_INSECURE_HTTP=1``, or when ``allow_private`` is
    in effect and every address is private/loopback.
    """
    if not isinstance(url, str) or not url.strip():
        raise SourceError("outbound URL is required")
    url = url.strip()
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise SourceError(f"outbound URL scheme {parsed.scheme!r} is not allowed")
    host = parsed.hostname
    if not host:
        raise SourceError("outbound URL is missing a host")
    try:
        port = parsed.port
    except ValueError as exc:
        raise SourceError("outbound URL has an invalid port") from exc
    if require_https and (parsed.username is not None or parsed.password is not None):
        raise SourceError("outbound URL must not embed credentials")
    allow_private = allow_private or env_flag("NETLOG_ALLOW_PRIVATE_OUTBOUND")
    lowered = host.lower().rstrip(".")
    if lowered in _METADATA_HOSTS or lowered.endswith(".metadata.google.internal"):
        raise SourceError("outbound URL targets a blocked metadata host")
    if not allow_private and (lowered == "localhost" or lowered.endswith(".localhost")):
        raise SourceError("outbound URL targets localhost")
    literal = _literal_address(lowered)
    private_only = False
    if literal is not None:
        problem = address_problem(literal, allow_private)
        if problem:
            raise SourceError(f"outbound URL targets {problem}")
        private_only = not literal.is_global
    elif resolve:
        infos = resolve_checked(lowered, port or (443 if parsed.scheme == "https" else 80),
                                allow_private=allow_private)
        private_only = all(not ipaddress.ip_address(str(i[4][0]).split("%", 1)[0]).is_global
                           for i in infos)
    if require_https and parsed.scheme != "https":
        if not (env_flag("NETLOG_ALLOW_INSECURE_HTTP") or (allow_private and private_only)):
            raise SourceError("outbound URL must use https "
                              "(plain http needs NETLOG_ALLOW_INSECURE_HTTP=1 or a private test host)")
    return url


# ──────────────────────────────────────────────────────────────────────────────
# Config dataclass
# ──────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SourceConfig:
    """Per-source configuration. Immutable so it can be safely shared."""
    id: str                                    # short identifier, e.g. "kibana-prod"
    type: str                                  # connector type, e.g. "kibana"
    url: str                                   # base URL
    auth_methods: tuple[str, ...] = ()         # fallback order, e.g. ("api_token","basic","cookie")
    api_token: str = ""
    username: str = ""
    password: str = ""
    cookies: dict[str, str] = field(default_factory=dict)
    extra: dict[str, str] = field(default_factory=dict)  # connector-specific opts
    verify_tls: bool = True
    timeout_seconds: float = 30.0
    # Programmatic opt-in to private/loopback targets. Deliberately a typed
    # field, not an ``extra`` key: ``extra`` is caller-controlled (MCP, web),
    # this is not reachable from there.
    allow_private: bool = False


# ──────────────────────────────────────────────────────────────────────────────
# Protocol
# ──────────────────────────────────────────────────────────────────────────────

@runtime_checkable
class LogSource(Protocol):
    """Contract every external connector implements.

    `name` is a human label. `kind` matches `SourceConfig.type`. `healthcheck`
    is cheap (no log fetch). `fetch` returns an iterable of `LogEvent` for the
    requested time window — connector decides pagination internally.
    """
    name: str
    kind: str

    def healthcheck(self) -> bool:
        """Return True if the source is reachable and auth works. Raise on hard error."""
        ...

    def fetch(self, *, since_seconds: int = 3600, limit: int = 10_000,
              host_filter: str = "") -> Iterable[LogEvent]:
        """Yield LogEvent instances from the last `since_seconds`, up to `limit`."""
        ...

    def close(self) -> None:
        """Release any held resources (sessions, sockets, listener threads)."""
        ...


# ──────────────────────────────────────────────────────────────────────────────
# Registry — supports late binding via entry_points or manual registration
# ──────────────────────────────────────────────────────────────────────────────

SourceFactory = Callable[[SourceConfig], LogSource]


def _operator_configured(config: SourceConfig) -> bool:
    """True when ``config.url`` is exactly what the operator put in the
    environment for this source id (NETLOG_SOURCE_<id>_URL, or SOLARWINDS_URL
    for the native SolarWinds source)."""
    url = (config.url or "").strip()
    if not url:
        return False
    if os.environ.get(f"NETLOG_SOURCE_{config.id}_URL", "").strip() == url:
        return True
    return config.id == "solarwinds" and os.environ.get("SOLARWINDS_URL", "").strip() == url


def source_allow_private(config: SourceConfig) -> bool:
    """May this source target private/loopback addresses?

    Yes only for operator-owned configuration: the typed ``allow_private``
    field, ``NETLOG_ALLOW_PRIVATE_OUTBOUND=1``, a URL taken from the
    operator's own NETLOG_SOURCE_<id>_URL / SOLARWINDS_URL, or an explicit
    ``NETLOG_SOURCE_<id>_ALLOW_PRIVATE=true``. A bare ``extra["allow_private"]``
    from an API caller is NOT honoured.
    """
    if config.allow_private or env_flag("NETLOG_ALLOW_PRIVATE_OUTBOUND"):
        return True
    if _operator_configured(config):
        return True
    asked = str((config.extra or {}).get("allow_private", "")).strip().lower() in _TRUE
    return asked and env_flag(f"NETLOG_SOURCE_{config.id}_ALLOW_PRIVATE")


class _Registry:
    """Lightweight in-memory registry. Connectors register themselves on import
    via `registry.register("kibana", KibanaSource.from_config)`."""

    def __init__(self) -> None:
        self._factories: dict[str, SourceFactory] = {}
        self._outbound: set[str] = set()

    def register(self, kind: str, factory: SourceFactory, *, outbound: bool = False) -> None:
        """``outbound=True`` marks a network connector: ``create`` then runs
        the SSRF guard on ``config.url`` before the factory is called."""
        if not kind or not callable(factory):
            raise ValueError("kind must be non-empty and factory must be callable")
        self._factories[kind] = factory
        (self._outbound.add if outbound else self._outbound.discard)(kind)

    def create(self, config: SourceConfig) -> LogSource:
        if config.type not in self._factories:
            raise SourceError(
                f"Unknown source type {config.type!r}. "
                f"Known: {sorted(self._factories)}"
            )
        if config.type in self._outbound:
            validate_outbound_url(config.url, allow_private=source_allow_private(config))
        return self._factories[config.type](config)

    def known(self) -> list[str]:
        return sorted(self._factories)

    def is_registered(self, kind: str) -> bool:
        return kind in self._factories


registry = _Registry()


# ──────────────────────────────────────────────────────────────────────────────
# Auth helpers — shared by all REST-based connectors
# ──────────────────────────────────────────────────────────────────────────────

def guarded_session(*, verify: bool = True, allow_private: bool = False):
    """``requests.Session`` that re-runs the SSRF guard on every redirect hop,
    so a 3xx from a vetted host cannot bounce the (credentialed) request to
    loopback / metadata / an internal address."""
    import requests

    session = requests.Session()
    session.verify = verify

    def _check_redirect(response, *_args, **_kwargs):
        if response.is_redirect:
            target = urllib.parse.urljoin(response.url, response.headers.get("location", ""))
            validate_outbound_url(target, allow_private=allow_private)
        return response

    session.hooks["response"].append(_check_redirect)
    return session


def build_auth(config: SourceConfig, *,
               token_header: str = "Authorization",
               token_scheme: str = "Bearer") -> tuple[dict[str, str], dict[str, str], tuple | None]:
    """Return (headers, cookies, basic_auth) for the first auth method that has
    sufficient credentials in `config.auth_methods`. Raises SourceAuthError if
    none satisfy.

    `basic_auth` is the requests-compatible (user, pass) tuple or None.
    """
    methods = config.auth_methods or ("api_token", "basic", "cookie")
    last_err = ""
    for method in methods:
        if method == "api_token" and config.api_token:
            return ({token_header: f"{token_scheme} {config.api_token}".strip()}, {}, None)
        if method == "basic" and config.username and config.password:
            return ({}, {}, (config.username, config.password))
        if method == "cookie" and config.cookies:
            return ({}, dict(config.cookies), None)
        last_err = f"method {method!r} has no credentials"
    raise SourceAuthError(f"No usable auth method for source {config.id!r}: {last_err}")
