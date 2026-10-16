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
})


def validate_outbound_url(url: str, *, allow_private: bool = False) -> str:
    """Reject non-HTTP(S) URLs and SSRF targets before any outbound request.

    Loopback, unspecified, link-local (including the cloud metadata address),
    and metadata hostnames are always blocked. Other private addresses are
    blocked unless ``allow_private`` is set.
    """
    if not isinstance(url, str) or not url.strip():
        raise SourceError("outbound URL is required")
    parsed = urllib.parse.urlparse(url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise SourceError(f"outbound URL scheme {parsed.scheme!r} is not allowed")
    host = parsed.hostname
    if not host:
        raise SourceError("outbound URL is missing a host")
    lowered = host.lower().rstrip(".")
    if lowered in _METADATA_HOSTS or lowered.endswith(".metadata.google.internal"):
        raise SourceError("outbound URL targets a blocked metadata host")
    if lowered == "localhost":
        raise SourceError("outbound URL targets localhost")
    try:
        address = ipaddress.ip_address(lowered)
    except ValueError:
        return url.strip()
    if address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local:
        raise SourceError("outbound URL targets a blocked address")
    if not allow_private and (address.is_private or address.is_reserved):
        raise SourceError("outbound URL targets a private address")
    return url.strip()


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


class _Registry:
    """Lightweight in-memory registry. Connectors register themselves on import
    via `registry.register("kibana", KibanaSource.from_config)`."""

    def __init__(self) -> None:
        self._factories: dict[str, SourceFactory] = {}

    def register(self, kind: str, factory: SourceFactory) -> None:
        if not kind or not callable(factory):
            raise ValueError("kind must be non-empty and factory must be callable")
        self._factories[kind] = factory

    def create(self, config: SourceConfig) -> LogSource:
        if config.type not in self._factories:
            raise SourceError(
                f"Unknown source type {config.type!r}. "
                f"Known: {sorted(self._factories)}"
            )
        return self._factories[config.type](config)

    def known(self) -> list[str]:
        return sorted(self._factories)

    def is_registered(self, kind: str) -> bool:
        return kind in self._factories


registry = _Registry()


# ──────────────────────────────────────────────────────────────────────────────
# Auth helpers — shared by all REST-based connectors
# ──────────────────────────────────────────────────────────────────────────────

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
