"""LibreNMS source connector.

Pulls device eventlog via the LibreNMS REST API (`/api/v0/logs/eventlog`).
Auth is a single token in the `X-Auth-Token` header — simple and well-supported.

Reference: https://docs.librenms.org/API/Logs/
"""
from __future__ import annotations

import logging
import urllib.parse
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone

import requests

from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.sources.base import (
    SourceConfig,
    SourceError,
    SourceTimeoutError,
    guarded_session,
    registry,
    source_allow_private,
    upstream_error,
    validate_host_filter,
)

log = logging.getLogger(__name__)


class LibreNMSSource:
    """LibreNMS eventlog source."""
    kind = "librenms"

    def __init__(self, config: SourceConfig) -> None:
        self.config = config
        self.name = config.id
        self.session = guarded_session(
            verify=config.verify_tls, allow_private=source_allow_private(config))
        if not config.api_token:
            raise SourceError("LibreNMS requires api_token")
        self.session.headers["X-Auth-Token"] = config.api_token
        self.session.headers["Accept"] = "application/json"

    @classmethod
    def from_config(cls, config: SourceConfig) -> LibreNMSSource:
        return cls(config)

    def healthcheck(self) -> bool:
        try:
            r = self.session.get(
                f"{self.config.url.rstrip('/')}/api/v0",
                timeout=self.config.timeout_seconds,
            )
            r.raise_for_status()
            return True
        except requests.exceptions.Timeout:
            raise SourceTimeoutError(f"LibreNMS {self.name} healthcheck timed out") from None
        except requests.exceptions.RequestException as exc:
            raise upstream_error(f"LibreNMS {self.name} healthcheck failed", exc) from None

    def fetch(self, *, since_seconds: int = 3600, limit: int = 10_000,
              host_filter: str = "") -> Iterable[LogEvent]:
        start_iso = (datetime.now(timezone.utc) - timedelta(seconds=int(since_seconds))).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        path = "/api/v0/logs/eventlog"
        host_filter = validate_host_filter(host_filter)
        if host_filter:
            path += "/" + urllib.parse.quote(host_filter, safe="")
        params = {"start": "0", "limit": str(min(int(limit), 1_000)), "from": start_iso}
        url = f"{self.config.url.rstrip('/')}{path}"
        try:
            r = self.session.get(url, params=params, timeout=self.config.timeout_seconds)
            r.raise_for_status()
            payload = r.json()
        except requests.exceptions.Timeout:
            raise SourceTimeoutError(f"LibreNMS {self.name} query timed out") from None
        except requests.exceptions.RequestException as exc:
            raise upstream_error(f"LibreNMS {self.name} query failed", exc) from None

        for ev in payload.get("logs") or []:
            msg = ev.get("message")
            if not msg:
                continue
            yield LogEvent(
                timestamp=str(ev.get("datetime", "")),
                hostname=str(ev.get("hostname") or ev.get("host", "")),
                appname=str(ev.get("type") or "librenms"),
                severity_raw=str(ev.get("severity") or "info"),
                message=str(msg),
            )

    def close(self) -> None:
        self.session.close()


registry.register("librenms", LibreNMSSource.from_config, outbound=True)
