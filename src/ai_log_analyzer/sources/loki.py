"""Grafana Loki source connector.

Uses `/loki/api/v1/query_range`. LogQL query string is configurable via
`extra["query"]`. Defaults to `{job=~".+"}` (all streams) which is broad but
useful for first-run "show me what's there" mode.

Auth (in fallback order):
  - api_token  → Authorization: Bearer <token>     (Grafana Cloud / OAuth proxy)
  - basic      → HTTP basic with username/password
  - cookie     → grafana_session cookie
"""
from __future__ import annotations

import logging
import time
from typing import Iterable

import requests

from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.sources.base import (
    LogSource,
    SourceConfig,
    SourceError,
    SourceTimeoutError,
    build_auth,
    registry,
)

log = logging.getLogger(__name__)


class LokiSource:
    """Loki via REST query_range API."""
    kind = "loki"

    def __init__(self, config: SourceConfig) -> None:
        self.config = config
        self.name = config.id
        self.query = config.extra.get("query", '{job=~".+"}')
        self.session = requests.Session()
        self.session.verify = config.verify_tls
        headers, cookies, basic = build_auth(config, token_scheme="Bearer")
        if headers:
            self.session.headers.update(headers)
        if cookies:
            self.session.cookies.update(cookies)
        if basic:
            self.session.auth = basic

    @classmethod
    def from_config(cls, config: SourceConfig) -> "LokiSource":
        return cls(config)

    def healthcheck(self) -> bool:
        try:
            r = self.session.get(
                f"{self.config.url.rstrip('/')}/ready",
                timeout=self.config.timeout_seconds,
            )
            # 200 with "ready" body OR 503 with "Ingester not ready" are both alive
            return r.status_code in (200, 503)
        except requests.exceptions.Timeout as exc:
            raise SourceTimeoutError(f"Loki {self.name} healthcheck timed out") from exc
        except requests.exceptions.RequestException as exc:
            raise SourceError(f"Loki {self.name} healthcheck failed: {exc}") from exc

    def fetch(self, *, since_seconds: int = 3600, limit: int = 10_000,
              host_filter: str = "") -> Iterable[LogEvent]:
        end_ns = int(time.time() * 1e9)
        start_ns = end_ns - int(since_seconds) * 1_000_000_000
        query = self.query
        if host_filter:
            # Loki label filter; assumes a `host` or `hostname` label is set.
            query = f'{query} |= "{host_filter}"'
        params = {
            "query": query,
            "start": str(start_ns),
            "end": str(end_ns),
            "limit": str(min(int(limit), 5_000)),  # Loki single-page default cap
            "direction": "backward",
        }
        url = f"{self.config.url.rstrip('/')}/loki/api/v1/query_range"
        try:
            r = self.session.get(url, params=params, timeout=self.config.timeout_seconds)
            r.raise_for_status()
            payload = r.json()
        except requests.exceptions.Timeout as exc:
            raise SourceTimeoutError(f"Loki {self.name} query timed out") from exc
        except requests.exceptions.RequestException as exc:
            raise SourceError(f"Loki {self.name} query failed: {exc}") from exc

        for stream in (payload.get("data") or {}).get("result", []):
            labels = stream.get("stream") or {}
            host = labels.get("host") or labels.get("hostname") or labels.get("instance") or ""
            app = labels.get("app") or labels.get("job") or labels.get("service") or "loki"
            sev = labels.get("level") or labels.get("severity") or "info"
            for ns_str, line in stream.get("values") or []:
                if not line:
                    continue
                yield LogEvent(
                    timestamp=ns_str,
                    hostname=str(host),
                    appname=str(app),
                    severity_raw=str(sev),
                    message=str(line),
                )

    def close(self) -> None:
        self.session.close()


registry.register("loki", LokiSource.from_config)
