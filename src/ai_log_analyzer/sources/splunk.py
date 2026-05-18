"""Splunk REST search source connector.

Uses the synchronous one-shot search endpoint: POST /services/search/jobs with
exec_mode=oneshot returns results in a single response — no job polling.

Authentication:
  - api_token  → Authorization: Bearer <token>     (recommended)
  - basic      → HTTP basic with username/password (legacy)

Defaults to JSON output. Search string defaults to `search index=* | head N`;
override via `extra["search"]`.
"""
from __future__ import annotations

import logging
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


class SplunkSource:
    """Splunk via REST oneshot search."""
    kind = "splunk"

    def __init__(self, config: SourceConfig) -> None:
        self.config = config
        self.name = config.id
        self.search = config.extra.get("search", "search index=*")
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
    def from_config(cls, config: SourceConfig) -> "SplunkSource":
        return cls(config)

    def healthcheck(self) -> bool:
        try:
            r = self.session.get(
                f"{self.config.url.rstrip('/')}/services/server/info",
                params={"output_mode": "json"},
                timeout=self.config.timeout_seconds,
            )
            r.raise_for_status()
            return True
        except requests.exceptions.Timeout as exc:
            raise SourceTimeoutError(f"Splunk {self.name} healthcheck timed out") from exc
        except requests.exceptions.RequestException as exc:
            raise SourceError(f"Splunk {self.name} healthcheck failed: {exc}") from exc

    def fetch(self, *, since_seconds: int = 3600, limit: int = 10_000,
              host_filter: str = "") -> Iterable[LogEvent]:
        search = self.search
        if host_filter:
            search = f'{search} host="{host_filter}"'
        # Cap to single-page Splunk default to keep response sane.
        page = min(int(limit), 50_000)
        params = {
            "search": search,
            "exec_mode": "oneshot",
            "output_mode": "json",
            "earliest_time": f"-{int(since_seconds)}s",
            "latest_time": "now",
            "count": str(page),
        }
        url = f"{self.config.url.rstrip('/')}/services/search/jobs"
        try:
            r = self.session.post(url, data=params, timeout=self.config.timeout_seconds)
            r.raise_for_status()
            payload = r.json()
        except requests.exceptions.Timeout as exc:
            raise SourceTimeoutError(f"Splunk {self.name} search timed out") from exc
        except requests.exceptions.RequestException as exc:
            raise SourceError(f"Splunk {self.name} search failed: {exc}") from exc

        for result in payload.get("results") or []:
            ev = _result_to_event(result)
            if ev is not None:
                yield ev

    def close(self) -> None:
        self.session.close()


def _result_to_event(r: dict) -> LogEvent | None:
    raw = r.get("_raw") or r.get("message")
    if not raw:
        return None
    return LogEvent(
        timestamp=str(r.get("_time", "")),
        hostname=str(r.get("host", "")),
        appname=str(r.get("sourcetype") or r.get("source") or "splunk"),
        severity_raw=str(r.get("severity") or r.get("level") or "info"),
        message=str(raw),
    )


registry.register("splunk", SplunkSource.from_config)
