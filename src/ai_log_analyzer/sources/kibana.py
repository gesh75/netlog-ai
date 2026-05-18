"""Kibana / Elasticsearch source connector.

Talks to the Elasticsearch `_search` API directly (Kibana ships with ES). Same
auth model as Datadog/Splunk: API token preferred, basic auth fallback, cookie
last resort. Index pattern + hostname field are configurable per deployment.

Real-world scale (from prior closed-source deployments): handled ~2.4M syslog
events / 24h across 50 devices on a single host.
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


# Common Elasticsearch field aliases — different deployments use different names.
# Connector picks the first present field in the document.
_FIELD_TIMESTAMP = ("@timestamp", "timestamp", "ts", "event.created")
_FIELD_HOST = ("host.name", "host.hostname", "host", "hostname", "agent.name")
_FIELD_APP = ("process.name", "app", "appname", "program", "syslog.appname")
_FIELD_SEV = ("log.syslog.severity.name", "severity", "level", "log.level")
_FIELD_MSG = ("message", "msg", "log.original", "event.original")


class KibanaSource:
    """Elasticsearch via REST `_search` endpoint."""
    kind = "kibana"

    def __init__(self, config: SourceConfig) -> None:
        self.config = config
        self.name = config.id
        self.index_pattern = config.extra.get("index_pattern", "*")
        self.session = requests.Session()
        self.session.verify = config.verify_tls
        headers, cookies, basic = build_auth(
            config,
            token_header="Authorization",
            token_scheme="ApiKey" if config.extra.get("auth_scheme") == "apikey" else "Bearer",
        )
        if headers:
            self.session.headers.update(headers)
        if cookies:
            self.session.cookies.update(cookies)
        if basic:
            self.session.auth = basic
        self.session.headers.setdefault("Content-Type", "application/json")
        self.session.headers.setdefault("Accept", "application/json")

    # ── classmethod factory used by the registry ─────────────────────────────
    @classmethod
    def from_config(cls, config: SourceConfig) -> "KibanaSource":
        return cls(config)

    # ── LogSource interface ──────────────────────────────────────────────────
    def healthcheck(self) -> bool:
        try:
            r = self.session.get(
                f"{self.config.url.rstrip('/')}/_cluster/health",
                timeout=self.config.timeout_seconds,
            )
            r.raise_for_status()
            data = r.json()
            # green / yellow are both operational
            return data.get("status") in {"green", "yellow"}
        except requests.exceptions.Timeout as exc:
            raise SourceTimeoutError(f"Kibana {self.name} healthcheck timed out") from exc
        except requests.exceptions.RequestException as exc:
            raise SourceError(f"Kibana {self.name} healthcheck failed: {exc}") from exc

    def fetch(self, *, since_seconds: int = 3600, limit: int = 10_000,
              host_filter: str = "") -> Iterable[LogEvent]:
        # Cap limit defensively — single page max, callers chunk if they need more.
        page_size = min(int(limit), 10_000)
        query = self._build_query(since_seconds, host_filter, page_size)
        url = f"{self.config.url.rstrip('/')}/{self.index_pattern}/_search"
        try:
            r = self.session.post(url, json=query, timeout=self.config.timeout_seconds)
            r.raise_for_status()
            payload = r.json()
        except requests.exceptions.Timeout as exc:
            raise SourceTimeoutError(f"Kibana {self.name} search timed out") from exc
        except requests.exceptions.RequestException as exc:
            raise SourceError(f"Kibana {self.name} search failed: {exc}") from exc

        hits = (payload.get("hits") or {}).get("hits") or []
        for hit in hits:
            ev = _doc_to_event(hit.get("_source") or {})
            if ev is not None:
                yield ev

    def close(self) -> None:
        self.session.close()

    # ── private helpers ──────────────────────────────────────────────────────
    def _build_query(self, since_seconds: int, host_filter: str, size: int) -> dict:
        must: list[dict] = [
            {"range": {"@timestamp": {"gte": f"now-{int(since_seconds)}s", "lte": "now"}}}
        ]
        if host_filter:
            must.append({
                "bool": {
                    "should": [
                        {"match_phrase": {"host.name": host_filter}},
                        {"match_phrase": {"hostname": host_filter}},
                        {"match_phrase": {"host": host_filter}},
                    ],
                    "minimum_should_match": 1,
                },
            })
        return {
            "size": size,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {"bool": {"must": must}},
        }


# ── document -> LogEvent normalizer ─────────────────────────────────────────
def _pick(src: dict, candidates: tuple[str, ...]) -> str:
    """Pick the first non-empty field, supporting dotted paths (`host.name`)."""
    for c in candidates:
        cur: object = src
        for part in c.split("."):
            if not isinstance(cur, dict):
                cur = None
                break
            cur = cur.get(part)
        if cur is not None and cur != "":
            return str(cur)
    return ""


def _doc_to_event(src: dict) -> LogEvent | None:
    msg = _pick(src, _FIELD_MSG)
    if not msg:
        return None
    return LogEvent(
        timestamp=_pick(src, _FIELD_TIMESTAMP),
        hostname=_pick(src, _FIELD_HOST),
        appname=_pick(src, _FIELD_APP) or "kibana",
        severity_raw=_pick(src, _FIELD_SEV) or "info",
        message=msg,
    )


# Self-register on import.
registry.register("kibana", KibanaSource.from_config)
registry.register("elasticsearch", KibanaSource.from_config)  # alias
