"""ServiceNow Table API log source.

Pulls ``em_alert``, ``incident``, or ``syslog`` rows and normalizes them into
``LogEvent`` lines the classifier already understands. Every request is checked
with ``validate_outbound_url`` before ``urllib`` runs.
"""
from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone

from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.sources.base import (
    SourceAuthError,
    SourceConfig,
    SourceError,
    SourceTimeoutError,
    registry,
    validate_outbound_url,
)

LogLine = LogEvent

_TABLES = frozenset({"em_alert", "incident", "syslog"})
_DEVICE_FIELDS = ("cmdb_ci", "node", "source", "u_device")
_MESSAGE_FIELDS = ("short_description", "description", "message")
_SEVERITY = {"1": "CRITICAL", "2": "ERROR", "3": "WARNING"}


class ServiceNowSource:
    """ServiceNow Table API connector. ``name`` is the registry kind."""

    name = "servicenow"
    kind = "servicenow"

    def __init__(self, config: SourceConfig) -> None:
        self.config = config
        self._allow_private = _extra_bool(config.extra, "allow_private", False)
        validate_outbound_url(config.url, allow_private=self._allow_private)

    @classmethod
    def from_config(cls, config: SourceConfig) -> ServiceNowSource:
        return cls(config)

    def test_connection(self, config: SourceConfig | None = None) -> bool:
        """GET one row from the configured table. True when the body has ``result``."""
        cfg = config or self.config
        table = _table(cfg)
        url = _table_url(cfg.url, table, {"sysparm_limit": "1"})
        payload = _get_json(cfg, url)
        return isinstance(payload.get("result"), list)

    def healthcheck(self) -> bool:
        return self.test_connection()

    def fetch(
        self,
        config: SourceConfig | None = None,
        *,
        since_seconds: int = 3600,
        limit: int = 10_000,
        host_filter: str = "",
    ) -> Iterable[LogEvent]:
        """Yield normalized syslog-style events for the requested window."""
        cfg = config or self.config
        table = _table(cfg)
        params = {
            "sysparm_limit": str(max(1, int(limit))),
            "sysparm_display_value": "true",
            "sysparm_query": _query(cfg, since_seconds=since_seconds, host_filter=host_filter),
        }
        payload = _get_json(cfg, _table_url(cfg.url, table, params))
        rows = payload.get("result")
        if not isinstance(rows, list):
            raise SourceError("ServiceNow response is missing a result array")
        for row in rows:
            if isinstance(row, dict):
                event = _row_to_event(row)
                if event is not None:
                    yield event

    def close(self) -> None:
        return None


def _table(config: SourceConfig) -> str:
    raw = str((config.extra or {}).get("table") or "em_alert").strip()
    if raw not in _TABLES:
        raise SourceError(f"unsupported ServiceNow table {raw!r}")
    return raw


def _query(config: SourceConfig, *, since_seconds: int, host_filter: str) -> str:
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=max(0, int(since_seconds)))
    parts = [f"sys_created_on>={cutoff.strftime('%Y-%m-%d %H:%M:%S')}"]
    custom = str((config.extra or {}).get("sysparm_query") or "").strip()
    if custom:
        parts.append(custom)
    if host_filter:
        parts.append(f"cmdb_ciLIKE{host_filter}")
    return "^".join(parts)


def _table_url(base: str, table: str, params: dict[str, str]) -> str:
    root = base.rstrip("/") + f"/api/now/table/{table}"
    return root + "?" + urllib.parse.urlencode(params)


def _get_json(config: SourceConfig, url: str) -> dict:
    allow_private = _extra_bool(config.extra, "allow_private", False)
    validate_outbound_url(url, allow_private=allow_private)
    verify = _verify_ssl(config)
    req = urllib.request.Request(url, headers=_headers(config), method="GET")
    context = None if verify else ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(req, timeout=config.timeout_seconds, context=context) as resp:
            raw = resp.read().decode("utf-8")
    except TimeoutError as exc:
        raise SourceTimeoutError(f"ServiceNow {config.id} timed out") from exc
    except urllib.error.HTTPError as exc:
        raise SourceError(f"ServiceNow {config.id} HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            raise SourceTimeoutError(f"ServiceNow {config.id} timed out") from exc
        raise SourceError(f"ServiceNow {config.id} request failed: {exc.reason}") from exc
    try:
        payload = json.loads(raw) if raw else {}
    except json.JSONDecodeError as exc:
        raise SourceError("ServiceNow returned non-JSON") from exc
    if not isinstance(payload, dict):
        raise SourceError("ServiceNow payload must be a JSON object")
    return payload


def _headers(config: SourceConfig) -> dict[str, str]:
    auth_type = str((config.extra or {}).get("auth_type") or "").strip().lower()
    if auth_type not in {"basic", "bearer"}:
        auth_type = "basic" if config.username else "bearer"
    headers = {"Accept": "application/json", "User-Agent": "netlog-ai/2.1.0"}
    if auth_type == "basic":
        if not config.username:
            raise SourceAuthError(f"ServiceNow {config.id} basic auth requires a username")
        token = base64.b64encode(f"{config.username}:{config.password}".encode()).decode("ascii")
        headers["Authorization"] = f"Basic {token}"
        return headers
    if not config.api_token:
        raise SourceAuthError(f"ServiceNow {config.id} bearer auth requires api_token")
    headers["Authorization"] = f"Bearer {config.api_token}"
    return headers


def _verify_ssl(config: SourceConfig) -> bool:
    extra = config.extra or {}
    if "verify_ssl" in extra:
        return _extra_bool(extra, "verify_ssl", True)
    return bool(config.verify_tls)


def _extra_bool(extra: dict, key: str, default: bool) -> bool:
    if key not in extra:
        return default
    raw = extra[key]
    if isinstance(raw, bool):
        return raw
    return str(raw).strip().lower() not in {"0", "false", "no", "off"}


def _row_to_event(row: dict) -> LogEvent | None:
    device = _first_display(row, _DEVICE_FIELDS)
    message = _first_display(row, _MESSAGE_FIELDS)
    if not message and not device:
        return None
    severity = _severity(row)
    timestamp = _display(row.get("sys_created_on")) or _display(row.get("opened_at"))
    host = device or "unknown"
    text = message or "(no description)"
    line = f"{timestamp} {host} servicenow: {severity}: {text}".strip()
    return LogEvent(
        timestamp=timestamp,
        hostname=host,
        appname="servicenow",
        severity_raw=severity,
        message=line,
    )


def _first_display(row: dict, fields: tuple[str, ...]) -> str:
    for key in fields:
        text = _display(row.get(key))
        if text:
            return text
    return ""


def _display(value: object) -> str:
    if isinstance(value, dict):
        shown = value.get("display_value")
        if shown:
            return str(shown)
        raw = value.get("value")
        return "" if raw is None else str(raw)
    if value is None:
        return ""
    return str(value).strip()


def _severity(row: dict) -> str:
    raw = _display(row.get("severity")) or _display(row.get("priority"))
    token = raw.strip()
    if token[:1] in _SEVERITY:
        return _SEVERITY[token[:1]]
    word = token.lower()
    if word in {"critical", "error", "warning", "info"}:
        return "WARNING" if word == "warning" else word.upper()
    return "INFO"


registry.register("servicenow", ServiceNowSource.from_config)
