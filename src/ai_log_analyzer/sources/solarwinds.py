"""SolarWinds Orion SWIS + Observability SaaS source connector.

On-prem Orion is queried first via SWQL on the Information Service
(`/SolarWinds/InformationService/v3/Json/Query`, typically port 17778).
If that call fails with an HTTP or URL error, the connector falls back to
the Observability SaaS `GET v1/alerts?status=active` endpoint.

Authentication (first match wins):
  - api_token  → Authorization: Bearer <token>
  - username + password → Authorization: Basic <base64>

Credentials are never written to logs. The User-Agent product version is
read from the installed package metadata, not hardcoded.
"""
from __future__ import annotations

import base64
import logging
import urllib.error
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

import requests

from ai_log_analyzer import __version__
from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.sources.base import (
    SourceConfig,
    SourceError,
    SourceTimeoutError,
    registry,
)

log = logging.getLogger(__name__)

_ORION_SWQL = "SELECT AlertMessage, Severity, TriggerTime, EntityNetObjectId FROM Orion.AlertActive"
_ORION_QUERY_PATH = "/SolarWinds/InformationService/v3/Json/Query"
_SAAS_ALERTS_PATH = "v1/alerts"

# Fallback is intentionally narrow: HTTP / URL failures only — never `except Exception`.
_FALLBACK_ERRORS = (
    requests.exceptions.HTTPError,
    requests.exceptions.ConnectionError,
    requests.exceptions.InvalidURL,
    requests.exceptions.InvalidSchema,
    requests.exceptions.MissingSchema,
    urllib.error.HTTPError,
    urllib.error.URLError,
)


@dataclass(frozen=True)
class SolarWindsConfig:
    """Native SolarWinds connector settings (Orion SWIS or Observability SaaS)."""

    endpoint_url: str
    username: str = ""
    password: str = ""
    api_token: str = ""
    verify_ssl: bool = True
    timeout: int = 15


def _user_agent() -> str:
    return f"netlog-ai/{__version__}"


def _first_str(alert: dict[str, Any], *keys: str, default: str = "") -> str:
    for key in keys:
        value = alert.get(key)
        if value is not None and str(value).strip() != "":
            return str(value)
    return default


def _entity_node(alert: dict[str, Any]) -> str:
    entity = alert.get("entity")
    if isinstance(entity, dict):
        return _first_str(entity, "name", "id", "entityId", default="")
    if isinstance(entity, str) and entity.strip():
        return entity
    return _first_str(
        alert,
        "EntityNetObjectId",
        "entityId",
        "entityName",
        "node",
        "hostname",
        default="unknown",
    )


def normalize_alert(alert: dict[str, Any]) -> str:
    """Render one Orion or SaaS alert as a syslog-shaped line."""
    timestamp = _first_str(alert, "TriggerTime", "triggeredAt", "createdAt", "timestamp", "time")
    node = _entity_node(alert)
    severity = _first_str(alert, "Severity", "severity", default="info")
    msg = _first_str(alert, "AlertMessage", "message", "name", "description", "title")
    return f"{timestamp} {node} SolarWindsAlert[{severity}]: {msg}"


def _extract_alerts(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("results", "Results", "alerts", "data"):
        items = payload.get(key)
        if isinstance(items, list):
            return [row for row in items if isinstance(row, dict)]
    return []


class SolarWindsConnector:
    """SolarWinds Orion (SWIS) with Observability SaaS fallback.

    Implements the repo `LogSource` protocol (`healthcheck` / `fetch` / `close`)
    in addition to the SolarWinds-specific `fetch_active_alerts` / `pull_logs`
    surface so `--source solarwinds` and `NETLOG_SOURCE_*` config blocks work.
    """

    kind = "solarwinds"

    def __init__(self, config: SolarWindsConfig) -> None:
        self.config = config
        self.name = "solarwinds"
        self.session = requests.Session()
        self.session.verify = config.verify_ssl
        self.session.headers["Accept"] = "application/json"
        self.session.headers["User-Agent"] = _user_agent()

    @classmethod
    def from_config(cls, config: SourceConfig) -> SolarWindsConnector:
        timeout = int(config.timeout_seconds) if config.timeout_seconds else 15
        sw_config = SolarWindsConfig(
            endpoint_url=config.url,
            username=config.username,
            password=config.password,
            api_token=config.api_token,
            verify_ssl=config.verify_tls,
            timeout=timeout,
        )
        inst = cls(sw_config)
        inst.name = config.id
        return inst

    def _auth_headers(self) -> dict[str, str]:
        if self.config.api_token:
            return {"Authorization": f"Bearer {self.config.api_token}"}
        if self.config.username and self.config.password:
            token = base64.b64encode(
                f"{self.config.username}:{self.config.password}".encode()
            ).decode("ascii")
            return {"Authorization": f"Basic {token}"}
        return {}

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        """Authenticated JSON request. Auth headers are set here; never logged."""
        url = f"{self.config.endpoint_url.rstrip('/')}/{path.lstrip('/')}"
        headers = {
            "Accept": "application/json",
            "User-Agent": _user_agent(),
        }
        headers.update(self._auth_headers())
        extra_headers = kwargs.pop("headers", None)
        if extra_headers:
            headers.update(extra_headers)
        if method.upper() in {"POST", "PUT", "PATCH"}:
            headers.setdefault("Content-Type", "application/json")

        # Path only — never URL (may embed userinfo) or headers (carry credentials).
        log.debug("SolarWinds %s %s", method, path)
        try:
            response = self.session.request(
                method,
                url,
                headers=headers,
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
                **kwargs,
            )
        except requests.exceptions.Timeout as exc:
            raise SourceTimeoutError(
                f"SolarWinds {self.name} {method} {path} timed out"
            ) from exc
        response.raise_for_status()
        if not response.content:
            return {}
        return response.json()

    def fetch_active_alerts(self) -> list[dict[str, Any]]:
        """POST SWQL to Orion SWIS; fall back to SaaS only on HTTP/URL errors."""
        try:
            payload = self._request(
                "POST",
                _ORION_QUERY_PATH,
                json={"query": _ORION_SWQL},
            )
            return _extract_alerts(payload)
        except _FALLBACK_ERRORS as exc:
            log.info(
                "Orion SWIS query failed (%s); falling back to Observability SaaS",
                type(exc).__name__,
            )
            payload = self._request(
                "GET",
                _SAAS_ALERTS_PATH,
                params={"status": "active"},
            )
            return _extract_alerts(payload)

    def pull_logs(self, limit: int = 100) -> list[str]:
        """Normalize active alerts to `{timestamp} {node} SolarWindsAlert[{severity}]: {msg}`."""
        cap = max(0, int(limit))
        alerts = self.fetch_active_alerts()[:cap]
        return [normalize_alert(alert) for alert in alerts]

    def healthcheck(self) -> bool:
        try:
            self.fetch_active_alerts()
            return True
        except SourceError:
            raise
        except requests.exceptions.RequestException as exc:
            raise SourceError(f"SolarWinds {self.name} healthcheck failed: {exc}") from exc

    def fetch(
        self,
        *,
        since_seconds: int = 3600,
        limit: int = 10_000,
        host_filter: str = "",
    ) -> Iterable[LogEvent]:
        del since_seconds  # SolarWinds active-alert APIs have no lookback window
        page = min(int(limit), 10_000)
        for line in self.pull_logs(limit=page):
            event = _line_to_event(line)
            if host_filter and host_filter not in event.hostname:
                continue
            yield event

    def close(self) -> None:
        self.session.close()


def _line_to_event(line: str) -> LogEvent:
    """Parse a normalized SolarWindsAlert line back into a LogEvent."""
    marker = " SolarWindsAlert["
    idx = line.find(marker)
    if idx == -1:
        return LogEvent(
            timestamp="",
            hostname="",
            appname="solarwinds",
            severity_raw="info",
            message=line,
        )
    prefix = line[:idx]
    parts = prefix.split(" ", 1)
    timestamp = parts[0] if parts else ""
    hostname = parts[1] if len(parts) == 2 else ""
    rest = line[idx + len(marker):]
    sev, _, msg = rest.partition("]: ")
    return LogEvent(
        timestamp=timestamp,
        hostname=hostname,
        appname="solarwinds",
        severity_raw=sev or "info",
        message=msg or line,
    )


# Alias used by docs / registry callers that expect a *Source class name.
SolarWindsSource = SolarWindsConnector

registry.register("solarwinds", SolarWindsConnector.from_config)
