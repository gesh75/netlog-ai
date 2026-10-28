"""SolarWinds Orion SWIS + Observability SaaS source connector.

SWIS v3 mode POSTs parameterized SWQL to
``/SolarWinds/InformationService/v3/Json/Query`` (typically port 17778).
SaaS mode uses Bearer auth against ``GET /v1/logs`` and ``GET /v1/alerts``
with cursor or page pagination.

Authentication (first match wins):
  - api_token  → Authorization: Bearer <token>
  - username + password → Authorization: Basic <base64>

Writeback (``append_alert_note`` / ``acknowledge_alert``) runs only when
called explicitly. Credentials are never written to logs. User-Agent uses
the installed package version.
"""
from __future__ import annotations

import base64
import logging
import os
import re
import urllib.error
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, NoReturn

import requests

from ai_log_analyzer import __version__
from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.sources.base import (
    SourceConfig,
    SourceError,
    SourceTimeoutError,
    guarded_session,
    registry,
    source_allow_private,
    upstream_error,
)
from ai_log_analyzer.sources.telemetry import InterfaceTelemetrySnapshot
from ai_log_analyzer.url_redact import redact_text

log = logging.getLogger(__name__)

SolarWindsMode = Literal["swis", "saas"]

_ORION_QUERY_PATH = "/SolarWinds/InformationService/v3/Json/Query"
_ORION_INVOKE_PATH = "/SolarWinds/InformationService/v3/Json/Invoke"
_SAAS_ALERTS_PATH = "v1/alerts"
_SAAS_LOGS_PATH = "v1/logs"
_SWQL_TOP = 10_000

_ALERT_SWQL = (
    "SELECT TOP 10000 aa.AlertActiveID, aa.AlertObjectID, aa.TriggeredDateTime, "
    "aa.TriggeredMessage, ac.Severity, ac.Name, ao.EntityCaption, ao.RelatedNodeCaption "
    "FROM Orion.AlertActive aa "
    "INNER JOIN Orion.AlertObjects ao ON aa.AlertObjectID = ao.AlertObjectID "
    "INNER JOIN Orion.AlertConfigurations ac ON ao.AlertID = ac.AlertID "
    "WHERE aa.TriggeredDateTime >= @since"
)
_ALERT_SWQL_HOST = (
    _ALERT_SWQL + " AND (ao.EntityCaption CONTAINS @host OR ao.RelatedNodeCaption CONTAINS @host)"
)

_OLM_SWQL = (
    "SELECT TOP 10000 le.DateTime, n.Caption, n.IPAddress, le.Message, le.LogLevel "
    "FROM Orion.OLM.LogEntry le "
    "INNER JOIN Orion.Nodes n ON n.NodeID = le.NodeID "
    "WHERE le.DateTime >= @since"
)
_OLM_SWQL_HOST = (
    _OLM_SWQL + " AND (n.Caption CONTAINS @host OR n.IPAddress CONTAINS @host)"
)

_SYSLOG_SWQL = (
    "SELECT TOP 10000 s.DateTime, n.Caption, n.IPAddress, s.Message, s.SysLogSeverity "
    "FROM Orion.SysLog s "
    "INNER JOIN Orion.Nodes n ON n.NodeID = s.NodeID "
    "WHERE s.DateTime >= @since"
)
_SYSLOG_SWQL_HOST = (
    _SYSLOG_SWQL + " AND (n.Caption CONTAINS @host OR n.IPAddress CONTAINS @host)"
)

_EVENTS_SWQL = (
    "SELECT TOP 10000 e.EventTime, n.Caption, e.Message, e.EventType "
    "FROM Orion.Events e "
    "INNER JOIN Orion.Nodes n ON n.NodeID = e.NetworkNode "
    "WHERE e.EventTime >= @since"
)
_EVENTS_SWQL_HOST = (
    _EVENTS_SWQL + " AND n.Caption CONTAINS @host"
)

# TOP without ORDER BY returns arbitrary rows: always keep the newest.
_ALERT_ORDER = " ORDER BY aa.TriggeredDateTime DESC"
_OLM_ORDER = " ORDER BY le.DateTime DESC"
_SYSLOG_ORDER = " ORDER BY s.DateTime DESC"
_EVENTS_ORDER = " ORDER BY e.EventTime DESC"

_NODES_SWQL = (
    "SELECT NodeID, Caption, IPAddress, Status, Vendor, MachineType, Location FROM Orion.Nodes"
)
_NODES_SWQL_SITE = (
    _NODES_SWQL + " WHERE Location = @site OR Caption CONTAINS @site"
)
_TOPO_SWQL = (
    "SELECT NodeID, DestNodeID, InterfaceID, DestInterfaceID FROM Orion.TopologyConnections"
)
_IFACE_SWQL = (
    "SELECT i.InErrorsToday, i.OutErrorsToday, i.InDiscardsToday, i.OutDiscardsToday, "
    "i.Status, i.Caption, n.Caption AS NodeCaption "
    "FROM Orion.NPM.Interfaces i "
    "INNER JOIN Orion.Nodes n ON n.NodeID = i.NodeID "
    "WHERE n.Caption = @device AND i.Caption = @interface"
)

class _SolarWindsHTTPError(SourceError):
    """A non-timeout HTTP/transport failure (so OLM -> SysLog fallback can tell it
    apart from a timeout, while every caller still only has to catch SourceError)."""


_HTTP_ERRORS = (
    _SolarWindsHTTPError,
    requests.exceptions.HTTPError,
    requests.exceptions.ConnectionError,
    requests.exceptions.InvalidURL,
    requests.exceptions.InvalidSchema,
    requests.exceptions.MissingSchema,
    urllib.error.HTTPError,
    urllib.error.URLError,
)

_LINE_RE = re.compile(
    r"^(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<program>[^\s\[]+)\[(?P<sev>[^\]]*)\]:\s*(?P<msg>.*)$"
)

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def _user_agent() -> str:
    return f"netlog-ai/{__version__}"


def _env_bool(name: str, default: bool = True) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    if raw in _TRUE:
        return True
    if raw in _FALSE:
        return False
    return default


def _normalize_mode(raw: str) -> SolarWindsMode:
    mode = (raw or "swis").strip().lower()
    if mode == "saas":
        return "saas"
    if mode in {"", "swis", "orion"}:
        return "swis"
    raise SourceError(f"invalid SOLARWINDS_MODE {raw!r}; expected 'swis' or 'saas'")


def _since_iso(since_seconds: int) -> str:
    delta = max(0, int(since_seconds))
    return (datetime.now(timezone.utc) - timedelta(seconds=delta)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _first_str(row: dict[str, Any], *keys: str, default: str = "") -> str:
    for key in keys:
        value = row.get(key)
        if value is not None and str(value).strip() != "":
            return str(value)
    return default


def _as_int(value: Any) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def _extract_rows(payload: Any, *keys: str) -> list[dict[str, Any]]:
    names = keys or ("results", "Results", "alerts", "logs", "data", "items")
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if not isinstance(payload, dict):
        return []
    for key in names:
        items = payload.get(key)
        if isinstance(items, list):
            return [row for row in items if isinstance(row, dict)]
    return []


def format_log_line(
    timestamp: str, hostname: str, program: str, severity: str, message: str,
) -> str:
    """Normalize to ``<timestamp> <hostname> <program>[<severity>]: <message>``."""
    return (
        f"{timestamp or '-'} {hostname or 'unknown'} "
        f"{program or 'solarwinds'}[{severity or 'info'}]: {message or ''}"
    )


def normalize_alert(alert: dict[str, Any]) -> str:
    """Render one Orion or SaaS alert as a syslog-shaped line."""
    timestamp = _first_str(
        alert, "TriggeredDateTime", "TriggerTime", "triggeredAt", "createdAt", "timestamp", "time",
    )
    node = _first_str(
        alert,
        "RelatedNodeCaption",
        "EntityCaption",
        "EntityNetObjectId",
        "entityName",
        "hostname",
        "node",
        default="unknown",
    )
    entity = alert.get("entity")
    if isinstance(entity, dict):
        node = _first_str(entity, "name", "id", "entityId", default=node)
    elif isinstance(entity, str) and entity.strip():
        node = entity
    severity = _first_str(alert, "Severity", "severity", default="info")
    msg = _first_str(
        alert, "TriggeredMessage", "AlertMessage", "Name", "message", "name", "description", "title",
    )
    return format_log_line(timestamp, node, "SolarWindsAlert", severity, msg)


def normalize_syslog(row: dict[str, Any]) -> str:
    timestamp = _first_str(row, "DateTime", "ObservationTime", "timestamp", "time")
    host = _first_str(row, "Caption", "Hostname", "hostname", default="unknown")
    severity = _first_str(row, "LogLevel", "SysLogSeverity", "severity", "level", default="info")
    msg = _first_str(row, "Message", "message")
    return format_log_line(timestamp, host, "SolarWindsSyslog", severity, msg)


def normalize_event(row: dict[str, Any]) -> str:
    timestamp = _first_str(row, "EventTime", "DateTime", "timestamp", "time")
    host = _first_str(row, "Caption", "hostname", default="unknown")
    severity = _first_str(row, "EventType", "severity", default="info")
    msg = _first_str(row, "Message", "message")
    return format_log_line(timestamp, host, "SolarWindsEvent", severity, msg)


def normalize_saas_log(row: dict[str, Any]) -> str:
    timestamp = _first_str(row, "timestamp", "time", "observedAt", "createdAt")
    host = _first_str(row, "hostname", "host", "entityName", default="unknown")
    program = _first_str(row, "service", "program", "source", "facility", default="SolarWindsLog")
    severity = _first_str(row, "severity", "level", default="info")
    msg = _first_str(row, "message", "body", "text")
    return format_log_line(timestamp, host, program, severity, msg)


def _fair_cap(streams: list[list[str]], cap: int) -> list[str]:
    """Take up to ``cap`` lines, sharing the budget across streams so a noisy
    stream (alerts) cannot crowd every other one (syslog) out. Stream order is
    kept; a stream that is short frees its share for the others."""
    counts = [0] * len(streams)
    remaining = cap
    active = [i for i, lines in enumerate(streams) if lines]
    while remaining > 0 and active:
        share = max(1, remaining // len(active))
        pending = []
        for i in active:
            take = min(share, len(streams[i]) - counts[i], remaining)
            counts[i] += take
            remaining -= take
            if counts[i] < len(streams[i]):
                pending.append(i)
        active = pending
    return [line for lines, n in zip(streams, counts) for line in lines[:n]]


def _unreachable_mode(mode: SolarWindsMode) -> NoReturn:
    raise SourceError(f"unsupported SolarWinds mode: {mode}")


def _next_cursor(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    for key in ("nextCursor", "cursor", "next_page_cursor", "pageToken"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value
    page_info = payload.get("pageInfo") or payload.get("page_info") or {}
    if isinstance(page_info, dict):
        for key in ("endCursor", "nextCursor", "cursor"):
            value = page_info.get(key)
            if isinstance(value, str) and value.strip() and page_info.get("hasNextPage", True):
                return value
    links = payload.get("links")
    if isinstance(links, dict):
        nxt = links.get("next")
        if isinstance(nxt, str) and nxt.strip():
            return nxt
    return ""


@dataclass
class SolarWindsInterfaceTelemetry(InterfaceTelemetrySnapshot):
    """Orion NPM interface snapshot.

    Maps In/OutErrorsToday onto ``fcs_crc_errors_delta`` and In/OutDiscardsToday
    onto the discard fields. Orion ``Status`` (1 = Up) has no home on the base
    snapshot type, so it is carried here.
    """

    status: str = ""


@dataclass(frozen=True)
class SolarWindsConfig:
    """Native SolarWinds connector settings (Orion SWIS or Observability SaaS)."""

    endpoint_url: str
    username: str = ""
    password: str = ""
    api_token: str = ""
    verify_ssl: bool = True
    timeout: int = 15
    mode: SolarWindsMode = "swis"

    @classmethod
    def from_env(cls) -> SolarWindsConfig:
        url = os.environ.get("SOLARWINDS_URL", "").strip()
        if not url:
            raise SourceError("SOLARWINDS_URL is not set")
        return cls(
            endpoint_url=url,
            username=os.environ.get("SOLARWINDS_USERNAME", "").strip(),
            password=os.environ.get("SOLARWINDS_PASSWORD", ""),
            api_token=os.environ.get("SOLARWINDS_TOKEN", "").strip(),
            verify_ssl=_env_bool("SOLARWINDS_VERIFY_SSL", default=True),
            mode=_normalize_mode(os.environ.get("SOLARWINDS_MODE", "swis")),
        )


class SolarWindsConnector:
    """SolarWinds Orion (SWIS) or Observability SaaS LogSource.

    Implements the repo `LogSource` protocol (`healthcheck` / `fetch` / `close`)
    plus SolarWinds-specific pull, topology, telemetry, and explicit writeback.
    """

    kind = "solarwinds"

    def __init__(self, config: SolarWindsConfig, *, allow_private: bool = False) -> None:
        self.config = config
        self.name = "solarwinds"
        self.session = guarded_session(verify=config.verify_ssl, allow_private=allow_private)
        self.session.headers["Accept"] = "application/json"
        self.session.headers["User-Agent"] = _user_agent()

    @classmethod
    def from_config(cls, config: SourceConfig) -> SolarWindsConnector:
        timeout = int(config.timeout_seconds) if config.timeout_seconds else 15
        mode = _normalize_mode(config.extra.get("mode") or "swis")
        sw_config = SolarWindsConfig(
            endpoint_url=config.url,
            username=config.username,
            password=config.password,
            api_token=config.api_token,
            verify_ssl=config.verify_tls,
            timeout=timeout,
            mode=mode,
        )
        inst = cls(sw_config, allow_private=source_allow_private(config))
        inst.name = config.id
        return inst

    @classmethod
    def from_env(cls) -> SolarWindsConnector:
        # SOLARWINDS_URL is operator-configured: a private Orion server is expected.
        return cls(SolarWindsConfig.from_env(), allow_private=True)

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
        except requests.exceptions.Timeout:
            raise SourceTimeoutError(
                f"SolarWinds {self.name} {method} {path} timed out"
            ) from None
        except requests.exceptions.RequestException as exc:
            # the exception text carries the request URL (userinfo, query): redact, and do not chain it
            raise _SolarWindsHTTPError(
                f"SolarWinds {self.name} {method} {path} failed: {redact_text(str(exc))}") from None
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError:
            raise _SolarWindsHTTPError(
                f"SolarWinds {self.name} {method} {path} HTTP {response.status_code}") from None
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError as exc:
            raise SourceError(f"SolarWinds {self.name} {method} {path} returned non-JSON") from exc

    def _swql(self, query: str, parameters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """POST parameterized SWQL. Never interpolates values into the query string."""
        payload = {"query": query, "parameters": dict(parameters or {})}
        return _extract_rows(self._request("POST", _ORION_QUERY_PATH, json=payload))

    def _bind(self, since_seconds: int, host_filter: str) -> dict[str, Any]:
        params: dict[str, Any] = {"since": _since_iso(since_seconds)}
        if host_filter:
            params["host"] = host_filter
        return params

    def _swis_alerts(self, *, since_seconds: int, host_filter: str) -> list[dict[str, Any]]:
        query = (_ALERT_SWQL_HOST if host_filter else _ALERT_SWQL) + _ALERT_ORDER
        return self._swql(query, self._bind(since_seconds, host_filter))

    def _swis_syslog(self, *, since_seconds: int, host_filter: str) -> list[dict[str, Any]]:
        params = self._bind(since_seconds, host_filter)
        olm = (_OLM_SWQL_HOST if host_filter else _OLM_SWQL) + _OLM_ORDER
        try:
            return self._swql(olm, params)
        except _HTTP_ERRORS as exc:
            log.info(
                "Orion.OLM.LogEntry unavailable (%s); falling back to Orion.SysLog",
                type(exc).__name__,
            )
            syslog = (_SYSLOG_SWQL_HOST if host_filter else _SYSLOG_SWQL) + _SYSLOG_ORDER
            return self._swql(syslog, params)

    def _swis_events(self, *, since_seconds: int, host_filter: str) -> list[dict[str, Any]]:
        query = (_EVENTS_SWQL_HOST if host_filter else _EVENTS_SWQL) + _EVENTS_ORDER
        return self._swql(query, self._bind(since_seconds, host_filter))

    def _saas_paginate(
        self, path: str, params: dict[str, Any], *, limit: int, keys: tuple[str, ...],
    ) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        cursor = ""
        page = 1
        page_size = min(max(int(limit), 1), 1000)
        while len(rows) < limit and page <= 100:
            query = dict(params)
            query.setdefault("pageSize", page_size)
            if cursor:
                query["cursor"] = cursor
            else:
                query["page"] = page
            payload = self._request("GET", path, params=query)
            batch = _extract_rows(payload, *keys)
            if not batch:
                break
            rows.extend(batch)
            cursor = _next_cursor(payload)
            if cursor:
                page += 1
                continue
            page_info = payload.get("pageInfo") if isinstance(payload, dict) else None
            if isinstance(page_info, dict) and page_info.get("hasNextPage"):
                page += 1
                continue
            if len(batch) < page_size:
                break
            page += 1
        return rows[:limit]

    def fetch_active_alerts(
        self, *, since_seconds: int = 3600, host_filter: str = "",
    ) -> list[dict[str, Any]]:
        """Active alerts via SWIS join query or SaaS ``GET /v1/alerts``."""
        mode = self.config.mode
        if mode == "swis":
            return self._swis_alerts(since_seconds=since_seconds, host_filter=host_filter)
        if mode == "saas":
            params: dict[str, Any] = {"status": "active"}
            if host_filter:
                params["hostname"] = host_filter
            return self._saas_paginate(
                _SAAS_ALERTS_PATH, params, limit=_SWQL_TOP, keys=("alerts", "results", "data", "items"),
            )
        _unreachable_mode(mode)

    def pull_logs(
        self,
        limit: int = 100,
        *,
        since_seconds: int = 3600,
        host_filter: str = "",
        include_alerts: bool = True,
        include_syslog: bool = True,
        include_events: bool = True,
    ) -> list[str]:
        """Normalize alerts, syslog/logs, and events to syslog-shaped lines."""
        cap = max(0, int(limit))
        mode = self.config.mode
        streams: list[list[str]] = []
        if mode == "swis":
            if include_alerts:
                streams.append([normalize_alert(row) for row in self.fetch_active_alerts(
                    since_seconds=since_seconds, host_filter=host_filter,
                )])
            if include_syslog:
                streams.append([normalize_syslog(row) for row in self._swis_syslog(
                    since_seconds=since_seconds, host_filter=host_filter,
                )])
            if include_events:
                streams.append([normalize_event(row) for row in self._swis_events(
                    since_seconds=since_seconds, host_filter=host_filter,
                )])
        elif mode == "saas":
            if include_syslog:
                log_params: dict[str, Any] = {}
                if host_filter:
                    log_params["hostname"] = host_filter
                log_params["startTime"] = _since_iso(since_seconds)
                streams.append([
                    normalize_saas_log(row)
                    for row in self._saas_paginate(
                        _SAAS_LOGS_PATH, log_params, limit=cap or _SWQL_TOP,
                        keys=("logs", "results", "data", "items"),
                    )
                ])
            if include_alerts:
                streams.append([
                    normalize_alert(row)
                    for row in self.fetch_active_alerts(
                        since_seconds=since_seconds, host_filter=host_filter,
                    )
                ])
        else:
            _unreachable_mode(mode)
        if host_filter:
            streams = [[line for line in lines if host_filter in line] for lines in streams]
        return _fair_cap(streams, cap)

    def build_site_manifest(self, site_name: str) -> dict[str, Any]:
        """Devices + TopologyConnections adjacency in the NetBox manifest shape."""
        if self.config.mode != "swis":
            return _empty_manifest(site_name)
        params: dict[str, Any] = {}
        query = _NODES_SWQL
        if site_name:
            query = _NODES_SWQL_SITE
            params["site"] = site_name
        nodes = self._swql(query, params)
        devices: list[dict[str, Any]] = []
        by_id: dict[str, str] = {}
        for raw in nodes:
            caption = _first_str(raw, "Caption", "caption")
            if not caption:
                continue
            node_id = _first_str(raw, "NodeID", "nodeID", "nodeId")
            if node_id:
                by_id[node_id] = caption
            devices.append({
                "hostname": caption,
                "site": _first_str(raw, "Location", "location") or site_name,
                "role": _first_str(raw, "MachineType", "Vendor"),
                "status": _first_str(raw, "Status", "status"),
                "device_type": _first_str(raw, "MachineType", "Vendor"),
                "primary_ip": _first_str(raw, "IPAddress", "ipAddress"),
                "id": raw.get("NodeID"),
            })
        links: list[dict[str, str]] = []
        adjacency: dict[str, list[str]] = {}
        skipped = 0
        for raw in self._swql(_TOPO_SWQL, {}):
            left_id = _first_str(raw, "NodeID", "SourceNodeID", "SrcNodeID")
            right_id = _first_str(raw, "DestNodeID", "DestinationNodeID", "ConnectedTo")
            left = by_id.get(left_id, "")
            right = by_id.get(right_id, "")
            if not left or not right or left == right:
                skipped += 1
                continue
            links.append({
                "a": left, "b": right,
                "a_iface": _first_str(raw, "InterfaceID", "SrcInterface"),
                "b_iface": _first_str(raw, "DestInterfaceID", "DestInterface"),
            })
            adjacency.setdefault(left, [])
            adjacency.setdefault(right, [])
            if right not in adjacency[left]:
                adjacency[left].append(right)
            if left not in adjacency[right]:
                adjacency[right].append(left)
        return {
            "site": site_name or _first_device_site(devices),
            "source": "solarwinds",
            "configured": True,
            "devices": devices,
            "links": links,
            "adjacency": adjacency,
            "skipped_terminations": skipped,
        }

    def fetch_interface_telemetry(
        self, device: str, interface: str,
    ) -> SolarWindsInterfaceTelemetry:
        """Map Orion.NPM.Interfaces counters onto InterfaceTelemetrySnapshot."""
        rows = self._swql(_IFACE_SWQL, {"device": device, "interface": interface})
        row = rows[0] if rows else {}
        in_err = _as_int(row.get("InErrorsToday"))
        out_err = _as_int(row.get("OutErrorsToday"))
        return SolarWindsInterfaceTelemetry(
            device=device,
            interface=interface,
            fcs_crc_errors_delta=in_err + out_err,
            in_discards_delta=_as_int(row.get("InDiscardsToday")),
            out_discards_delta=_as_int(row.get("OutDiscardsToday")),
            status=_first_str(row, "Status", "status"),
        )

    def append_alert_note(self, alert_object_id: int, note: str) -> Any:
        """Invoke Orion.AlertActive/AppendNote. Explicit only — never automatic."""
        if self.config.mode != "swis":
            raise SourceError("SolarWinds writeback requires SWIS mode")
        path = f"{_ORION_INVOKE_PATH}/Orion.AlertActive/AppendNote"
        return self._request("POST", path, json=[int(alert_object_id), str(note)])

    def acknowledge_alert(self, ids: Iterable[int], note: str) -> Any:
        """Invoke Orion.AlertActive/Acknowledge. Explicit only — never automatic."""
        if self.config.mode != "swis":
            raise SourceError("SolarWinds writeback requires SWIS mode")
        path = f"{_ORION_INVOKE_PATH}/Orion.AlertActive/Acknowledge"
        object_ids = [int(i) for i in ids]
        return self._request("POST", path, json=[object_ids, str(note)])

    def healthcheck(self) -> bool:
        try:
            if self.config.mode == "saas":
                self._request("GET", _SAAS_ALERTS_PATH, params={"status": "active", "pageSize": 1})
            else:
                self._swql("SELECT TOP 1 NodeID FROM Orion.Nodes", {})
            return True
        except SourceError:
            raise
        except requests.exceptions.RequestException as exc:
            raise upstream_error(f"SolarWinds {self.name} healthcheck failed", exc) from None

    def fetch(
        self,
        *,
        since_seconds: int = 3600,
        limit: int = 10_000,
        host_filter: str = "",
    ) -> Iterable[LogEvent]:
        page = min(int(limit), 10_000)
        for line in self.pull_logs(limit=page, since_seconds=since_seconds, host_filter=host_filter):
            yield _line_to_event(line)

    def close(self) -> None:
        self.session.close()


def _line_to_event(line: str) -> LogEvent:
    """Parse a normalized SolarWinds line back into a LogEvent."""
    match = _LINE_RE.match(line)
    if not match:
        return LogEvent(
            timestamp="",
            hostname="",
            appname="solarwinds",
            severity_raw="info",
            message=line,
        )
    return LogEvent(
        timestamp=match.group("ts") if match.group("ts") != "-" else "",
        hostname=match.group("host"),
        appname=match.group("program"),
        severity_raw=match.group("sev") or "info",
        message=match.group("msg") or line,
    )


def _empty_manifest(site: str) -> dict[str, Any]:
    return {
        "site": site or "",
        "source": "solarwinds",
        "configured": False,
        "devices": [],
        "links": [],
        "adjacency": {},
        "skipped_terminations": 0,
    }


def _first_device_site(devices: list[dict[str, Any]]) -> str:
    for device in devices:
        site = device.get("site")
        if site:
            return str(site)
    return ""


def build_site_manifest(
    site_name: str, connector: SolarWindsConnector | None = None,
) -> dict[str, Any]:
    """Build a site manifest from Orion.Nodes + Orion.TopologyConnections."""
    conn = connector or SolarWindsConnector.from_env()
    try:
        return conn.build_site_manifest(site_name)
    finally:
        if connector is None:
            conn.close()


def fetch_interface_telemetry(
    device: str, interface: str, connector: SolarWindsConnector | None = None,
) -> SolarWindsInterfaceTelemetry:
    """Fetch Orion NPM interface counters mapped to InterfaceTelemetrySnapshot."""
    conn = connector or SolarWindsConnector.from_env()
    try:
        return conn.fetch_interface_telemetry(device, interface)
    finally:
        if connector is None:
            conn.close()


SolarWindsSource = SolarWindsConnector

registry.register("solarwinds", SolarWindsConnector.from_config, outbound=True)
