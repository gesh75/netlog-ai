"""ServiceNow change correlation and idempotent incident sync.

Scoring is deterministic. Live HTTP uses the stdlib client and
``validate_outbound_url``. ``dry_run=True`` never opens a socket.
"""
from __future__ import annotations

import base64
import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ai_log_analyzer.analytics import (
    BlastRadiusReport,
    Finding,
    FlapAnalysisReport,
    _iter_findings,
)
from ai_log_analyzer.itsm import build_servicenow_payload
from ai_log_analyzer.sanitize import sanitize
from ai_log_analyzer.sources import outbound as _outbound
from ai_log_analyzer.sources.base import (
    SourceAuthError,
    SourceError,
    validate_outbound_url,
)

_KEYWORDS = (
    "bgp", "ospf", "evpn", "mtu", "vlan", "vxlan", "firewall",
    "prefix-list", "route-map", "upgrade", "optic", "interface", "bfd",
)
_HIGH_RISK = {"high", "critical", "1", "2"}


@dataclass
class ServiceNowChangeRecord:
    number: str
    short_description: str
    cmdb_ci: str
    state: str = "Implement"
    start_date: str = ""
    end_date: str = ""
    risk: str = "Moderate"
    assigned_to: str = ""
    close_notes: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "number": self.number,
            "short_description": self.short_description,
            "cmdb_ci": self.cmdb_ci,
            "state": self.state,
            "start_date": self.start_date,
            "end_date": self.end_date,
            "risk": self.risk,
            "assigned_to": self.assigned_to,
            "close_notes": self.close_notes,
        }


@dataclass
class ChangeCorrelationHit:
    change_number: str
    device: str
    confidence: float
    time_delta_minutes: float | None
    matched_signals: list[str]
    summary: str
    rollback_recommended: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "change_number": self.change_number,
            "device": self.device,
            "confidence": self.confidence,
            "time_delta_minutes": self.time_delta_minutes,
            "matched_signals": list(self.matched_signals),
            "summary": self.summary,
            "rollback_recommended": self.rollback_recommended,
        }


@dataclass
class ChangeCorrelationReport:
    hits: list[ChangeCorrelationHit] = field(default_factory=list)
    top_suspect_change: str | None = None
    overall_change_induced_probability: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "hits": [hit.to_dict() for hit in self.hits],
            "top_suspect_change": self.top_suspect_change,
            "overall_change_induced_probability": self.overall_change_induced_probability,
        }


@dataclass
class ServiceNowSyncResult:
    dry_run: bool
    action: str
    incident_number: str | None
    sys_id: str | None
    correlation_id: str
    payload: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "dry_run": self.dry_run,
            "action": self.action,
            "incident_number": self.incident_number,
            "sys_id": self.sys_id,
            "correlation_id": self.correlation_id,
            "payload": dict(self.payload),
        }


def correlate_changes_with_findings(
    changes: list[ServiceNowChangeRecord | Mapping[str, Any]],
    findings: list[Any],
    incident_timestamp: str | None = None,
    lookback_minutes: int = 180,
) -> ChangeCorrelationReport:
    """Score each change against findings. Confidence is capped at 1.0."""
    rows = list(_iter_findings(findings))
    incident = _parse_when(incident_timestamp or "")
    hits = [
        _score_change(as_change(item), rows, incident, lookback_minutes)
        for item in changes
    ]
    hits.sort(key=lambda hit: (-hit.confidence, hit.change_number))
    top = hits[0] if hits and hits[0].confidence > 0 else None
    return ChangeCorrelationReport(
        hits=hits,
        top_suspect_change=None if top is None else top.change_number,
        overall_change_induced_probability=0.0 if top is None else top.confidence,
    )


class ServiceNowClient:
    """Read change requests and create or update one incident per correlation id."""

    def __init__(
        self,
        instance_url: str,
        username: str = "",
        password: str = "",
        bearer_token: str = "",
        allow_private: bool = False,
        timeout: int = 15,
    ) -> None:
        self.instance_url = (instance_url or "").rstrip("/")
        self.username = username
        self.password = password
        self.bearer_token = bearer_token
        self.timeout = timeout
        # The operator's own SERVICENOW_URL is a trusted (possibly on-prem) target.
        self.allow_private = allow_private or any(
            _outbound.endpoints_match(self.instance_url, u) for u in _env_urls())
        if self.instance_url:
            validate_outbound_url(self.instance_url, allow_private=self.allow_private,
                                  require_https=True, resolve=False)

    def _check_credential_binding(self) -> None:
        """Server-environment credentials only go to the environment's own URL."""
        _outbound.require_env_bound_target(
            "ServiceNow", self.instance_url,
            supplied={"username": self.username, "password": self.password,
                      "bearer_token": self.bearer_token},
            env_creds={"username": _outbound.env_values("SERVICENOW_USER", "SNOW_USER"),
                       "password": _outbound.env_values("SERVICENOW_PASSWORD", "SNOW_PASSWORD"),
                       "bearer_token": _outbound.env_values("SERVICENOW_TOKEN")},
            env_urls=_env_urls(),
        )

    def fetch_recent_changes(
        self,
        ci_names: list[str] | None = None,
        limit: int = 50,
    ) -> list[ServiceNowChangeRecord]:
        params: dict[str, str] = {
            "sysparm_limit": str(max(1, int(limit))),
            "sysparm_display_value": "true",
        }
        # cmdb_ci is a reference field: match it by CI name (dot-walk), escape the
        # query operator (``^`` -> ``^^``), and order newest first so the limit
        # keeps the most recent changes instead of arbitrary rows.
        names = [n.strip() for n in ci_names or [] if _safe_ci_name(n)]
        clauses = ["cmdb_ci.nameIN" + ",".join(n.replace("^", "^^") for n in names)] if names else []
        params["sysparm_query"] = "^".join([*clauses, "ORDERBYDESCsys_updated_on"])
        payload = self._request("GET", "/api/now/table/change_request", params=params)
        rows = payload.get("result")
        if not isinstance(rows, list):
            raise SourceError("ServiceNow change_request response is missing result")
        return [as_change(row) for row in rows if isinstance(row, dict)]

    def sync_incident(
        self,
        report: Any,
        blast_radius: BlastRadiusReport | None = None,
        change_report: ChangeCorrelationReport | None = None,
        flap_report: FlapAnalysisReport | None = None,
        dry_run: bool = True,
    ) -> ServiceNowSyncResult:
        title, detail, devices = _summarize_report(report)
        correlation_id = _correlation_id(title, devices, blast_radius, change_report, flap_report)
        notes = _work_notes(title, detail, blast_radius, change_report, flap_report)
        safe_notes, _redactions = sanitize(notes, mask_pii=False)
        ci = devices[0] if devices else ""
        if change_report and change_report.hits:
            ci = change_report.hits[0].device or ci
        payload = build_servicenow_payload(
            short_description=title or "netlog-ai network anomaly",
            work_notes=safe_notes,
            cmdb_ci=ci,
            correlation_id=correlation_id,
            urgency="1" if blast_radius and blast_radius.critical_spofs else "2",
            impact="1" if blast_radius and blast_radius.blast_radius_score >= 50 else "2",
        )
        if dry_run:
            return ServiceNowSyncResult(
                dry_run=True,
                action="preview",
                incident_number=None,
                sys_id=None,
                correlation_id=correlation_id,
                payload=payload,
            )
        return self._upsert(correlation_id, payload)

    def _upsert(self, correlation_id: str, payload: dict[str, Any]) -> ServiceNowSyncResult:
        if not self.instance_url:
            raise SourceError("instance_url is required for a live ServiceNow sync")
        found = self._request(
            "GET",
            "/api/now/table/incident",
            params={
                "sysparm_query": f"correlation_id={correlation_id}^active=true",
                "sysparm_limit": "1",
            },
        )
        rows = found.get("result") if isinstance(found.get("result"), list) else []
        if rows and isinstance(rows[0], dict) and rows[0].get("sys_id"):
            sys_id = str(rows[0]["sys_id"])
            updated = self._request(
                "PATCH",
                f"/api/now/table/incident/{sys_id}",
                body={"work_notes": payload.get("work_notes", "")},
            )
            result = updated.get("result") if isinstance(updated.get("result"), dict) else {}
            number = str(result.get("number") or rows[0].get("number") or "")
            return ServiceNowSyncResult(
                dry_run=False,
                action="updated",
                incident_number=number or None,
                sys_id=str(result.get("sys_id") or sys_id),
                correlation_id=correlation_id,
                payload=payload,
            )
        created = self._request("POST", "/api/now/table/incident", body=payload)
        result = created.get("result") if isinstance(created.get("result"), dict) else {}
        return ServiceNowSyncResult(
            dry_run=False,
            action="created",
            incident_number=str(result.get("number") or "") or None,
            sys_id=str(result.get("sys_id") or "") or None,
            correlation_id=correlation_id,
            payload=payload,
        )

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not self.instance_url:
            raise SourceError("instance_url is required")
        url = self.instance_url + path
        if params:
            url = url + "?" + urllib.parse.urlencode(params)
        self._check_credential_binding()
        data = None if body is None else json.dumps(body).encode("utf-8")
        headers = {
            "Accept": "application/json",
            "Authorization": _auth_header(self.username, self.password, self.bearer_token),
            "User-Agent": _user_agent(),
        }
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with _outbound.safe_urlopen(req, timeout=self.timeout, allow_private=self.allow_private) as resp:
                raw = resp.read().decode("utf-8")
        except TimeoutError as exc:
            raise SourceError("ServiceNow request timed out") from exc
        except urllib.error.HTTPError as exc:
            raise SourceError(f"ServiceNow HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise SourceError(f"ServiceNow request failed: {exc.reason}") from exc
        try:
            payload = json.loads(raw) if raw else {}
        except json.JSONDecodeError as exc:
            raise SourceError("ServiceNow returned non-JSON") from exc
        if not isinstance(payload, dict):
            raise SourceError("ServiceNow payload must be a JSON object")
        return payload


def _user_agent() -> str:
    # lazy import: avoids a cycle at package load
    from ai_log_analyzer import __version__
    return f"netlog-ai/{__version__}"


def _env_urls() -> tuple[str, ...]:
    return _outbound.env_values("SERVICENOW_URL", "SNOW_URL")


def _safe_ci_name(name: object) -> bool:
    text = str(name or "")
    return bool(text.strip()) and "," not in text and text.isprintable()


def as_change(item: ServiceNowChangeRecord | Mapping[str, Any]) -> ServiceNowChangeRecord:
    if isinstance(item, ServiceNowChangeRecord):
        return item
    return ServiceNowChangeRecord(
        number=str(item.get("number") or ""),
        short_description=str(item.get("short_description") or ""),
        cmdb_ci=_display(item.get("cmdb_ci")),
        state=str(item.get("state") or "Implement"),
        start_date=_display(item.get("start_date")),
        end_date=_display(item.get("end_date")),
        risk=str(item.get("risk") or "Moderate"),
        assigned_to=_display(item.get("assigned_to")),
        close_notes=str(item.get("close_notes") or ""),
    )


def _score_change(
    change: ServiceNowChangeRecord,
    findings: list[Finding],
    incident: datetime | None,
    lookback_minutes: int,
) -> ChangeCorrelationHit:
    signals: list[str] = []
    score = 0.0
    device = _matched_device(change.cmdb_ci, findings)
    if device:
        score += 0.45
        signals.append("cmdb_ci")
    delta = _time_delta(change.start_date, incident)
    if delta is not None and 0 <= delta <= lookback_minutes:
        score += 0.30
        signals.append("time_window")
    words = _keyword_overlap(change.short_description, findings)
    if words:
        score += 0.15
        signals.extend(f"keyword:{word}" for word in words)
    if change.risk.strip().lower() in _HIGH_RISK:
        score += 0.10
        signals.append("risk")
    confidence = round(min(1.0, score), 4)
    target = device or change.cmdb_ci or "unknown"
    return ChangeCorrelationHit(
        change_number=change.number,
        device=target,
        confidence=confidence,
        time_delta_minutes=None if delta is None else round(delta, 2),
        matched_signals=signals,
        summary=f"{change.number} on {target} scored {confidence:.2f}",
        rollback_recommended=confidence >= 0.65,
    )


def _matched_device(ci: str, findings: list[Finding]) -> str:
    for finding in findings:
        if _host_match(ci, finding.device):
            return finding.device
    return ""


def _host_match(left: str, right: str) -> bool:
    a, b = left.strip().lower(), right.strip().lower()
    if not a or not b:
        return False
    if a == b:
        return True
    short, long = (a, b) if len(a) <= len(b) else (b, a)
    if not long.startswith(short):
        return False
    return long[len(short)] in ".-"


def _time_delta(start: str, incident: datetime | None) -> float | None:
    if incident is None:
        return None
    opened = _parse_when(start)
    if opened is None:
        return None
    return (incident - opened).total_seconds() / 60.0


def _keyword_overlap(description: str, findings: list[Finding]) -> list[str]:
    low = description.lower()
    blob = " ".join(finding.message.lower() for finding in findings)
    return [word for word in _KEYWORDS if word in low and word in blob]


def _parse_when(value: str) -> datetime | None:
    text = (value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        parsed = _parse_snow_clock(text)
        if parsed is None:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    try:
        return parsed.astimezone(timezone.utc)
    except OverflowError:   # an offset pushes a year-1/9999 stamp outside datetime
        return None


def _parse_snow_clock(text: str) -> datetime | None:
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _summarize_report(report: Any) -> tuple[str, str, list[str]]:
    if report is None:
        return "Network anomaly", "", []
    if isinstance(report, str):
        return report[:160], report, []
    if isinstance(report, Mapping):
        title = str(report.get("summary") or report.get("short_description") or "Network anomaly")
        detail = str(report.get("detail") or report.get("executive_summary") or title)
        devices = [str(device) for device in report.get("devices") or [] if device]
        return title[:160], detail, devices
    summary = getattr(report, "executive_summary", None)
    if isinstance(summary, list):
        detail = " ".join(str(line) for line in summary)
    else:
        detail = str(summary or "")
    devices: list[str] = []
    for item in getattr(report, "action_items", []) or []:
        devices.extend(str(device) for device in getattr(item, "devices", []) or [])
    title = (detail or "Network anomaly")[:160]
    return title, detail, devices


def _correlation_id(
    title: str,
    devices: list[str],
    blast: BlastRadiusReport | None,
    changes: ChangeCorrelationReport | None,
    flap: FlapAnalysisReport | None,
) -> str:
    spofs = ",".join(blast.critical_spofs) if blast else ""
    suspect = (changes.top_suspect_change or "") if changes else ""
    unstable = (flap.most_unstable_entity or "") if flap else ""
    blob = "|".join([title, ",".join(sorted(set(devices))), unstable, spofs, suspect])
    digest = hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]
    return f"netlog-ai-{digest}"


def _work_notes(
    title: str,
    detail: str,
    blast: BlastRadiusReport | None,
    changes: ChangeCorrelationReport | None,
    flap: FlapAnalysisReport | None,
) -> str:
    dampened = flap.dampened_count if flap else 0
    unstable = flap.most_unstable_entity if flap else None
    score = blast.blast_radius_score if blast else 0.0
    spofs = ", ".join(blast.critical_spofs) if blast and blast.critical_spofs else "none"
    suspect = changes.top_suspect_change if changes else None
    confidence = changes.overall_change_induced_probability if changes else 0.0
    rollback = bool(changes and changes.hits and changes.hits[0].rollback_recommended)
    cli = _rollback_cli(flap)
    return "\n".join([
        "## Top Root Cause & Causal Chain",
        title,
        detail or "(no additional chain)",
        "",
        "## Flap Dampening Physics",
        f"dampened_count={dampened}",
        f"most_unstable_entity={unstable or 'none'}",
        "",
        "## Blast Radius Score & SPOF warnings",
        f"blast_radius_score={score}",
        f"critical_spofs={spofs}",
        "",
        "## Correlated Change Request",
        f"top_suspect_change={suspect or 'none'}",
        f"confidence={confidence}",
        f"rollback_recommended={rollback}",
        "",
        "## Safe Rollback / Verification CLI",
        *cli,
    ])


def _rollback_cli(flap: FlapAnalysisReport | None) -> list[str]:
    lines = ["show bgp summary", "show interfaces status"]
    if flap is None:
        return lines
    for vendor, commands in flap.recommended_dampening_cli.items():
        lines.append(f"# {vendor}")
        lines.extend(commands)
    return lines


def _display(value: object) -> str:
    if isinstance(value, dict):
        shown = value.get("display_value") or value.get("value") or ""
        return str(shown)
    if value is None:
        return ""
    return str(value).strip()


def _auth_header(username: str, password: str, bearer_token: str) -> str:
    if bearer_token:
        return f"Bearer {bearer_token}"
    if username:
        token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        return f"Basic {token}"
    raise SourceAuthError("ServiceNow credentials are required")
