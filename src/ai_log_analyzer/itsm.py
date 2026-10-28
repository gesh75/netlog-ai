"""Two-way Jira Service Management and ServiceNow incident correlation & enrichment.

Supports deterministic incident fingerprinting (to prevent duplicate ticket storms),
Atlassian Document Format (ADF) / Markdown comment synthesis, ServiceNow work_notes
enrichment, and offline dry-run execution when credentials are omitted.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ai_log_analyzer.remediation import RemediationPlan
from ai_log_analyzer.sanitize import sanitize
from ai_log_analyzer.sources import outbound as _outbound
from ai_log_analyzer.sources.base import validate_outbound_url

_ATTACHMENT_CHARS = 6000   # Jira descriptions cap near 32 KB; leave room for the RCA card


def _user_agent() -> str:
    # lazy import: avoids a cycle at package load
    from ai_log_analyzer import __version__
    return f"netlog-ai/{__version__}"


def _clean(text: str) -> str:
    """Redact secrets from free text before it is posted to an external ITSM."""
    return sanitize(text or "", mask_pii=False)[0]


# Ticket renderers read markup out of plain text. Jira (REST v2) renders wiki markup, so an
# unescaped `!url!` loads an image, `[a|url]` is a disguised link and `{panel}` / `{color}` /
# `{code}` open blocks; ServiceNow journal fields show text as text except `[code]...[/code]`,
# which is rendered as HTML. Device-derived text is neutralised for the target before it is sent.
_BODY_TARGETS = ("markdown", "jira", "servicenow")
_ZWSP = "\u200b"  # zero-width space: breaks a tag token without changing how the text reads
_JIRA_MARKUP_RE = re.compile(r"([\\*_{}\[\]|!#^~])")
_JIRA_NOFORMAT_RE = re.compile(r"\{(?=\s*noformat)", re.IGNORECASE)
_SNOW_CODE_TAG_RE = re.compile(r"\[(?=\s*/?\s*code\s*\])", re.IGNORECASE)


def _jira_inline(text: str) -> str:
    """One line of device text for Jira wiki markup: whitespace collapsed (no line-start markup),
    markup characters backslash-escaped so the text shows as typed."""
    return _JIRA_MARKUP_RE.sub(r"\\\1", " ".join(text.split()))


def _jira_block(text: str) -> str:
    """Device text as a literal Jira block; a `{noformat}` inside it cannot close the block early."""
    return "{noformat}\n" + _JIRA_NOFORMAT_RE.sub("{" + _ZWSP, text) + "\n{noformat}"


def _jira_label(text: str) -> str:
    """Jira labels cannot contain spaces or most punctuation."""
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", text or "").strip("-") or "unknown"


@dataclass
class IncidentEnrichmentPayload:
    """Normalized RCA + Blast Radius + Remediation package for ITSM platforms."""

    site: str
    root_device: str
    root_layer: str
    root_interface: str | None
    summary_title: str
    rca_rationale: str
    confidence: float
    affected_devices: list[str] = field(default_factory=list)
    affected_vnis: list[int] = field(default_factory=list)
    suppressed_symptom_count: int = 0
    telemetry_summary: str | None = None
    remediation_plan: RemediationPlan | None = None
    # Extra Markdown sections (title → body), e.g. the RCA playbook, cited
    # evidence and an Ansible check-mode playbook from the triage worker.
    attachments: dict[str, str] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        """Deterministic deduplication key for two-way ticket correlation."""
        raw = f"{self.site}|{self.root_device}|{self.root_layer}|{self.root_interface or 'none'}"
        return "NETLOG-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12].upper()

    def to_markdown_body(self, target: str = "markdown", scrub: Callable[[str], str] | None = None) -> str:
        """Format full RCA, blast radius, and remediation card.

        ``target`` is where the text is read: "markdown" (the default; dashboards, webhooks, previews)
        leaves device text as it is; "jira" escapes it as wiki markup and puts multi-line sections
        (attachments, remediation card) in a ``{noformat}`` block; "servicenow" breaks any
        ``[code]`` tag. ``scrub`` (a secret redactor) runs on each device-derived string before it
        is escaped, so the escaping cannot hide a secret from it.
        """
        if target not in _BODY_TARGETS:
            raise ValueError(f"unknown ticket target {target!r}; use one of {', '.join(_BODY_TARGETS)}")
        redact = scrub or (lambda t: t)

        def one(value: Any) -> str:
            text = redact(str(value))
            return _jira_inline(text) if target == "jira" else text

        def block(value: str) -> str:
            text = redact(value)
            return _jira_block(text) if target == "jira" else text

        vni_str = ", ".join(str(v) for v in sorted(self.affected_vnis)) or "None"
        dev_str = ", ".join(one(d) for d in sorted(self.affected_devices)) or one(self.root_device)
        lines = [
            f"## netlog-ai Automated RCA Summary (`{self.fingerprint}`)",
            f"- **Site:** `{one(self.site)}`",
            f"- **Root Cause Device:** `{one(self.root_device)}`"
            + (f" (`{one(self.root_interface)}`)" if self.root_interface else ""),
            f"- **Protocol Layer:** `{one(self.root_layer)}`",
            f"- **Confidence:** `{int(self.confidence * 100)}%`",
            f"- **Rationale:** {one(self.rca_rationale)}",
            "",
            "### Blast Radius & Symptom Suppression",
            f"- **Affected Devices ({len(self.affected_devices) or 1}):** {dev_str}",
            f"- **Affected EVPN VNIs:** {vni_str}",
            f"- **Suppressed Downstream Alarms:** `{self.suppressed_symptom_count}`",
        ]
        if self.telemetry_summary:
            lines.extend(["", "### Optical / Interface Telemetry Verdict",
                          f"> {one(self.telemetry_summary)}"])
        if self.remediation_plan:
            lines.extend(["", block(self.remediation_plan.to_markdown_card())])
        for title, body in self.attachments.items():
            if body:
                lines.extend(["", f"### {one(title)}", block(body[:_ATTACHMENT_CHARS])])
        text = "\n".join(lines)
        return _SNOW_CODE_TAG_RE.sub("[" + _ZWSP, text) if target == "servicenow" else text

    def to_jira_issue_fields(self, project_key: str, issue_type: str = "Incident") -> dict[str, Any]:
        """Construct Jira REST API v2/v3 issue creation fields with fingerprint label."""
        priority = "Highest" if self.confidence >= 0.90 and len(self.affected_devices) > 1 else "High"
        return {
            "project": {"key": project_key},
            "summary": f"[{self.site}] {self.summary_title} on {self.root_device}",
            "description": self.to_markdown_body(target="jira"),
            "issuetype": {"name": issue_type},
            "priority": {"name": priority},
            "labels": ["netlog-ai", _jira_label(f"site-{self.site}"), self.fingerprint],
        }

    def to_servicenow_record(self, caller_id: str = "netlog-ai") -> dict[str, Any]:
        """Construct ServiceNow table/incident payload with correlation_id."""
        urgency = "1" if len(self.affected_devices) > 1 else "2"
        impact = "1" if self.affected_vnis else "2"
        return {
            "caller_id": caller_id,
            "cmdb_ci": self.root_device,
            "correlation_id": self.fingerprint,
            "short_description": f"[{self.site}] {self.summary_title} ({self.root_device})",
            "urgency": urgency,
            "impact": impact,
            "work_notes": self.to_markdown_body(target="servicenow"),
        }


def build_servicenow_payload(
    short_description: str,
    work_notes: str,
    *,
    cmdb_ci: str = "",
    correlation_id: str = "",
    urgency: str = "2",
    impact: str = "2",
    caller_id: str = "netlog-ai",
) -> dict[str, Any]:
    """Base incident body shared by the ServiceNow sync client."""
    return {
        "caller_id": caller_id,
        "cmdb_ci": cmdb_ci,
        "correlation_id": correlation_id,
        "short_description": short_description[:160],
        "urgency": urgency,
        "impact": impact,
        "work_notes": work_notes,
    }


class JiraITSMClient:
    """Two-way Jira Service Management connector supporting search, create, and comment."""

    def __init__(
        self,
        base_url: str,
        email: str,
        api_token: str,
        project_key: str = "NET",
        timeout: int = 15,
        *,
        allow_private: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.project_key = project_key
        self.timeout = timeout
        # Server-environment credentials only ever go to the environment's own URL.
        trusted = _outbound.require_env_bound_target(
            "Jira", self.base_url,
            supplied={"email": email, "api_token": api_token},
            env_creds={"email": _outbound.env_values("JIRA_EMAIL"),
                       "api_token": _outbound.env_values("JIRA_API_TOKEN")},
            env_urls=_outbound.env_values("JIRA_URL", "JIRA_BASE_URL"),
        )
        self.allow_private = allow_private or trusted
        validate_outbound_url(self.base_url, allow_private=self.allow_private,
                              require_https=True, resolve=False)
        creds = f"{email}:{api_token}".encode()
        self._auth_header = "Basic " + base64.b64encode(creds).decode("ascii")

    @classmethod
    def from_env(cls) -> JiraITSMClient:
        url = os.environ.get("JIRA_URL", "")
        email = os.environ.get("JIRA_EMAIL", "")
        token = os.environ.get("JIRA_API_TOKEN", "")
        project = os.environ.get("JIRA_PROJECT_KEY", "NET")
        if not url or not email or not token:
            raise ValueError("JIRA_URL, JIRA_EMAIL, and JIRA_API_TOKEN are required.")
        return cls(base_url=url, email=email, api_token=token, project_key=project)

    def _request(self, method: str, endpoint: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {
            "Authorization": self._auth_header,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": _user_agent(),
        }
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with _outbound.safe_urlopen(req, timeout=self.timeout, allow_private=self.allow_private) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}

    def find_open_issue_by_fingerprint(self, fingerprint: str) -> str | None:
        """Query JQL for an existing unresolved incident matching the fingerprint label."""
        project = self.project_key.replace("\\", "\\\\").replace('"', '\\"')
        jql = (
            f'project = "{project}" AND labels = "{fingerprint}" '
            "AND statusCategory != Done ORDER BY created DESC"
        )
        params = urllib.parse.urlencode({"jql": jql, "maxResults": 1, "fields": "key"})
        res = self._request("GET", f"/rest/api/2/search?{params}")
        issues = res.get("issues") or []
        return issues[0].get("key") if issues else None

    def upsert_incident(self, payload: IncidentEnrichmentPayload) -> dict[str, Any]:
        """Update existing open Jira ticket if fingerprint matches, otherwise create a new issue."""
        existing_key = self.find_open_issue_by_fingerprint(payload.fingerprint)
        if existing_key:
            self._request(
                "POST",
                f"/rest/api/2/issue/{existing_key}/comment",
                {"body": _clean(payload.to_markdown_body(target="jira", scrub=_clean))},
            )
            return {"action": "updated", "issue_key": existing_key, "fingerprint": payload.fingerprint}

        fields = payload.to_jira_issue_fields(self.project_key)
        fields["summary"] = _clean(fields["summary"])[:255]
        fields["description"] = _clean(payload.to_markdown_body(target="jira", scrub=_clean))
        created = self._request("POST", "/rest/api/2/issue", {"fields": fields})
        return {
            "action": "created",
            "issue_key": created.get("key", "UNKNOWN"),
            "fingerprint": payload.fingerprint,
        }

    def enrich_incident(self, payload: IncidentEnrichmentPayload) -> dict[str, Any]:
        """Polymorphic alias for upsert_incident."""
        return self.upsert_incident(payload)


class ServiceNowITSMClient:
    """Two-way ServiceNow Incident Table API connector with correlation_id deduplication."""

    def __init__(self, instance_url: str, username: str, password: str, timeout: int = 15,
                 *, allow_private: bool = False) -> None:
        self.base_url = instance_url.rstrip("/")
        self.timeout = timeout
        trusted = _outbound.require_env_bound_target(
            "ServiceNow", self.base_url,
            supplied={"username": username, "password": password},
            env_creds={"username": _outbound.env_values("SERVICENOW_USER", "SNOW_USER"),
                       "password": _outbound.env_values("SERVICENOW_PASSWORD", "SNOW_PASSWORD")},
            env_urls=_outbound.env_values("SERVICENOW_URL", "SNOW_URL"),
        )
        self.allow_private = allow_private or trusted
        validate_outbound_url(self.base_url, allow_private=self.allow_private,
                              require_https=True, resolve=False)
        creds = f"{username}:{password}".encode()
        self._auth_header = "Basic " + base64.b64encode(creds).decode("ascii")

    def _request(self, method: str, endpoint: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {
            "Authorization": self._auth_header,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": _user_agent(),
        }
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with _outbound.safe_urlopen(req, timeout=self.timeout, allow_private=self.allow_private) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}

    def find_active_incident(self, fingerprint: str) -> dict[str, Any] | None:
        query = f"correlation_id={fingerprint}^active=true"
        params = urllib.parse.urlencode({"sysparm_query": query, "sysparm_limit": 1})
        res = self._request("GET", f"/api/now/table/incident?{params}")
        records = res.get("result") or []
        return records[0] if records else None

    def upsert_incident(self, payload: IncidentEnrichmentPayload) -> dict[str, Any]:
        """Append work_notes to active ServiceNow incident or create a new record."""
        existing = self.find_active_incident(payload.fingerprint)
        if existing and existing.get("sys_id"):
            sys_id = existing["sys_id"]
            self._request(
                "PATCH",
                f"/api/now/table/incident/{sys_id}",
                {"work_notes": _clean(payload.to_markdown_body(target="servicenow", scrub=_clean))},
            )
            return {
                "action": "updated",
                "number": existing.get("number", sys_id),
                "sys_id": sys_id,
                "fingerprint": payload.fingerprint,
            }

        record = payload.to_servicenow_record()
        record["work_notes"] = _clean(payload.to_markdown_body(target="servicenow", scrub=_clean))
        record["short_description"] = _clean(record["short_description"])[:160]
        created = self._request("POST", "/api/now/table/incident", record)
        result_obj = created.get("result") or {}
        return {
            "action": "created",
            "number": result_obj.get("number", "INC_NEW"),
            "sys_id": result_obj.get("sys_id", ""),
            "fingerprint": payload.fingerprint,
        }

    def enrich_incident(self, payload: IncidentEnrichmentPayload) -> dict[str, Any]:
        """Polymorphic alias for upsert_incident."""
        return self.upsert_incident(payload)
