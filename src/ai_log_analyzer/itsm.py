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
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from ai_log_analyzer.remediation import RemediationPlan

_ATTACHMENT_CHARS = 6000   # Jira descriptions cap near 32 KB; leave room for the RCA card


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

    def to_markdown_body(self) -> str:
        """Format full RCA, blast radius, and remediation card in Markdown."""
        vni_str = ", ".join(str(v) for v in sorted(self.affected_vnis)) or "None"
        dev_str = ", ".join(sorted(self.affected_devices)) or self.root_device
        lines = [
            f"## netlog-ai Automated RCA Summary (`{self.fingerprint}`)",
            f"- **Site:** `{self.site}`",
            f"- **Root Cause Device:** `{self.root_device}`"
            + (f" (`{self.root_interface}`)" if self.root_interface else ""),
            f"- **Protocol Layer:** `{self.root_layer}`",
            f"- **Confidence:** `{int(self.confidence * 100)}%`",
            f"- **Rationale:** {self.rca_rationale}",
            "",
            "### Blast Radius & Symptom Suppression",
            f"- **Affected Devices ({len(self.affected_devices) or 1}):** {dev_str}",
            f"- **Affected EVPN VNIs:** {vni_str}",
            f"- **Suppressed Downstream Alarms:** `{self.suppressed_symptom_count}`",
        ]
        if self.telemetry_summary:
            lines.extend(["", "### Optical / Interface Telemetry Verdict", f"> {self.telemetry_summary}"])
        if self.remediation_plan:
            lines.extend(["", self.remediation_plan.to_markdown_card()])
        for title, body in self.attachments.items():
            if body:
                lines.extend(["", f"### {title}", body[:_ATTACHMENT_CHARS]])
        return "\n".join(lines)

    def to_jira_issue_fields(self, project_key: str, issue_type: str = "Incident") -> dict[str, Any]:
        """Construct Jira REST API v2/v3 issue creation fields with fingerprint label."""
        priority = "Highest" if self.confidence >= 0.90 and len(self.affected_devices) > 1 else "High"
        return {
            "project": {"key": project_key},
            "summary": f"[{self.site}] {self.summary_title} on {self.root_device}",
            "description": self.to_markdown_body(),
            "issuetype": {"name": issue_type},
            "priority": {"name": priority},
            "labels": ["netlog-ai", f"site-{self.site}", self.fingerprint],
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
            "work_notes": self.to_markdown_body(),
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
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.project_key = project_key
        self.timeout = timeout
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
            "User-Agent": "netlog-ai/2.1.0",
        }
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}

    def find_open_issue_by_fingerprint(self, fingerprint: str) -> str | None:
        """Query JQL for an existing unresolved incident matching the fingerprint label."""
        jql = (
            f'project = "{self.project_key}" AND labels = "{fingerprint}" '
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
                {"body": payload.to_markdown_body()},
            )
            return {"action": "updated", "issue_key": existing_key, "fingerprint": payload.fingerprint}

        created = self._request(
            "POST",
            "/rest/api/2/issue",
            {"fields": payload.to_jira_issue_fields(self.project_key)},
        )
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

    def __init__(self, instance_url: str, username: str, password: str, timeout: int = 15) -> None:
        self.base_url = instance_url.rstrip("/")
        self.timeout = timeout
        creds = f"{username}:{password}".encode()
        self._auth_header = "Basic " + base64.b64encode(creds).decode("ascii")

    def _request(self, method: str, endpoint: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {
            "Authorization": self._auth_header,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "netlog-ai/2.1.0",
        }
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
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
                {"work_notes": payload.to_markdown_body()},
            )
            return {
                "action": "updated",
                "number": existing.get("number", sys_id),
                "sys_id": sys_id,
                "fingerprint": payload.fingerprint,
            }

        created = self._request(
            "POST",
            "/api/now/table/incident",
            payload.to_servicenow_record(),
        )
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
