"""Unit tests for two-way Jira Service Management and ServiceNow incident correlation."""

from __future__ import annotations

from typing import Any

import pytest

from ai_log_analyzer.itsm import (
    IncidentEnrichmentPayload,
    JiraITSMClient,
    ServiceNowITSMClient,
)
from ai_log_analyzer.remediation import RemediationGenerator, VendorOS

pytestmark = pytest.mark.unit


class DummyJiraClient(JiraITSMClient):
    def __init__(self, existing_key: str | None = None) -> None:
        super().__init__("https://jira.internal", "noc@example.com", "secret", "NET")
        self.existing_key = existing_key
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []

    def _request(self, method: str, endpoint: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        self.calls.append((method, endpoint, body))
        if endpoint.startswith("/rest/api/2/search"):
            if self.existing_key:
                return {"issues": [{"key": self.existing_key}]}
            return {"issues": []}
        if method == "POST" and endpoint == "/rest/api/2/issue":
            return {"key": "NET-901"}
        return {}


class DummyServiceNowClient(ServiceNowITSMClient):
    def __init__(self, existing_sys_id: str | None = None) -> None:
        super().__init__("https://dev12345.service-now.com", "admin", "secret")
        self.existing_sys_id = existing_sys_id
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []

    def _request(self, method: str, endpoint: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        self.calls.append((method, endpoint, body))
        if method == "GET":
            if self.existing_sys_id:
                return {"result": [{"sys_id": self.existing_sys_id, "number": "INC001055"}]}
            return {"result": []}
        if method == "POST":
            return {"result": {"sys_id": "sys-new-999", "number": "INC001099"}}
        return {"result": {}}


def _sample_payload() -> IncidentEnrichmentPayload:
    plan = RemediationGenerator().build_graceful_link_drain(
        device="leaf1",
        vendor=VendorOS.ARISTA_EOS,
        interface="Ethernet1/1",
        bgp_neighbor_ip="10.0.1.1",
    )
    return IncidentEnrichmentPayload(
        site="clab-clos-evpn",
        root_device="leaf1",
        root_layer="L1_PHYSICAL",
        root_interface="Ethernet1/1",
        summary_title="Optical Rx low & BGP EVPN cascade",
        rca_rationale="L1 transceiver fault on leaf1 (Ethernet1/1) caused 4 overlay EVPN withdrawals.",
        confidence=0.95,
        affected_devices=["leaf1", "spine1", "leaf2"],
        affected_vnis=[10010, 10020],
        suppressed_symptom_count=4,
        telemetry_summary="Rx power -19.4 dBm, FCS/CRC delta=342",
        remediation_plan=plan,
    )


def test_deterministic_fingerprint_and_markdown_card() -> None:
    p1 = _sample_payload()
    p2 = _sample_payload()

    assert p1.fingerprint == p2.fingerprint
    assert p1.fingerprint.startswith("NETLOG-")

    md = p1.to_markdown_body()
    assert "### Blast Radius & Symptom Suppression" in md
    assert "10010, 10020" in md
    assert "commit timer 00:05:00" in md


def test_jira_creates_new_incident_when_no_fingerprint_match() -> None:
    client = DummyJiraClient(existing_key=None)
    res = client.upsert_incident(_sample_payload())

    assert res["action"] == "created"
    assert res["issue_key"] == "NET-901"
    assert len(client.calls) == 2
    assert client.calls[1][0] == "POST"
    assert client.calls[1][1] == "/rest/api/2/issue"


def test_jira_updates_existing_incident_on_matching_fingerprint() -> None:
    client = DummyJiraClient(existing_key="NET-777")
    res = client.upsert_incident(_sample_payload())

    assert res["action"] == "updated"
    assert res["issue_key"] == "NET-777"
    assert client.calls[1][1] == "/rest/api/2/issue/NET-777/comment"


def test_servicenow_create_and_idempotent_update() -> None:
    create_client = DummyServiceNowClient(existing_sys_id=None)
    res_new = create_client.upsert_incident(_sample_payload())
    assert res_new["action"] == "created"
    assert res_new["number"] == "INC001099"

    update_client = DummyServiceNowClient(existing_sys_id="abc-123")
    res_upd = update_client.upsert_incident(_sample_payload())
    assert res_upd["action"] == "updated"
    assert res_upd["number"] == "INC001055"
    assert update_client.calls[1][0] == "PATCH"
