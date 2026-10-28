"""Ticket bodies render device text literally in Jira and ServiceNow (dJURoFJ9). Synthetic data only."""

from __future__ import annotations

import re
from typing import Any

import pytest

from ai_log_analyzer.itsm import (
    IncidentEnrichmentPayload,
    JiraITSMClient,
    ServiceNowITSMClient,
)
from ai_log_analyzer.remediation import RemediationGenerator, VendorOS

pytestmark = pytest.mark.unit


# ── ITSM bodies (dJURoFJ9) ─────────────────────────────────────────────────────────────────────────

HOSTILE = ("!https://192.0.2.9/t.png! [a|https://192.0.2.9/r] {panel:title=x} {code} [~admin] "
           "[code]<a href=x>x</a>[/code] [CODE]<script>1</script>[/CODE] ||h|| {{x}} *b* _i_ #n {noformat} "
           "{color:red}")


def _hostile_payload() -> IncidentEnrichmentPayload:
    plan = RemediationGenerator().build_custom_safe_plan(
        "leaf1", VendorOS.ARISTA_EOS, ["description " + HOSTILE.replace("\n", " ")], [], [], HOSTILE)
    return IncidentEnrichmentPayload(
        site="S " + HOSTILE, root_device="leaf1 " + HOSTILE, root_layer="L3", root_interface="Et1 " + HOSTILE,
        summary_title="t", rca_rationale="why\n# h1. " + HOSTILE + "\n* item\n----", confidence=0.9,
        affected_devices=["leaf1", HOSTILE], telemetry_summary=HOSTILE, remediation_plan=plan,
        attachments={"Sample events": "- `" + HOSTILE + "`\n" + HOSTILE, "Other " + HOSTILE: HOSTILE},
    )


class _Jira(JiraITSMClient):
    def __init__(self, existing: str | None = None) -> None:
        super().__init__("https://jira.example.com", "noc@example.com", "S3cr3tExampleOnly", "NET")
        self.existing = existing
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []

    def _request(self, method: str, endpoint: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        self.calls.append((method, endpoint, body))
        if endpoint.startswith("/rest/api/2/search"):
            return {"issues": [{"key": self.existing}] if self.existing else []}
        return {"key": "NET-1"} if method == "POST" and endpoint == "/rest/api/2/issue" else {}


class _Snow(ServiceNowITSMClient):
    def __init__(self, existing: str | None = None) -> None:
        super().__init__("https://dev1.service-now.example.com", "svc", "S3cr3tExampleOnly")
        self.existing = existing
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []

    def _request(self, method: str, endpoint: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        self.calls.append((method, endpoint, body))
        if method == "GET":
            return {"result": [{"sys_id": self.existing, "number": "INC1"}] if self.existing else []}
        return {"result": {"sys_id": "s1", "number": "INC2"}}


def _outside_noformat(body: str) -> str:
    return re.sub(r"\{noformat\}.*?\{noformat\}", "", body, flags=re.DOTALL)


def _assert_jira_inert(body: str) -> None:
    assert body.count("{noformat}") % 2 == 0 and body.count("{noformat}") >= 2
    prose = re.sub(r"\\.", "", _outside_noformat(body))
    assert not re.search(r"[{}\[\]!|]", prose), prose
    for block in re.findall(r"\{noformat\}(.*?)\{noformat\}", body, flags=re.DOTALL):
        assert "{noformat" not in block
    for line_start in ("\n* item", "\n# h1.", "\nh1.", "\n----"):  # the rationale stays on one line
        assert line_start not in prose, line_start


def test_jira_description_and_comment_render_device_text_literally() -> None:
    created = _Jira()
    created.upsert_incident(_hostile_payload())
    _assert_jira_inert(created.calls[1][2]["fields"]["description"])  # type: ignore[index]
    updated = _Jira(existing="NET-7")
    updated.upsert_incident(_hostile_payload())
    _assert_jira_inert(updated.calls[1][2]["body"])  # type: ignore[index]


def test_jira_body_stays_readable() -> None:
    body = _hostile_payload().to_markdown_body(target="jira")
    for word in ("leaf1", "192.0.2.9", "Sample events", "Automated RCA Summary", "Blast Radius"):
        assert word in body
    assert "10010" not in body and "NETLOG-" in body


def test_servicenow_work_notes_carry_no_code_tags() -> None:
    tag = re.compile(r"\[\s*/?\s*code\s*\]", re.IGNORECASE)
    created = _Snow()
    created.upsert_incident(_hostile_payload())
    notes = created.calls[1][2]["work_notes"]  # type: ignore[index]
    assert not tag.search(notes) and "code" in notes
    updated = _Snow(existing="abc")
    updated.upsert_incident(_hostile_payload())
    assert not tag.search(updated.calls[1][2]["work_notes"])  # type: ignore[index]
    assert not tag.search(_hostile_payload().to_servicenow_record()["work_notes"])


def test_preview_payloads_match_what_is_sent() -> None:
    p = _hostile_payload()
    assert p.to_jira_issue_fields("NET")["description"] == p.to_markdown_body(target="jira")
    assert p.to_servicenow_record()["work_notes"] == p.to_markdown_body(target="servicenow")


def test_default_markdown_body_is_unchanged() -> None:
    p = IncidentEnrichmentPayload(site="s", root_device="leaf1", root_layer="L3", root_interface="Et1",
                                  summary_title="t", rca_rationale="a [b](c) !x!", confidence=0.5,
                                  attachments={"A": "- `x [y]`"})
    body = p.to_markdown_body()
    assert "**Rationale:** a [b](c) !x!" in body and "### A\n- `x [y]`" in body and "{noformat}" not in body
