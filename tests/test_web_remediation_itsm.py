"""Route and CLI tests for Release v1.1.0 vendor-safe remediation and ITSM enrichment."""

from __future__ import annotations

import argparse
from typing import Any
from unittest.mock import patch

import pytest

from ai_log_analyzer.cli import cmd_remediation
from ai_log_analyzer.web.app import create_app

pytestmark = pytest.mark.unit


@pytest.fixture
def client():
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


def test_api_remediation_drain_success(client) -> None:
    resp = client.post(
        "/api/remediation",
        json={
            "device": "leaf1",
            "vendor": "juniper_junos",
            "action": "drain",
            "interface": "xe-0/0/1",
            "rollback_minutes": 10,
        },
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["plan"]["vendor"] == "juniper_junos"
    assert data["plan"]["rollback_minutes"] == 10
    assert any("commit confirmed 10" in cmd for cmd in data["plan"]["commit_with_timer_commands"])
    assert "markdown_card" in data


def test_api_remediation_copp_success(client) -> None:
    resp = client.post(
        "/api/remediation",
        json={
            "device": "spine1",
            "vendor": "arista_eos",
            "action": "copp",
            "interface": "Ethernet1",
            "rollback_minutes": 5,
        },
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert any("commit timer 5" in cmd for cmd in data["plan"]["commit_with_timer_commands"])


def test_api_remediation_safety_guardrail_blocks_erase(client) -> None:
    resp = client.post(
        "/api/remediation",
        json={
            "device": "leaf1",
            "vendor": "arista_eos",
            "action": "custom",
            "commands": ["write erase"],
            "pre_checks": ["show version"],
            "post_checks": ["show version"],
        },
    )
    assert resp.status_code == 400
    data = resp.get_json()
    assert data["ok"] is False
    assert "blocked by safety guardrail" in data["error"]


def test_api_remediation_validation_errors(client) -> None:
    # Missing device and vendor
    resp = client.post("/api/remediation", json={})
    assert resp.status_code == 400

    # Unknown vendor
    resp = client.post("/api/remediation", json={"device": "leaf1", "vendor": "alien_os"})
    assert resp.status_code == 400
    assert "unknown vendor" in resp.get_json()["error"]

    # Invalid rollback minutes (out of bounds)
    resp = client.post(
        "/api/remediation",
        json={
            "device": "leaf1",
            "vendor": "arista_eos",
            "action": "drain",
            "rollback_minutes": 60,
        },
    )
    assert resp.status_code == 400
    assert "must be between 1 and 30" in resp.get_json()["error"]


def test_api_itsm_enrich_dry_run(client) -> None:
    resp = client.post(
        "/api/itsm/enrich",
        json={
            "system": "jira",
            "device": "leaf1",
            "vendor": "arista_eos",
            "root_cause_summary": "L1 Transceiver Fault on Ethernet1",
            "site": "clab-clos-evpn",
            "dry_run": True,
        },
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["dry_run"] is True
    assert data["fingerprint"].startswith("NETLOG-")
    assert "jira_payload" in data
    assert "markdown_card" in data


def test_api_itsm_enrich_live_dispatch_mocked(client) -> None:
    mock_res: dict[str, Any] = {"action": "created", "issue_key": "NET-501"}
    with patch("ai_log_analyzer.itsm.JiraITSMClient.enrich_incident", return_value=mock_res):
        resp = client.post(
            "/api/itsm/enrich",
            json={
                "system": "jira",
                "device": "leaf1",
                "vendor": "arista_eos",
                "root_cause_summary": "BGP Underlay flap",
                "instance_url": "https://jira.example.com",
                "email": "noc@example.com",
                "api_token": "token123",
                "dry_run": False,
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["dry_run"] is False
        assert data["result"]["issue_key"] == "NET-501"


def test_cli_cmd_remediation_drain(capsys) -> None:
    args = argparse.Namespace(
        device="leaf1",
        vendor="arista_eos",
        action="drain",
        interface="Ethernet1",
        bgp_neighbor="10.0.0.1",
        rollback_minutes=5,
        rationale="Emergency drain test",
        json=False,
    )
    rc = cmd_remediation(args)
    assert rc == 0
    out = capsys.readouterr().out
    assert "Remediation Plan" in out
    assert "commit timer 5" in out


def test_cli_cmd_remediation_json(capsys) -> None:
    args = argparse.Namespace(
        device="spine1",
        vendor="juniper_junos",
        action="copp",
        interface="xe-0/0/0",
        bgp_neighbor=None,
        rollback_minutes=7,
        rationale="QoS boost",
        json=True,
    )
    rc = cmd_remediation(args)
    assert rc == 0
    out = capsys.readouterr().out
    assert '"rollback_minutes": 7' in out
    assert '"vendor": "juniper_junos"' in out
