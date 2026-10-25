"""Unit tests for vendor-safe remediation plans, rollback timers, and safety guardrails."""

from __future__ import annotations

import pytest

from ai_log_analyzer.remediation import (
    AuditRecord,
    RemediationActionType,
    RemediationGenerator,
    SafetyViolationError,
    VendorOS,
)

pytestmark = pytest.mark.unit


def test_junos_graceful_drain_uses_commit_confirmed() -> None:
    gen = RemediationGenerator(default_rollback_minutes=5)
    plan = gen.build_graceful_link_drain(
        device="junos-rt-01",
        vendor=VendorOS.JUNIPER_JUNOS,
        interface="xe-0/0/1",
        bgp_neighbor_ip="10.0.1.1",
        rollback_minutes=7,
    )

    assert plan.vendor == VendorOS.JUNIPER_JUNOS
    assert plan.action_type == RemediationActionType.GRACEFUL_LINK_DRAIN
    assert plan.rollback_minutes == 7
    assert "configure exclusive" in plan.config_commands
    assert any("commit confirmed 7" in cmd for cmd in plan.commit_with_timer_commands)
    assert "rollback 0" in plan.manual_rollback_commands

    md = plan.to_markdown_card()
    assert "Auto-Rollback Timer:** `7 min`" in md
    assert "xe-0/0/1" in md


def test_arista_eos_uses_configure_session_commit_timer() -> None:
    gen = RemediationGenerator()
    plan = gen.build_qos_copp_remediation(
        device="eos-sw-01",
        vendor=VendorOS.ARISTA_EOS,
        interface="Ethernet1/1",
        rollback_minutes=4,
    )

    assert any(cmd.startswith("configure session REM_") for cmd in plan.config_commands)
    assert "commit timer 00:04:00" in plan.commit_with_timer_commands
    assert "abort" in plan.manual_rollback_commands


def test_cisco_nxos_and_ios_xe_rollback_wrappers() -> None:
    gen = RemediationGenerator()

    nxos_plan = gen.build_graceful_link_drain(
        device="nxos-spine-01",
        vendor=VendorOS.CISCO_NXOS,
        interface="Ethernet1/1",
    )
    assert any(cmd.startswith("checkpoint REM_") for cmd in nxos_plan.config_commands)
    assert any(cmd.startswith("rollback running-config checkpoint") for cmd in nxos_plan.manual_rollback_commands)

    ios_plan = gen.build_graceful_link_drain(
        device="ios-edge-01",
        vendor=VendorOS.CISCO_IOS_XE,
        interface="GigabitEthernet0/1",
        rollback_minutes=6,
    )
    assert "configure terminal revert timer 6" in ios_plan.config_commands
    assert "configure confirm" in ios_plan.confirm_commit_commands
    assert "configure revert now" in ios_plan.manual_rollback_commands


def test_safety_guardrail_blocks_destructive_commands() -> None:
    gen = RemediationGenerator()

    for dangerous_cmd in [
        "write erase",
        "request system zeroize",
        "reload in 5",
        "no router bgp 65001",
        "delete",
    ]:
        with pytest.raises(SafetyViolationError):
            gen.build_custom_safe_plan(
                device="leaf1",
                vendor=VendorOS.ARISTA_EOS,
                commands=[dangerous_cmd],
                pre_checks=["show version"],
                post_checks=["show ip bgp summary"],
                rationale="Malicious or hallucinated LLM command test",
            )


def test_safety_guardrail_enforces_timer_bounds() -> None:
    gen = RemediationGenerator()
    with pytest.raises(SafetyViolationError):
        gen.build_graceful_link_drain(
            device="leaf1",
            vendor=VendorOS.ARISTA_EOS,
            interface="Ethernet1",
            rollback_minutes=0,
        )
    with pytest.raises(SafetyViolationError):
        gen.build_graceful_link_drain(
            device="leaf1",
            vendor=VendorOS.ARISTA_EOS,
            interface="Ethernet1",
            rollback_minutes=90,
        )


def test_audit_record_jsonl_serialization() -> None:
    rec = AuditRecord(
        timestamp="2026-10-13T23:00:00Z",
        actor="netlog-ai-mcp",
        event_type="remediation_generated",
        device="leaf1",
        plan_id="REM-1234ABCD",
        ticket_id="NET-402",
    )
    parsed = rec.to_jsonl()
    assert '"plan_id": "REM-1234ABCD"' in parsed
    assert '"ticket_id": "NET-402"' in parsed
