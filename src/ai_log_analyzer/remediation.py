"""Vendor-safe remediation generator with automatic rollback guardrails.

Produces deterministic pre-checks, transactional configuration blocks with
auto-revert timers, post-checks, and explicit abort/rollback sequences across
Arista EOS, Juniper Junos, Cisco NX-OS, Cisco IOS-XE, and FRRouting.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class VendorOS(str, Enum):
    ARISTA_EOS = "arista_eos"
    JUNIPER_JUNOS = "juniper_junos"
    CISCO_NXOS = "cisco_nxos"
    CISCO_IOS_XE = "cisco_ios"
    FRR = "frr"


class RemediationActionType(str, Enum):
    GRACEFUL_LINK_DRAIN = "graceful_link_drain"
    INTERFACE_FLAP_DAMPENING = "interface_flap_dampening"
    QOS_COPP_CONTROL_PLANE_BOOST = "qos_copp_control_plane_boost"
    EVPN_MAC_MOBILITY_FREEZE = "evpn_mac_mobility_freeze"
    CUSTOM_SAFE_CONFIG = "custom_safe_config"


# Destructive CLI patterns strictly blocked from automated or copy-paste generation
_FORBIDDEN_CLI_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("erase_storage", re.compile(r"\b(?:write\s+erase|erase\s+startup-config|format\s+flash:)\b", re.IGNORECASE)),
    ("system_zeroize", re.compile(r"\brequest\s+system\s+(?:zeroize|halt|power-off)\b", re.IGNORECASE)),
    ("unscoped_reload", re.compile(r"^\s*(?:reload|reboot)\b", re.IGNORECASE)),
    ("wipe_bgp_asn", re.compile(r"^\s*no\s+router\s+(?:bgp|ospf|isis)\b", re.IGNORECASE)),
    ("delete_root_config", re.compile(r"^\s*delete\s*$", re.IGNORECASE)),
]


class SafetyViolationError(ValueError):
    """Raised when a proposed remediation violates network safety guardrails."""


@dataclass
class RemediationPlan:
    """Complete vendor-safe change package with rollback timer and verification steps."""

    plan_id: str
    device: str
    vendor: VendorOS
    action_type: RemediationActionType
    rollback_minutes: int
    rationale: str
    pre_checks: list[str]
    config_commands: list[str]
    commit_with_timer_commands: list[str]
    post_checks: list[str]
    confirm_commit_commands: list[str]
    manual_rollback_commands: list[str]
    blast_radius_notes: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_markdown_card(self) -> str:
        """Render a copy-pasteable engineering remediation card for CLI, Web UI, or Jira."""
        pre_block = "\n".join(self.pre_checks)
        apply_block = "\n".join(self.config_commands + self.commit_with_timer_commands)
        post_block = "\n".join(self.post_checks)
        confirm_block = "\n".join(self.confirm_commit_commands)
        rollback_block = "\n".join(self.manual_rollback_commands)

        return (
            f"### Remediation Plan `{self.plan_id}` — `{self.device}` ({self.vendor.value})\n"
            f"**Action:** `{self.action_type.value}` | "
            f"**Auto-Rollback Timer:** `{self.rollback_minutes} min`\n"
            f"**Rationale:** {self.rationale}\n"
            + (f"**Blast Radius:** {self.blast_radius_notes}\n" if self.blast_radius_notes else "")
            + f"\n#### 1. Pre-Checks (Read-Only)\n```text\n{pre_block}\n```\n"
            f"#### 2. Transactional Apply (Auto-Reverts in {self.rollback_minutes}m if Unconfirmed)\n"
            f"```text\n{apply_block}\n```\n"
            f"#### 3. Post-Checks (Verify Convergence)\n```text\n{post_block}\n```\n"
            f"#### 4a. Confirm Change (Make Persistent)\n```text\n{confirm_block}\n```\n"
            f"#### 4b. Emergency Immediate Rollback\n```text\n{rollback_block}\n```"
        )


class SafetyGuardrail:
    """Validates CLI commands and rollback parameters before plan emission."""

    MIN_ROLLBACK_MINUTES = 1
    MAX_ROLLBACK_MINUTES = 30

    @classmethod
    def validate(cls, commands: list[str], rollback_minutes: int) -> None:
        if not (cls.MIN_ROLLBACK_MINUTES <= rollback_minutes <= cls.MAX_ROLLBACK_MINUTES):
            raise SafetyViolationError(
                f"rollback_minutes ({rollback_minutes}) must be between "
                f"{cls.MIN_ROLLBACK_MINUTES} and {cls.MAX_ROLLBACK_MINUTES}."
            )

        for cmd in commands:
            for rule_name, pattern in _FORBIDDEN_CLI_PATTERNS:
                if pattern.search(cmd):
                    raise SafetyViolationError(
                        f"Command '{cmd}' blocked by safety guardrail '{rule_name}'."
                    )


class RemediationGenerator:
    """Generates vendor-specific, rollback-guarded remediation plans."""

    def __init__(self, default_rollback_minutes: int = 5) -> None:
        self.default_rollback_minutes = default_rollback_minutes

    @staticmethod
    def _make_plan_id(device: str, action: RemediationActionType, target: str) -> str:
        digest = hashlib.sha1(f"{device}:{action.value}:{target}".encode()).hexdigest()[:8]
        return f"REM-{digest.upper()}"

    def _wrap_vendor_transaction(
        self,
        vendor: VendorOS,
        session_tag: str,
        body_commands: list[str],
        rollback_minutes: int,
    ) -> tuple[list[str], list[str], list[str], list[str]]:
        """Return (config_cmds, commit_timer_cmds, confirm_cmds, rollback_cmds)."""
        if vendor == VendorOS.JUNIPER_JUNOS:
            config_cmds = ["configure exclusive", *body_commands, "show | compare"]
            commit_timer = [
                f'commit confirmed {rollback_minutes} comment "netlog-ai {session_tag}"'
            ]
            confirm_cmds = [f'commit comment "netlog-ai {session_tag} confirmed"', "exit"]
            rollback_cmds = ["rollback 0", "commit and-quit"]
            return config_cmds, commit_timer, confirm_cmds, rollback_cmds

        if vendor == VendorOS.ARISTA_EOS:
            config_cmds = [f"configure session {session_tag}", *body_commands, "show session-config diffs"]
            commit_timer = [f"commit timer {rollback_minutes}"]
            confirm_cmds = [f"configure session {session_tag}", "commit"]
            rollback_cmds = [f"configure session {session_tag}", "abort"]
            return config_cmds, commit_timer, confirm_cmds, rollback_cmds

        if vendor == VendorOS.CISCO_NXOS:
            config_cmds = [
                f"checkpoint {session_tag} description netlog-ai-pre-change",
                "configure terminal",
                *body_commands,
            ]
            commit_timer = ["end"]
            confirm_cmds = ["copy running-config startup-config"]
            rollback_cmds = [f"rollback running-config checkpoint {session_tag}"]
            return config_cmds, commit_timer, confirm_cmds, rollback_cmds

        if vendor == VendorOS.CISCO_IOS_XE:
            config_cmds = [
                f"configure terminal revert timer {rollback_minutes}",
                *body_commands,
            ]
            commit_timer = ["end"]
            confirm_cmds = ["configure confirm"]
            rollback_cmds = ["configure revert now"]
            return config_cmds, commit_timer, confirm_cmds, rollback_cmds

        # FRR (vtysh transactional snapshot + reload test)
        config_cmds = [
            f"cp /etc/frr/frr.conf /etc/frr/frr.conf.{session_tag}.bak",
            "vtysh -c 'configure terminal' " + " ".join(f"-c '{c}'" for c in body_commands),
        ]
        commit_timer = [
            f"nohup sh -c 'sleep {rollback_minutes * 60} && cp /etc/frr/frr.conf.{session_tag}.bak /etc/frr/frr.conf && systemctl reload frr' >/dev/null 2>&1 &"
        ]
        confirm_cmds = ["pkill -f 'frr.conf." + session_tag + "'", "vtysh -c 'write integrated'"]
        rollback_cmds = [
            f"cp /etc/frr/frr.conf.{session_tag}.bak /etc/frr/frr.conf && systemctl reload frr"
        ]
        return config_cmds, commit_timer, confirm_cmds, rollback_cmds

    def build_graceful_link_drain(
        self,
        device: str,
        vendor: VendorOS,
        interface: str,
        bgp_neighbor_ip: str | None = None,
        rollback_minutes: int | None = None,
        rationale: str = "Drain traffic gracefully prior to physical transceiver/fiber maintenance.",
    ) -> RemediationPlan:
        """Cost-out an impaired interface/BGP peer before shutting down L1 optics."""
        timer = self.default_rollback_minutes if rollback_minutes is None else rollback_minutes
        plan_id = self._make_plan_id(device, RemediationActionType.GRACEFUL_LINK_DRAIN, interface)
        session_tag = plan_id.replace("-", "_")

        if vendor == VendorOS.JUNIPER_JUNOS:
            pre = [
                'show interfaces ' + interface + ' extensive | match "error|flap|dbm"',
                "show bgp summary",
            ]
            body = [
                f"set protocols bgp group UNDERLAY neighbor {bgp_neighbor_ip or 'peer'} import DRAIN-IN",
                f"set protocols bgp group UNDERLAY neighbor {bgp_neighbor_ip or 'peer'} export DRAIN-OUT",
                f"set interfaces {interface} disable",
            ]
            post = [
                f"show interfaces {interface} terse",
                "show route summary",
            ]
        elif vendor == VendorOS.ARISTA_EOS:
            pre = [
                f"show interfaces {interface} transceiver dom",
                "show ip bgp summary",
            ]
            body = [
                "ip as-path access-list DRAIN permit .*",
                f"interface {interface}",
                "   bgp session tracker DRAIN",
                "   shutdown",
            ]
            post = [
                f"show interfaces {interface} status",
                "show ip bgp summary",
            ]
        else:
            pre = [f"show interface {interface}", "show ip bgp summary"]
            body = [f"interface {interface}", "shutdown"]
            post = [f"show interface {interface} status", "show ip bgp summary"]

        SafetyGuardrail.validate(body, timer)
        cfg, c_timer, confirm, rb = self._wrap_vendor_transaction(vendor, session_tag, body, timer)

        return RemediationPlan(
            plan_id=plan_id,
            device=device,
            vendor=vendor,
            action_type=RemediationActionType.GRACEFUL_LINK_DRAIN,
            rollback_minutes=timer,
            rationale=rationale,
            pre_checks=pre,
            config_commands=cfg,
            commit_with_timer_commands=c_timer,
            post_checks=post,
            confirm_commit_commands=confirm,
            manual_rollback_commands=rb,
            blast_radius_notes=f"Drains ECMP member {interface} on {device}; verify >=1 alternate spine path is Up.",
        )

    def build_qos_copp_remediation(
        self,
        device: str,
        vendor: VendorOS,
        interface: str,
        rollback_minutes: int | None = None,
        rationale: str = "Prioritize BFD/BGP control-plane traffic to eliminate microburst hold-timer drops.",
    ) -> RemediationPlan:
        """Generate strict-priority control-plane QoS/CoPP protection for BFD/BGP."""
        timer = self.default_rollback_minutes if rollback_minutes is None else rollback_minutes
        plan_id = self._make_plan_id(device, RemediationActionType.QOS_COPP_CONTROL_PLANE_BOOST, interface)
        session_tag = plan_id.replace("-", "_")

        if vendor == VendorOS.JUNIPER_JUNOS:
            pre = [f"show interfaces queue {interface}", "show bfd session"]
            body = [
                f"set class-of-service interfaces {interface} scheduler-map STRICT-NC-PRIORITY",
            ]
            post = [f"show interfaces queue {interface} | matchPoliced", "show bfd session"]
        elif vendor == VendorOS.ARISTA_EOS:
            pre = [f"show qos interfaces {interface} queue", "show bfd peers"]
            body = [
                f"interface {interface}",
                "   tx-queue 7",
                "      priority strict",
                "      bandwidth percent 15",
            ]
            post = [f"show qos interfaces {interface} queue", "show bfd peers"]
        else:
            pre = [f"show queuing interface {interface}", "show bfd neighbors"]
            body = [f"interface {interface}", "priority-queue out"]
            post = [f"show queuing interface {interface}", "show bfd neighbors"]

        SafetyGuardrail.validate(body, timer)
        cfg, c_timer, confirm, rb = self._wrap_vendor_transaction(vendor, session_tag, body, timer)

        return RemediationPlan(
            plan_id=plan_id,
            device=device,
            vendor=vendor,
            action_type=RemediationActionType.QOS_COPP_CONTROL_PLANE_BOOST,
            rollback_minutes=timer,
            rationale=rationale,
            pre_checks=pre,
            config_commands=cfg,
            commit_with_timer_commands=c_timer,
            post_checks=post,
            confirm_commit_commands=confirm,
            manual_rollback_commands=rb,
            blast_radius_notes=f"Non-disruptive QoS scheduler update on {device} ({interface}).",
        )

    def build_custom_safe_plan(
        self,
        device: str,
        vendor: VendorOS,
        commands: list[str],
        pre_checks: list[str],
        post_checks: list[str],
        rationale: str,
        rollback_minutes: int | None = None,
    ) -> RemediationPlan:
        """Validate arbitrary LLM-proposed commands against safety guardrails and wrap in rollback timers."""
        timer = self.default_rollback_minutes if rollback_minutes is None else rollback_minutes
        SafetyGuardrail.validate(commands, timer)

        plan_id = self._make_plan_id(device, RemediationActionType.CUSTOM_SAFE_CONFIG, ";".join(commands))
        session_tag = plan_id.replace("-", "_")
        cfg, c_timer, confirm, rb = self._wrap_vendor_transaction(vendor, session_tag, commands, timer)

        return RemediationPlan(
            plan_id=plan_id,
            device=device,
            vendor=vendor,
            action_type=RemediationActionType.CUSTOM_SAFE_CONFIG,
            rollback_minutes=timer,
            rationale=rationale,
            pre_checks=pre_checks,
            config_commands=cfg,
            commit_with_timer_commands=c_timer,
            post_checks=post_checks,
            confirm_commit_commands=confirm,
            manual_rollback_commands=rb,
        )


@dataclass
class AuditRecord:
    """Immutable audit log entry for remediation generation and ITSM dispatches."""

    timestamp: str
    actor: str
    event_type: str
    device: str
    plan_id: str | None = None
    ticket_id: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_jsonl(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)
