"""Vendor-safe remediation generator with automatic rollback guardrails.

Produces deterministic pre-checks, transactional configuration blocks with
auto-revert timers, post-checks, and explicit abort/rollback sequences across
Arista EOS, Juniper Junos, Cisco NX-OS, Cisco IOS-XE, FRRouting, Fortinet
FortiOS, Palo Alto PAN-OS and Cisco Catalyst SD-WAN.

Rollback semantics differ per platform and are stated in each plan:
Junos/EOS/IOS-XE/SD-WAN have a native confirm timer; FortiOS revert mode
restores the saved config by restarting the unit; PAN-OS has no commit timer,
so its plan saves a named snapshot and rolls back by loading it.
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
    FORTINET_FORTIOS = "fortinet_fortios"
    PALOALTO_PANOS = "paloalto_panos"
    CISCO_SDWAN = "cisco_sdwan"


class RemediationActionType(str, Enum):
    GRACEFUL_LINK_DRAIN = "graceful_link_drain"
    INTERFACE_FLAP_DAMPENING = "interface_flap_dampening"
    QOS_COPP_CONTROL_PLANE_BOOST = "qos_copp_control_plane_boost"
    EVPN_MAC_MOBILITY_FREEZE = "evpn_mac_mobility_freeze"
    CUSTOM_SAFE_CONFIG = "custom_safe_config"


# Destructive CLI patterns strictly blocked from automated or copy-paste generation.
# Patterns are matched per command *segment*: a CLI string is split on
# newlines, `;`, `&&`, `||` and `vtysh -c '...'` boundaries first, so
# anchored rules still catch `vtysh -c 'reload'` or a second line `reboot`.
_FORBIDDEN_CLI_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("erase_storage", re.compile(r"\b(?:write\s+erase|erase\s+(?:startup-config|nvram:|flash:|bootflash:)|format\s+(?:flash|bootflash|disk\d*|usb\d*):?)", re.IGNORECASE)),
    ("system_zeroize", re.compile(r"\brequest\s+system\s+(?:zeroize|halt|power-off|reboot|snapshot\s+delete)\b", re.IGNORECASE)),
    ("unscoped_reload", re.compile(r"^\s*(?:sudo\s+)?(?:reload|reboot|shutdown\s+-[hr]|halt|poweroff)\b", re.IGNORECASE)),
    ("wipe_bgp_asn", re.compile(r"^\s*no\s+router\s+(?:bgp|ospf|isis)\b", re.IGNORECASE)),
    ("delete_root_config", re.compile(r"^\s*delete\s*$", re.IGNORECASE)),
    # Junos: deleting a whole top-level stanza (≤1 qualifier, e.g. `delete protocols bgp`).
    ("delete_config_stanza", re.compile(r"^\s*delete\s+(?:protocols|routing-options|routing-instances|interfaces|security|system|policy-options|firewall|chassis)(?:\s+\S+)?\s*$", re.IGNORECASE)),
    # Hard reset of every BGP session (soft refresh is allowed).
    # Junos `clear bgp neighbor` with no peer resets every session too.
    ("clear_all_bgp", re.compile(r"^\s*clear\s+(?:ip\s+)?bgp\s+(?:(?:neighbor\s+)?(?:\*|all)(?!\S)(?!.*\bsoft\b)|neighbor\s*$)", re.IGNORECASE)),
    ("load_override", re.compile(r"^\s*load\s+(?:override|factory-default)\b", re.IGNORECASE)),
    # FortiOS / PAN-OS / SD-WAN platform resets, wipes and restarts.
    ("fortios_destructive", re.compile(r"^\s*execute\s+(?:factoryreset\w*|formatlogdisk|erase-disk|reboot|shutdown|restore\s+image)\b", re.IGNORECASE)),
    ("panos_destructive", re.compile(r"^\s*request\s+(?:system\s+private-data-reset|restart\s+system|shutdown\s+system)\b", re.IGNORECASE)),
    ("sdwan_destructive", re.compile(r"^\s*request\s+(?:software\s+reset|reset\s+all|platform\s+software\s+sdwan\s+software\s+reset)\b|^\s*reboot\s+now\b", re.IGNORECASE)),
    ("shell_wipe", re.compile(r"\brm\s+-[a-z]*r[a-z]*f?\s+/(?:\s|$)|\bmkfs\b|\bdd\s+if=.*\bof=/dev/", re.IGNORECASE)),
]

_SEGMENT_SPLIT_RE = re.compile(r"\n|;|&&|\|\||\bvtysh\b|-c\s+")

BLOCKED_CLI_PLACEHOLDER = "# BLOCKED by SafetyGuardrail ({rule}): command withheld — requires manual engineering review"


def _command_segments(cmd: str) -> list[str]:
    """Split one CLI string into the individual commands it would run."""
    parts = _SEGMENT_SPLIT_RE.split(cmd or "")
    return [p.strip().strip("'\"").strip() for p in parts if p and p.strip().strip("'\"").strip()]


class SafetyViolationError(ValueError):
    """Raised when a proposed remediation violates network safety guardrails."""


_NO_QOS_TEMPLATE = frozenset({VendorOS.FORTINET_FORTIOS, VendorOS.PALOALTO_PANOS, VendorOS.CISCO_SDWAN})


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

    def _apply_heading(self) -> str:
        if self.vendor == VendorOS.PALOALTO_PANOS:
            return f"No Native Auto-Revert — Manual Rollback Window {self.rollback_minutes}m"
        if self.vendor == VendorOS.FORTINET_FORTIOS:
            return f"Revert Mode — Unit Restarts on Saved Config in {self.rollback_minutes}m if Unsaved"
        return f"Auto-Reverts in {self.rollback_minutes}m if Unconfirmed"

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
            f"#### 2. Transactional Apply ({self._apply_heading()})\n"
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
            rule_name = cls.violation(cmd)
            if rule_name:
                raise SafetyViolationError(
                    f"Command '{cmd}' blocked by safety guardrail '{rule_name}'."
                )

    @staticmethod
    def violation(cmd: str) -> str | None:
        """Name of the first guardrail rule ``cmd`` violates, or None if safe."""
        if not isinstance(cmd, str):
            return None
        for segment in [cmd, *_command_segments(cmd)]:
            for rule_name, pattern in _FORBIDDEN_CLI_PATTERNS:
                if pattern.search(segment):
                    return rule_name
        return None

    @classmethod
    def screen(cls, commands: list[str] | tuple[str, ...]) -> tuple[list[str], list[dict[str, str]]]:
        """Non-raising filter for model-generated CLI.

        Returns (commands with violations replaced by a visible placeholder,
        [{"command", "rule"}] for each blocked command).
        """
        safe: list[str] = []
        blocked: list[dict[str, str]] = []
        for cmd in commands or []:
            text = str(cmd)
            rule = cls.violation(text)
            if rule:
                blocked.append({"command": text, "rule": rule})
                safe.append(BLOCKED_CLI_PLACEHOLDER.format(rule=rule))
            else:
                safe.append(text)
        return safe, blocked


def screen_llm_cli(value: Any, blocked: list[dict[str, str]] | None = None) -> Any:
    """Recursively screen LLM output (str / list / dict of CLI) through the guardrail.

    Strings are treated as one command (multi-line strings are screened per
    segment); dict keys (platform or hostname) are preserved. Violations are
    replaced with ``BLOCKED_CLI_PLACEHOLDER`` and appended to ``blocked``.
    """
    sink = blocked if blocked is not None else []
    if isinstance(value, str):
        rule = SafetyGuardrail.violation(value)
        if rule:
            sink.append({"command": value, "rule": rule})
            return BLOCKED_CLI_PLACEHOLDER.format(rule=rule)
        return value
    if isinstance(value, list):
        return [screen_llm_cli(v, sink) for v in value]
    if isinstance(value, tuple):
        return tuple(screen_llm_cli(v, sink) for v in value)
    if isinstance(value, dict):
        return {k: screen_llm_cli(v, sink) for k, v in value.items()}
    return value


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

        if vendor == VendorOS.FORTINET_FORTIOS:
            # Revert mode: changes are live but unsaved; if not saved before the
            # timer expires the unit restarts on the last saved configuration.
            config_cmds = [
                f"execute backup config flash netlog-ai-{session_tag}",
                "config system global",
                "    set cfg-save revert",
                f"    set cfg-revert-timeout {rollback_minutes * 60}",
                "end",
                *body_commands,
            ]
            commit_timer = [
                f"# changes are live and UNSAVED; auto-revert in {rollback_minutes} min restarts the unit "
                "on the saved config — run in a maintenance window",
            ]
            confirm_cmds = ["execute cfg save", "config system global", "    set cfg-save automatic", "end"]
            rollback_cmds = ["execute cfg reload"]
            return config_cmds, commit_timer, confirm_cmds, rollback_cmds

        if vendor == VendorOS.PALOALTO_PANOS:
            snapshot = f"netlog-ai-{session_tag}.xml"
            config_cmds = ["configure", f"save config to {snapshot}", *body_commands, "validate full"]
            commit_timer = [
                f'commit description "netlog-ai {session_tag}"',
                f"# PAN-OS has no commit-confirmed timer: if post-checks fail within {rollback_minutes} min, "
                "run the rollback block",
            ]
            confirm_cmds = ["exit"]
            rollback_cmds = ["configure", f"load config from {snapshot}",
                             f'commit description "netlog-ai rollback {session_tag}"']
            return config_cmds, commit_timer, confirm_cmds, rollback_cmds

        if vendor == VendorOS.CISCO_SDWAN:
            # cEdge (IOS-XE SD-WAN) config-transaction / vEdge CLI. vManage
            # template-attached devices must be changed through vManage.
            config_cmds = ["config-transaction", *body_commands]
            commit_timer = [f"commit confirmed {rollback_minutes}"]
            confirm_cmds = ["config-transaction", "commit"]
            rollback_cmds = [
                "# let the commit-confirmed timer expire, or roll back now:",
                "config-transaction", "rollback configuration 0", "commit",
            ]
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
        elif vendor == VendorOS.FORTINET_FORTIOS:
            pre = ["diagnose sys sdwan member", "get router info bgp summary"]
            body = ["config system interface", f"    edit {interface}", "        set status down",
                    "    next", "end"]
            post = ["diagnose sys sdwan health-check", "get router info bgp summary"]
        elif vendor == VendorOS.PALOALTO_PANOS:
            pre = [f"show interface {interface}", "show routing protocol bgp summary"]
            body = [f"set network interface ethernet {interface} link-state down"]
            post = [f"show interface {interface}", "show routing protocol bgp summary"]
        elif vendor == VendorOS.CISCO_SDWAN:
            pre = ["show sdwan bfd sessions", "show sdwan control connections"]
            body = [f"interface {interface}", " shutdown"]
            post = ["show sdwan bfd sessions", "show sdwan control connections"]
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
        if vendor in _NO_QOS_TEMPLATE:
            raise SafetyViolationError(
                f"No vetted QoS/CoPP template for {vendor.value}; use a custom plan "
                "(local-in policy / zone protection / SD-WAN QoS) reviewed by an engineer."
            )
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
