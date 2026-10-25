"""Vendor-safe remediation generator with automatic rollback guardrails.

Produces deterministic pre-checks, transactional configuration blocks with
auto-revert timers, post-checks, and explicit abort/rollback sequences across
Arista EOS, Juniper Junos, Cisco NX-OS, Cisco IOS-XE, FRRouting, Fortinet
FortiOS, Palo Alto PAN-OS and Cisco Catalyst SD-WAN.

Rollback semantics differ per platform and are stated in each plan:
Junos (`commit confirmed`), IOS-XE (`revert timer`) and EOS (session
`commit timer hh:mm:ss`) have a native confirm timer; SD-WAN uses `commit
confirmed` (verify on your platform); FRR relies on a host-side dead-man timer;
FortiOS revert mode restores the saved config by restarting the unit; NX-OS
(checkpoint) and PAN-OS (named snapshot) have no timer, so their plans roll
back manually by restoring the snapshot.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import secrets
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
# Each segment is matched twice: as written and in canonical form (lowercased,
# whitespace collapsed, leading `do `/`sudo ` removed, IOS-style unique-prefix
# abbreviations of the destructive verbs expanded: `rel` -> `reload`,
# `wr er` -> `write erase`, `cle ip bgp *` -> `clear ip bgp *`).
_BGP_AF = r"(?:vrf\s+\S+\s+|ipv[46]\s+(?:unicast|multicast|labeled-unicast)\s+(?:vrf\s+\S+\s+)?|vpnv[46]\s+unicast\s+|l2vpn\s+evpn\s+|all\s+)*"
_FORBIDDEN_CLI_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("erase_storage", re.compile(
        r"\b(?:write\s+erase|erase\s+(?:/\S+\s+)*(?:startup-config|[a-z0-9_-]+:)|"
        r"format\s+(?:/\S+\s+)*(?:flash|bootflash|disk\d*|usb\d*|nvram)(?::|\s|$))", re.IGNORECASE)),
    ("system_zeroize", re.compile(r"\brequest\s+(?:system|vmhost)\s+(?:zeroize|halt|power-off|reboot|snapshot\s+delete)\b", re.IGNORECASE)),
    ("crypto_zeroize", re.compile(r"^\s*crypto\s+key\s+zeroize\b", re.IGNORECASE)),
    ("unscoped_reload", re.compile(
        r"^\s*(?:sudo\s+(?:-\S+\s+)*)?(?:reload|reboot|halt|poweroff|shutdown\s+(?:-\S+|now|\+?\d)|init\s+[06]|telinit\s+[06]|"
        r"systemctl\s+(?:-\S+\s+)*(?:reboot|poweroff|halt|kexec))(?![\w-])", re.IGNORECASE)),
    ("wipe_bgp_asn", re.compile(r"^\s*no\s+router\s+(?:bgp|ospf|ospfv3|isis|eigrp|rip)\b", re.IGNORECASE)),
    ("no_feature", re.compile(r"^\s*no\s+feature\b", re.IGNORECASE)),
    ("delete_root_config", re.compile(r"^\s*delete\s*$", re.IGNORECASE)),
    # IOS / EOS file delete: `delete flash:startup-config`, `delete /force /recursive flash:`.
    ("delete_files", re.compile(r"^\s*delete\s+(?:/\S+\s+)+\S|^\s*delete\s+(?:\S*:\S*|startup-config\S*)", re.IGNORECASE)),
    # Junos: deleting a whole top-level stanza (≤1 qualifier, e.g. `delete protocols bgp`).
    ("delete_config_stanza", re.compile(r"^\s*delete\s+(?:protocols|routing-options|routing-instances|interfaces|security|system|policy-options|firewall|chassis)(?:\s+\S+)?\s*$", re.IGNORECASE)),
    # Junos: deleting a whole protocol group/area/instance (`delete protocols bgp group X`).
    ("delete_protocol_group", re.compile(r"^\s*delete\s+protocols\s+\S+(?:\s+(?:group|area|instance|peer-group)\s+\S+)?\s*$", re.IGNORECASE)),
    # Hard reset of every BGP session (soft refresh and `in`/`out` are allowed).
    # Junos `clear bgp neighbor` with no peer resets every session too.
    ("clear_all_bgp", re.compile(
        r"^\s*clear\s+(?:ip\s+|ipv6\s+)?bgp\s+(?:" + _BGP_AF + r"(?:neighbor\s+)?(?:\*|all|external)(?!\S)(?!.*\b(?:soft|in|out)\b)|neighbor\s*$)",
        re.IGNORECASE)),
    ("load_override", re.compile(r"^\s*load\s+(?:override|replace|factory-default)\b", re.IGNORECASE)),
    ("config_replace", re.compile(r"^\s*configure\s+replace\b", re.IGNORECASE)),
    # Overwriting the startup/running config from a file or URL (saving running -> startup is fine).
    ("copy_over_config", re.compile(r"^\s*copy\s+(?!running-config\b)\S+\s+(?:startup|running)-config\b", re.IGNORECASE)),
    # FortiOS / PAN-OS / SD-WAN platform resets, wipes and restarts.
    ("fortios_destructive", re.compile(r"^\s*execute\s+(?:factoryreset\w*|formatlogdisk|erase-disk|reboot|shutdown|restore\s+image)\b", re.IGNORECASE)),
    ("panos_destructive", re.compile(r"^\s*request\s+(?:system\s+private-data-reset|restart\s+system|shutdown\s+system)\b", re.IGNORECASE)),
    ("sdwan_destructive", re.compile(r"^\s*request\s+(?:software\s+reset|reset\s+all|platform\s+software\s+sdwan\s+software\s+reset)\b|^\s*reboot\s+now\b", re.IGNORECASE)),
    ("shell_wipe", re.compile(
        r"\brm\s+(?:-\S+\s+)*(?:-[a-z]*r[a-z]*|--recursive)\s+(?:-\S+\s+)*(?:/\*?|~/?\*?|"
        r"/(?:etc|var|boot|usr|bin|sbin|lib\w*|home|root|mnt|opt|srv|dev|sys|proc|flash)(?:/\S*)?)(?=\s|$)|"
        r"\bmkfs\b|\bdd\s+if=.*\bof=/dev/", re.IGNORECASE)),
]

_SEGMENT_SPLIT_RE = re.compile(r"\n|;|&&|\|\||\bvtysh\b|-c\s+")
_LINE_BREAK_RE = re.compile(r"[\r\x0b\x0c\x1c-\x1e\x85\u2028\u2029]")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0e-\x1b\x7f]")

# Leading-verb abbreviation tree: IOS / NX-OS / FortiOS / Junos accept any unique
# prefix, so `rel`, `wr er` or `cle ip bgp *` run the full command. name -> (min
# prefix length, children). Only verbs the denylist cares about are listed.
_Tree = dict[str, tuple[int, "_Tree"]]
_CLI_TREE: _Tree = {
    "reload": (3, {}), "reboot": (3, {}), "halt": (3, {}), "poweroff": (4, {}),
    "write": (2, {"erase": (1, {})}),
    "erase": (3, {}),
    "format": (4, {}),
    "delete": (3, {}),
    "copy": (3, {}),
    "configure": (4, {"replace": (3, {})}),
    "crypto": (3, {"key": (1, {"zeroize": (3, {})})}),
    "clear": (3, {"ip": (2, {"bgp": (2, {})}), "ipv6": (3, {"bgp": (2, {})}), "bgp": (2, {})}),
    "request": (3, {
        "system": (3, {"zeroize": (3, {}), "halt": (3, {}), "reboot": (3, {}), "power-off": (3, {}), "snapshot": (3, {})}),
        "vmhost": (4, {"zeroize": (3, {}), "halt": (3, {}), "reboot": (3, {}), "power-off": (3, {}), "snapshot": (3, {})}),
        "restart": (3, {"system": (3, {})}), "shutdown": (3, {"system": (3, {})}),
        "software": (4, {"reset": (3, {})}), "reset": (3, {"all": (3, {})}),
    }),
    "execute": (3, {"factoryreset": (4, {}), "formatlogdisk": (4, {}), "erase-disk": (4, {}), "reboot": (3, {}),
                    "shutdown": (3, {}), "restore": (3, {"image": (3, {})})}),
    "load": (3, {"override": (3, {}), "replace": (3, {}), "factory-default": (3, {})}),
}
_WRAPPER_RE = re.compile(r"^(?:do|sudo(?:\s+-\S+)*|nohup)\s+")

BLOCKED_CLI_PLACEHOLDER = "# BLOCKED by SafetyGuardrail ({rule}): command withheld — requires manual engineering review"


def _command_segments(cmd: str) -> list[str]:
    """Split one CLI string into the individual commands it would run."""
    text = _CONTROL_RE.sub("", _LINE_BREAK_RE.sub("\n", cmd or ""))
    parts = _SEGMENT_SPLIT_RE.split(text)
    return [p.strip().strip("'\"").strip() for p in parts if p and p.strip().strip("'\"").strip()]


def _canonical_segment(segment: str) -> str:
    """Lowercase, collapse whitespace, drop `do`/`sudo`, expand unique-prefix verb abbreviations."""
    text = " ".join(segment.lower().split())
    while True:
        stripped = _WRAPPER_RE.sub("", text, count=1)
        if stripped == text:
            break
        text = stripped
    tokens = text.split(" ")
    tree: _Tree = _CLI_TREE
    for i, tok in enumerate(tokens):
        hit = next((name for name, (minlen, _) in tree.items() if len(tok) >= minlen and name.startswith(tok)), None)
        if hit is None:
            break
        tokens[i] = hit
        tree = tree[hit][1]
        if not tree:
            break
    return " ".join(tokens)


# Pre/post checks run unattended before and after the change: read-only verbs only.
_READ_ONLY_VERBS = frozenset({"show", "sho", "display", "get", "diagnose", "ping", "ping6", "traceroute",
                              "traceroute6", "tracepath", "tracert"})
_READ_ONLY_EXEC = frozenset({"ping", "ping6", "ping-options", "traceroute", "traceroute6", "tracert"})
_QUOTED_RE = re.compile(r"\"[^\"]*\"|'[^']*'")
# Redirects, command substitution, and pipes into a shell / file writer.
_CHECK_UNSAFE_RE = re.compile(r"[`>]|\$\(|\|\s*(?:sh|bash|zsh|tee|redirect|save|append|xargs)\b", re.IGNORECASE)


class SafetyViolationError(ValueError):
    """Raised when a proposed remediation violates network safety guardrails."""


class PlanInputError(SafetyViolationError):
    """A caller-supplied parameter (device, interface, neighbor, timer) is malformed — a usage error."""


_NO_QOS_TEMPLATE = frozenset({VendorOS.FORTINET_FORTIOS, VendorOS.PALOALTO_PANOS, VendorOS.CISCO_SDWAN})

_DEVICE_RE = re.compile(r"^[A-Za-z0-9._:-]{1,255}$")
_INTERFACE_RE = re.compile(r"^[A-Za-z0-9._:/-]{1,64}$")
_PLAN_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
# Ansible host patterns that would widen `hosts:` beyond one device.
_ANSIBLE_GROUP_WORDS = frozenset({"all", "ungrouped"})
_CONTROL_TEXT_RE = re.compile(r"[\x00-\x1f\x7f\x85\u2028\u2029]+")


def clean_text(value: Any, limit: int = 500) -> str:
    """Single-line, control-character-free text for headers, comments and docstrings."""
    return _CONTROL_TEXT_RE.sub(" ", str(value if value is not None else "")).strip()[:limit]


def validate_device(device: Any) -> str:
    """Return ``device`` if it is a plain hostname / address, else raise SafetyViolationError."""
    text = device if isinstance(device, str) else ""
    if not _DEVICE_RE.match(text):
        raise PlanInputError(
            f"invalid device name {clean_text(device, 60)!r}: use 1-255 characters from A-Z a-z 0-9 . _ : - "
            "(no spaces, newlines, wildcards or quotes)")
    return text


def validate_ansible_host(device: str) -> str:
    """A device name safe to use as an Ansible ``hosts:`` pattern (exactly one inventory host)."""
    validate_device(device)
    if device.lower() in _ANSIBLE_GROUP_WORDS or device.startswith(("-", ".")):
        raise PlanInputError(f"device {device!r} would address more than one inventory host")
    if ":" in device:  # `a:b` is an Ansible union pattern; only a literal IPv6 address may contain ':'
        try:
            ipaddress.IPv6Address(device)
        except ValueError:
            raise PlanInputError(
                f"device {device!r} contains ':' (an Ansible host-pattern separator); use the inventory hostname") from None
    return device


def validate_interface(interface: Any) -> str:
    text = interface if isinstance(interface, str) else ""
    if not _INTERFACE_RE.match(text):
        raise PlanInputError(
            f"invalid interface name {clean_text(interface, 60)!r}: use 1-64 characters from A-Z a-z 0-9 . _ : / - "
            "(no spaces, newlines or quotes)")
    return text


def validate_neighbor_ip(value: Any) -> str | None:
    """Canonical BGP neighbor address, or None when not given."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        raise PlanInputError(f"invalid bgp_neighbor_ip {clean_text(value, 60)!r}: not an IPv4/IPv6 address") from None


def validate_plan_id(plan_id: Any) -> str:
    if not isinstance(plan_id, str) or not _PLAN_ID_RE.match(plan_id):
        raise PlanInputError(f"invalid plan id {clean_text(plan_id, 60)!r}")
    return plan_id


def _hhmmss(minutes: int) -> str:
    return f"{minutes // 60:02d}:{minutes % 60:02d}:00"


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
    # Raw change (no vendor transaction wrapper) and its inverse — used by the
    # Ansible / Nornir exporters. Child lines are indented under their parent.
    body_commands: list[str] = field(default_factory=list)
    inverse_commands: list[str] = field(default_factory=list)
    # Drain target, when known: lets the exporters assert on the post-check output.
    interface: str = ""
    bgp_neighbor_ip: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def _apply_heading(self) -> str:
        n = self.rollback_minutes
        if self.vendor == VendorOS.PALOALTO_PANOS:
            return f"No Native Auto-Revert — Manual Rollback Window {n}m"
        if self.vendor == VendorOS.FORTINET_FORTIOS:
            return f"Revert Mode — Unit Restarts on Saved Config in {n}m if Unsaved"
        if self.vendor == VendorOS.CISCO_NXOS:
            return "No Automatic Rollback — Checkpoint Only, Use the Manual Rollback Commands"
        if self.vendor == VendorOS.FRR:
            return f"Host Dead-Man Timer Restores the Backup in {n}m Unless Cancelled"
        if self.vendor == VendorOS.CISCO_SDWAN:
            return f"commit confirmed {n} — Verify Auto-Revert on Your Platform"
        return f"Auto-Reverts in {n}m if Unconfirmed"

    def _rollback_summary(self) -> str:
        """Vendor-accurate one-liner for the card header (no timer claimed where none exists)."""
        n = self.rollback_minutes
        if self.vendor in (VendorOS.JUNIPER_JUNOS, VendorOS.CISCO_IOS_XE, VendorOS.ARISTA_EOS):
            return f"**Auto-Rollback Timer:** `{n} min`"
        if self.vendor == VendorOS.FORTINET_FORTIOS:
            return f"**Auto-Rollback:** revert mode, `{n} min` (unit restarts on the saved config)"
        if self.vendor == VendorOS.FRR:
            return f"**Auto-Rollback:** host dead-man timer, `{n} min` (background job; verify it is running)"
        if self.vendor == VendorOS.CISCO_SDWAN:
            return f"**Auto-Rollback Timer:** `{n} min` (`commit confirmed`; verify on your platform)"
        return "**Auto-Rollback:** none — use the manual rollback commands (4b)"

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
            f"{self._rollback_summary()}\n"
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
        if isinstance(rollback_minutes, bool) or not isinstance(rollback_minutes, int):
            raise PlanInputError(f"rollback_minutes must be an integer, got {type(rollback_minutes).__name__}.")
        if not (cls.MIN_ROLLBACK_MINUTES <= rollback_minutes <= cls.MAX_ROLLBACK_MINUTES):
            raise PlanInputError(
                f"rollback_minutes ({rollback_minutes}) must be between "
                f"{cls.MIN_ROLLBACK_MINUTES} and {cls.MAX_ROLLBACK_MINUTES}."
            )

        for cmd in commands:
            if not isinstance(cmd, str):
                raise SafetyViolationError(f"command {cmd!r} is not a string")
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
        segments = _command_segments(cmd)
        for segment in [cmd, *segments, *(_canonical_segment(s) for s in segments)]:
            for rule_name, pattern in _FORBIDDEN_CLI_PATTERNS:
                if pattern.search(segment):
                    return rule_name
        return None

    @classmethod
    def read_only_violation(cls, cmd: str) -> str | None:
        """Why ``cmd`` is not an acceptable pre/post check (read-only verbs only), or None."""
        if not isinstance(cmd, str):
            return "not_a_string"
        rule = cls.violation(cmd)
        if rule:
            return rule
        if _CHECK_UNSAFE_RE.search(_QUOTED_RE.sub('""', cmd)):
            return "check_shell_metacharacters"
        for segment in _command_segments(cmd):
            canonical = _canonical_segment(segment)
            if canonical.startswith(("#", "!")):
                continue  # comment
            tokens = canonical.split()
            verb = tokens[0] if tokens else ""
            if verb in _READ_ONLY_VERBS:
                continue
            if verb == "execute" and len(tokens) > 1 and tokens[1] in _READ_ONLY_EXEC:
                continue
            if verb in ("exec", "exe") and len(tokens) > 1 and tokens[1] in _READ_ONLY_EXEC:
                continue
            return "not_read_only"
        return None

    @classmethod
    def validate_read_only(cls, commands: list[str] | tuple[str, ...], label: str = "check") -> None:
        """Raise unless every pre/post-check is a read-only command (show/display/get/ping...)."""
        for cmd in commands or []:
            rule = cls.read_only_violation(cmd)
            if rule:
                raise SafetyViolationError(
                    f"{label} '{cmd}' rejected ({rule}): pre/post checks may only use read-only commands "
                    f"({', '.join(sorted(_READ_ONLY_VERBS))}).")

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


_JUNOS_DRAIN_IN = "NETLOG-DRAIN-IN"
_JUNOS_DRAIN_OUT = "NETLOG-DRAIN-OUT"


def _drain_inverse(vendor: VendorOS, interface: str, bgp_neighbor_ip: str | None) -> list[str]:
    """Commands that undo ``build_graceful_link_drain`` (used for Ansible rescue)."""
    if vendor == VendorOS.JUNIPER_JUNOS:
        undo: list[str] = []
        if bgp_neighbor_ip:
            undo += [f"delete protocols bgp group UNDERLAY neighbor {bgp_neighbor_ip} import {_JUNOS_DRAIN_IN}",
                     f"delete protocols bgp group UNDERLAY neighbor {bgp_neighbor_ip} export {_JUNOS_DRAIN_OUT}"]
            undo += [f"delete policy-options policy-statement {_JUNOS_DRAIN_IN}",
                     f"delete policy-options policy-statement {_JUNOS_DRAIN_OUT}"]
        undo.append(f"delete interfaces {interface} disable")
        return undo
    if vendor == VendorOS.ARISTA_EOS:
        return [f"interface {interface}", "   no bgp session tracker", "   no shutdown"]
    if vendor == VendorOS.FORTINET_FORTIOS:
        return ["config system interface", f"    edit {interface}", "        set status up", "    next", "end"]
    if vendor == VendorOS.PALOALTO_PANOS:
        return [f"set network interface ethernet {interface} link-state auto"]
    return [f"interface {interface}", " no shutdown"]


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
            commit_timer = [f"commit timer {_hhmmss(rollback_minutes)}"]
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
            # `configure confirm` only stops the revert timer; it does not save to startup-config.
            confirm_cmds = ["configure confirm", "copy running-config startup-config"]
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

        # FRR (vtysh transactional snapshot + reload test). The backup name carries a
        # random suffix so a second plan for the same device/interface keeps its own .bak.
        session_tag = f"{session_tag}_{secrets.token_hex(3)}"
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

    @staticmethod
    def _drain_blast_notes(vendor: VendorOS, device: str, interface: str, bgp_neighbor_ip: str | None) -> str:
        note = f"Drains ECMP member {interface} on {device}; verify >=1 alternate spine path is Up."
        if vendor == VendorOS.JUNIPER_JUNOS:
            note += (" Assumes the peer already sits in BGP group UNDERLAY; the drain policies are appended after"
                     " any existing import/export policies on that neighbor.")
            if not bgp_neighbor_ip:
                note += (" No bgp_neighbor_ip given: no BGP policy drain, the interface is simply disabled and its"
                         " sessions drop immediately.")
        elif vendor == VendorOS.ARISTA_EOS:
            note += (" The EOS drain lines (`ip as-path access-list DRAIN`, `bgp session tracker`) are generic;"
                     " verify the syntax on your EOS release before applying.")
        return note

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
        validate_device(device)
        validate_interface(interface)
        bgp_neighbor_ip = validate_neighbor_ip(bgp_neighbor_ip)
        timer = self.default_rollback_minutes if rollback_minutes is None else rollback_minutes
        plan_id = self._make_plan_id(device, RemediationActionType.GRACEFUL_LINK_DRAIN, interface)
        session_tag = plan_id.replace("-", "_")

        if vendor == VendorOS.JUNIPER_JUNOS:
            pre = [
                'show interfaces ' + interface + ' extensive | match "error|flap|dbm"',
                "show bgp summary",
            ]
            # Self-contained: the drain policies are defined here, and only attached when
            # the peer address is known (no placeholder neighbor, no undefined policy).
            body = []
            if bgp_neighbor_ip:
                body += [
                    f"set policy-options policy-statement {_JUNOS_DRAIN_IN} term drain then local-preference 0",
                    f"set policy-options policy-statement {_JUNOS_DRAIN_IN} term drain then accept",
                    f"set policy-options policy-statement {_JUNOS_DRAIN_OUT} term drain then reject",
                    f"set protocols bgp group UNDERLAY neighbor {bgp_neighbor_ip} import {_JUNOS_DRAIN_IN}",
                    f"set protocols bgp group UNDERLAY neighbor {bgp_neighbor_ip} export {_JUNOS_DRAIN_OUT}",
                ]
            body.append(f"set interfaces {interface} disable")
            post = [
                f"show interfaces {interface} terse",
                "show bgp summary",
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
            body = [f"interface {interface}", " shutdown"]
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
            blast_radius_notes=self._drain_blast_notes(vendor, device, interface, bgp_neighbor_ip),
            body_commands=list(body),
            inverse_commands=_drain_inverse(vendor, interface, bgp_neighbor_ip),
            interface=interface,
            bgp_neighbor_ip=bgp_neighbor_ip or "",
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
        validate_device(device)
        validate_interface(interface)
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
            post = [f"show interfaces queue {interface} | match Policed", "show bfd session"]
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
            body = [f"interface {interface}", " priority-queue out"]
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
            body_commands=list(body),
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
        validate_device(device)
        timer = self.default_rollback_minutes if rollback_minutes is None else rollback_minutes
        SafetyGuardrail.validate(commands, timer)
        SafetyGuardrail.validate_read_only(pre_checks, "pre-check")
        SafetyGuardrail.validate_read_only(post_checks, "post-check")

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
            body_commands=list(commands),
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
