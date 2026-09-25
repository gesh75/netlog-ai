"""Work-shift surfaces for a netlog analysis.

A ticket shape an operator can paste into ServiceNow, a one-page brief, and
the next read-only commands for IOS-XE, Aruba, and Meraki events. Nothing
here posts to a ticket system.
"""
from __future__ import annotations

from typing import Any

from ai_log_analyzer.kb import lookup, phase_cli_for
from ai_log_analyzer.sanitize import sanitize

_URGENCY = {"critical": "1 - High", "high": "1 - High", "medium": "2 - Medium"}
_MAX_COMMANDS = 3
_MAX_BRIEF_CHARS = 1200
# Read-only checks for the work edge. Matched on the classifier description.
_COMMANDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("access point", ("show ap summary", "show ap name <ap> config general", "show logging | include AP")),
    ("802.1x", ("show authentication sessions", "show aaa servers", "show logging | include DOT1X")),
    ("dhcp", ("show ip dhcp pool", "show ip dhcp binding", "show ip dhcp conflict")),
    ("wan uplink", ("show ip interface brief", "show track", "show ip route 0.0.0.0")),
    ("vpn", ("show crypto session", "show crypto isakmp sa", "show logging | include IKE")),
)


def _clean(value: object) -> str:
    return sanitize(str(value), mask_pii=True)[0]


def _top(result: dict[str, Any]) -> dict[str, Any]:
    items = result.get("action_items") or []
    return items[0] if items else {}


def next_commands(result: dict[str, Any], limit: int = _MAX_COMMANDS) -> list[str]:
    """Up to three read-only commands for the top action."""
    item = _top(result)
    if not item:
        return []
    description = str(item.get("description") or "").lower()
    for needle, commands in _COMMANDS:
        if needle in description:
            return [_clean(cmd) for cmd in commands[:limit]]
    entry = lookup(str(item.get("category") or ""), description)
    commands: list[str] = []
    for phase in entry.get("phases") or []:
        commands.extend(phase_cli_for(phase, "ios"))
        if len(commands) >= limit:
            break
    return [_clean(cmd) for cmd in commands[:limit]]


def ticket_fields(result: dict[str, Any], work_notes: str) -> dict[str, Any]:
    """ServiceNow-shaped fields. ``posted`` stays false — copy, do not send."""
    item = _top(result)
    blast = result.get("blast") or {}
    severity = str(item.get("severity") or "low")
    description = str(item.get("description") or "Network incident")
    short = description[:80]
    return {
        "short_description": _clean(short),
        "urgency": _URGENCY.get(severity, "3 - Low"),
        "configuration_item": _clean(blast.get("epicenter") or "unknown"),
        "work_notes": work_notes,
        "posted": False,
    }


def shift_brief(result: dict[str, Any]) -> str:
    """One page: what is down, the epicenter, the change window, next commands."""
    blast = result.get("blast") or {}
    window = result.get("change_window") or {}
    item = _top(result)
    devices = ", ".join(str(d) for d in (item.get("devices") or [])[:4]) or "n/a"
    if item:
        down = f"{item.get('description', 'event')} on {devices}"
    else:
        down = "nothing ranked"
    if window.get("detected"):
        hosts = ", ".join(str(d) for d in (window.get("devices") or [])[:4]) or "unknown"
        change = f"yes — {window.get('count', 0)} config event(s) on {hosts}"
    else:
        change = "no commit in this batch"
    lines = [
        "SHIFT BRIEF",
        f"Down: {down}",
        f"Epicenter: {blast.get('epicenter', '—')}",
        f"Change window: {change}",
        "Next commands:",
    ]
    commands = next_commands(result)
    if commands:
        lines.extend(f"  {i}. {cmd}" for i, cmd in enumerate(commands, start=1))
    else:
        lines.append("  none")
    for row in (result.get("repeat_offenders") or [])[:5]:
        lines.append(
            f"Repeat: {row.get('hostname')} {row.get('category')} "
            f"{row.get('count')} times in 7 days"
        )
    text = _clean("\n".join(lines))
    if len(text) > _MAX_BRIEF_CHARS:
        return text[: _MAX_BRIEF_CHARS - 1] + "…"
    return text
