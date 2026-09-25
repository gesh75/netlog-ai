"""Paste-ready incident handoff. Sanitized before it can leave the host.

NetBrain, Selector, Kentik, and ServiceNow post the incident story into Slack
or a ticket. The leak is the paste: syslog lines, SNMP communities, and type-7
passwords land in work notes. This card is the text an operator copies, built
only from the analysis summary, then run through the same sanitize gate as an
LLM prompt. Raw log bodies are not included.
"""
from __future__ import annotations

from typing import Any

from ai_log_analyzer.sanitize import sanitize_report
from ai_log_analyzer.work_shift import shift_brief, ticket_fields

_MAX_ACTIONS = 5


def _lines(result: dict[str, Any]) -> list[str]:
    blast = result.get("blast") or {}
    window = result.get("change_window") or {}
    lines = [
        "netlog-ai incident handoff",
        f"health {result.get('score', '?')}/100 grade {result.get('grade', '?')}",
        f"epicenter {blast.get('epicenter', '—')}",
        f"impact {blast.get('estimated_impact', 'unknown')}",
    ]
    if window.get("detected"):
        hosts = ", ".join(str(d) for d in (window.get("devices") or [])[:4]) or "unknown"
        lines.append(
            f"change window: {window.get('count', 0)} config event(s) on {hosts}"
        )
        for sample in (window.get("samples") or [])[:2]:
            lines.append(f"  commit: {sample}")
    else:
        lines.append("change window: none in this batch")
    lines.append("actions:")
    items = result.get("action_items") or []
    if not items:
        lines.append("  none")
    for item in items[:_MAX_ACTIONS]:
        devices = ", ".join(str(d) for d in (item.get("devices") or [])[:4]) or "n/a"
        lines.append(
            f"  [{item.get('severity', '?')}] {item.get('description', '')} "
            f"(×{item.get('count', 0)} on {devices})"
        )
    lines.append("Do not attach raw syslog. This card is the shareable text.")
    return lines


def incident_handoff(result: dict[str, Any]) -> dict[str, Any]:
    """Return a redacted paste card for a ticket or chat channel.

    ``result`` is ``AnalysisResult.to_dict()`` or the same shape. Never raises
    on a partial dict. ``paste`` is safe to copy; ``redactions`` is how many
    secret or public-IP spans were removed from that paste.
    """
    draft = "\n".join(_lines(result))
    report = sanitize_report(draft, mask_pii=True)
    notes = report["sanitized"]
    return {
        "paste": notes,
        "redactions": report["total"],
        "by_rule": report["by_rule"],
        "safe_to_share": True,
        "ticket": ticket_fields(result, notes),
        "brief": shift_brief(result),
    }
