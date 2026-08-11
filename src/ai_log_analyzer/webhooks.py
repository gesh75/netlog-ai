"""Severity-threshold webhook notifications for completed analyses.

Turns the analyzer from "paste logs, read report" into an always-on monitor:
when an analysis produces events at or above a severity threshold, a webhook
fires with the summary. Generic JSON POST by default; Slack incoming-webhook
payload supported.

Configuration (env, all optional — unset URL disables the feature):
    AI_LOG_ANALYZER_WEBHOOK_URL           destination URL
    AI_LOG_ANALYZER_WEBHOOK_MIN_SEVERITY  critical|high|medium|low (default high)
    AI_LOG_ANALYZER_WEBHOOK_FORMAT        generic|slack (default generic)

Delivery is best-effort: failures are logged and swallowed — an unreachable
webhook must never break an analysis response.
"""
from __future__ import annotations

import logging
import os
from typing import Any

import requests

from ai_log_analyzer.sanitize import sanitize

logger = logging.getLogger(__name__)

_SEV_RANK: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_TIMEOUT_S = 5
_MAX_ACTION_ITEMS = 5


def _sanitize_text(value: Any) -> str:
    """Remove secrets and PII from an analysis-derived payload field."""
    return sanitize(str(value), mask_pii=True)[0]


def _slack_text(value: Any) -> str:
    """Sanitize user-controlled text and disable Slack link/mention parsing."""
    return _sanitize_text(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _config() -> tuple[str, str, str]:
    url = os.environ.get("AI_LOG_ANALYZER_WEBHOOK_URL", "").strip()
    min_sev = os.environ.get("AI_LOG_ANALYZER_WEBHOOK_MIN_SEVERITY", "high").strip().lower()
    if min_sev not in _SEV_RANK:
        logger.warning("Invalid AI_LOG_ANALYZER_WEBHOOK_MIN_SEVERITY %r — using 'high'", min_sev)
        min_sev = "high"
    fmt = os.environ.get("AI_LOG_ANALYZER_WEBHOOK_FORMAT", "generic").strip().lower()
    if fmt not in ("generic", "slack"):
        logger.warning("Invalid AI_LOG_ANALYZER_WEBHOOK_FORMAT %r — using 'generic'", fmt)
        fmt = "generic"
    return url, min_sev, fmt


def should_notify(severity_counts: dict[str, int], min_severity: str) -> bool:
    """True when any event sits at or above the threshold severity."""
    threshold = _SEV_RANK.get(min_severity, 1)
    return any(
        count > 0 and _SEV_RANK.get(sev, 5) <= threshold
        for sev, count in severity_counts.items()
    )


def _alerting_counts(result: dict[str, Any], min_severity: str) -> dict[str, int]:
    threshold = _SEV_RANK.get(min_severity, 1)
    return {
        sev: n for sev, n in result.get("severity_counts", {}).items()
        if n > 0 and _SEV_RANK.get(sev, 5) <= threshold
    }


def build_payload(result: dict[str, Any], source: str, fmt: str, min_severity: str) -> dict[str, Any]:
    """Webhook body from an AnalysisResult.to_dict(). Carries only the
    summary + top action items — payloads stay small and post-sanitize."""
    top_actions = [
        {
            "severity": _sanitize_text(a.get("severity", "")),
            "category": _sanitize_text(a.get("category", "")),
            "description": _sanitize_text(a.get("description", "")),
            "count": a.get("count", 0),
            "devices": [_sanitize_text(device) for device in a.get("devices", [])[:5]],
        }
        for a in result.get("action_items", [])[:_MAX_ACTION_ITEMS]
    ]
    if fmt == "slack":
        alerting = _alerting_counts(result, min_severity)
        sev_line = ", ".join(f"{n} {sev}" for sev, n in alerting.items()) or "events"
        lines = [
            f":rotating_light: *netlog-ai* — {sev_line} from *{_slack_text(source)}* "
            f"(health {result.get('score', '?')}/100, grade {result.get('grade', '?')})"
        ]
        lines += [
            f"• [{_slack_text(a['severity']).upper()}] {_slack_text(a['description'])} "
            f"(×{a['count']} on {', '.join(_slack_text(d) for d in a['devices']) or 'n/a'})"
            for a in top_actions
        ]
        return {"text": "\n".join(lines)}
    return {
        "source": "netlog-ai",
        "event": "analysis_completed",
        "input": _sanitize_text(source),
        "score": result.get("score"),
        "grade": result.get("grade"),
        "severity_counts": result.get("severity_counts", {}),
        "action_items": top_actions,
        "generated_at": result.get("generated_at", ""),
    }


def notify_analysis(result: dict[str, Any], source: str) -> bool:
    """Fire the configured webhook for one analysis result.

    Returns True only when a notification was sent successfully. No-op
    (False) when unconfigured or below threshold; never raises.
    """
    url, min_sev, fmt = _config()
    if not url:
        return False
    if not should_notify(result.get("severity_counts", {}), min_sev):
        return False
    try:
        r = requests.post(url, json=build_payload(result, source, fmt, min_sev),
                          timeout=_TIMEOUT_S)
        if r.status_code >= 300:
            logger.warning("Webhook %s answered HTTP %s", url, r.status_code)
            return False
        return True
    except requests.RequestException as exc:
        logger.warning("Webhook delivery failed: %s", exc)
        return False
