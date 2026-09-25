"""Incident handoff cards must be paste-safe before they leave the host."""
from __future__ import annotations

import pytest

from ai_log_analyzer.analyzer import analyze
from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.handoff import incident_handoff

pytestmark = pytest.mark.unit


def test_handoff_strips_secret_and_public_ip_from_the_paste():
    card = incident_handoff({
        "score": 40,
        "grade": "F",
        "blast": {
            "epicenter": "edge-1",
            "estimated_impact": "peer 8.8.8.8 unreachable",
        },
        "change_window": {
            "detected": True,
            "count": 1,
            "devices": ["edge-1"],
            "samples": ["snmp-server community SuperSecret ro password 7 0123ABCD"],
        },
        "action_items": [{
            "severity": "critical",
            "description": "BGP down after password 7 99secret",
            "count": 3,
            "devices": ["edge-1"],
        }],
    })
    paste = card["paste"]
    assert "SuperSecret" not in paste
    assert "99secret" not in paste
    assert "0123ABCD" not in paste
    assert "8.8.8.8" not in paste
    assert "<REDACTED>" in paste
    assert card["redactions"] >= 1
    assert card["safe_to_share"] is True
    assert "raw syslog" in paste


def test_handoff_quiet_result_still_pastes():
    card = incident_handoff({"score": 100, "grade": "A"})
    assert "health 100/100" in card["paste"]
    assert "change window: none" in card["paste"]
    assert "actions:" in card["paste"]
    assert card["redactions"] == 0


def test_analyze_includes_handoff_card():
    result = analyze([
        LogEvent("2026-08-29T10:00:00", "rt-01", "mgd", "info",
                 "commit complete password 7 keep-me-out"),
        LogEvent("2026-08-29T10:00:02", "rt-01", "rpd", "err",
                 "bgp peer 10.0.0.1 down"),
    ], use_llm=False)
    card = result.to_dict()["handoff"]
    assert "keep-me-out" not in card["paste"]
    assert card["safe_to_share"] is True
    assert "rt-01" in card["paste"]
