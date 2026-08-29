"""Causal console: timeline, blast radius, change-window correlator."""
from __future__ import annotations

import pytest

from ai_log_analyzer.analyzer import ActionItem, analyze
from ai_log_analyzer.causal import blast_radius, build_timeline, change_window
from ai_log_analyzer.classifier import ClassifiedEvent, LogEvent


pytestmark = pytest.mark.unit


def _ce(**kw) -> ClassifiedEvent:
    defaults = dict(
        timestamp="2026-08-29T10:00:00",
        hostname="spine-01",
        appname="rpd",
        severity="high",
        severity_raw="err",
        category="routing",
        description="BGP peer down / connect failure",
        action="check",
        message="bgp peer 10.0.0.1 down",
        sample_message="bgp peer 10.0.0.1 down",
        confidence=0.9,
    )
    defaults.update(kw)
    return ClassifiedEvent(**defaults)


def test_timeline_orders_chronologically_and_links_linkdown_to_bgp():
    events = [
        _ce(timestamp="2026-08-29T10:01:00", description="BGP peer down / connect failure",
            category="routing", hostname="spine-01"),
        _ce(timestamp="2026-08-29T10:00:00", description="Interface link down",
            category="interface", hostname="leaf-01", severity="high"),
    ]
    nodes = build_timeline(events)
    assert [n["t"] for n in nodes] == ["2026-08-29T10:00:00", "2026-08-29T10:01:00"]
    assert nodes[1]["cause_of"] == "Interface link down"


def test_timeline_links_config_commit_to_critical():
    events = [
        _ce(timestamp="2026-08-29T10:00:00", category="config", severity="low",
            description="Configuration change committed", hostname="rt-01"),
        _ce(timestamp="2026-08-29T10:00:05", category="system", severity="critical",
            description="Kernel panic / core dump — OS failure", hostname="rt-01"),
    ]
    nodes = build_timeline(events)
    assert nodes[1]["cause_of"] == "Configuration change committed"


def test_blast_radius_names_epicenter_and_devices():
    items = [
        ActionItem("critical", "system", "Kernel panic / core dump — OS failure",
                   2, ["rt-01", "rt-02"], ["kernel panic"]),
        ActionItem("high", "routing", "BGP peer down / connect failure",
                   4, ["rt-01", "spine-01"], ["bgp down"]),
    ]
    blast = blast_radius(items)
    assert blast["epicenter"] == "rt-01"
    assert blast["device_count"] == 3
    assert "rt-01" in blast["devices"] and "spine-01" in blast["devices"]
    assert "system" in blast["categories"]
    assert "epicenter rt-01" in blast["estimated_impact"].lower()


def test_blast_radius_quiet_when_no_actions():
    blast = blast_radius([])
    assert blast["epicenter"] == "—"
    assert blast["device_count"] == 0
    assert "quiet" in blast["estimated_impact"].lower()


def test_change_window_detects_config_commits():
    events = [
        _ce(category="config", description="Configuration change committed",
            hostname="rt-01", sample_message="mgd: commit complete"),
        _ce(category="routing", description="BGP peer down / connect failure", hostname="rt-01"),
    ]
    cw = change_window(events)
    assert cw["detected"] is True
    assert cw["count"] == 1
    assert cw["devices"] == ["rt-01"]


def test_change_window_quiet_without_commits():
    cw = change_window([_ce()])
    assert cw["detected"] is False
    assert cw["count"] == 0


def test_analyze_exposes_causal_fields():
    events = [
        LogEvent("2026-08-29T10:00:00", "rt-01", "mgd", "info",
                 "commit complete confirmed"),
        LogEvent("2026-08-29T10:00:02", "rt-01", "rpd", "err",
                 "bgp peer 10.0.0.1 down"),
        LogEvent("2026-08-29T10:00:03", "rt-01", "kernel", "crit",
                 "kernel panic - not syncing"),
    ]
    result = analyze(events, use_llm=False)
    payload = result.to_dict()
    assert payload["timeline"]
    assert payload["blast"]["epicenter"]
    assert payload["change_window"]["detected"] is True
    assert "by_rule" in payload["sanitize_diff"]
    assert any("Change window" in b for b in payload["executive_summary"])
