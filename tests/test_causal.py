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
    assert payload["change_window"]["count"] == 1
    assert "by_rule" in payload["sanitize_diff"]
    assert any("Change window" in b for b in payload["executive_summary"])


def test_timeline_keeps_late_config_under_display_cap():
    """A commit after 24+ earlier flaps must still appear on the timeline."""
    events = [
        _ce(timestamp=f"2026-08-29T10:00:{i:02d}") for i in range(30)
    ]
    events.append(_ce(
        timestamp="2026-08-29T10:01:00", category="config", severity="low",
        hostname="rt-01", description="Configuration change committed",
    ))
    nodes = build_timeline(events, limit=24)
    assert len(nodes) == 24
    assert any(n.get("category") == "config" for n in nodes)
    assert nodes[-1]["device"] == "rt-01"
    assert nodes[-1]["category"] == "config"


def test_timeline_pin_keeps_last_incident_row():
    """A config-heavy prefix must not evict every flap to pin late commits."""
    events = [
        _ce(
            timestamp=f"2026-08-29T10:00:{i:02d}",
            category="config",
            severity="low",
            description="Configuration change committed",
            hostname="rt-01",
        )
        for i in range(20)
    ]
    events.extend(_ce(timestamp=f"2026-08-29T10:00:{20 + i:02d}") for i in range(4))
    events.extend(
        _ce(
            timestamp=f"2026-08-29T10:01:{i:02d}",
            category="config",
            severity="low",
            description="Configuration change committed",
            hostname="rt-02",
        )
        for i in range(6)
    )
    nodes = build_timeline(events, limit=24)
    assert len(nodes) == 24
    assert any(n.get("category") != "config" for n in nodes)
    assert any(n.get("device") == "rt-02" for n in nodes)


def test_timeline_surfaces_incidents_after_config_flood():
    """24+ earlier commits must not hide the BGP storm that follows.

    PR #37 pinned late config into an incident-heavy prefix. The inverse
    — a maintenance burst that fills the chronological cap — used to
    render an all-config timeline while action items still named the
    outage.
    """
    events = [
        _ce(
            timestamp=f"2026-08-29T09:58:{i:02d}",
            category="config",
            severity="low",
            description="Configuration change committed",
            hostname="rt-01",
        )
        for i in range(30)
    ]
    events.extend(
        _ce(
            timestamp=f"2026-08-29T10:00:{i:02d}",
            category="routing",
            severity="high",
            description="BGP peer down / connect failure",
            hostname="spine-01",
        )
        for i in range(20)
    )
    nodes = build_timeline(events, limit=24)
    assert len(nodes) == 24
    assert any(n.get("category") == "config" for n in nodes)
    assert any(n.get("category") == "routing" and n.get("device") == "spine-01" for n in nodes)
    assert sum(1 for n in nodes if n.get("category") != "config") >= 8


def test_timeline_surfaces_later_storm_despite_early_flaps():
    """Old flaps + a trailing commit burst must not hide the later storm.

    A count-only floor would treat leftover interface flaps as already
    showing the outage and keep the chronological commit tail, dropping
    the routing failure that follows the configs.
    """
    events = [
        _ce(
            timestamp=f"2026-08-29T09:00:{i:02d}",
            category="interface",
            description="Interface link down",
            hostname="leaf-01",
        )
        for i in range(10)
    ]
    events.extend(
        _ce(
            timestamp=f"2026-08-29T09:58:{i:02d}",
            category="config",
            severity="low",
            description="Configuration change committed",
            hostname="rt-01",
        )
        for i in range(20)
    )
    events.extend(
        _ce(
            timestamp=f"2026-08-29T10:00:{i:02d}",
            category="routing",
            severity="high",
            description="BGP peer down / connect failure",
            hostname="spine-01",
        )
        for i in range(20)
    )
    nodes = build_timeline(events, limit=24)
    assert len(nodes) == 24
    assert any(n.get("category") == "config" for n in nodes)
    assert sum(
        1 for n in nodes
        if n.get("category") == "routing" and n.get("device") == "spine-01"
    ) >= 8


def test_timeline_floor_swaps_late_commits_not_the_storm():
    """After flooring later incidents, pin true late commits by swapping
    remaining early commits — do not evict the outage just surfaced.
    """
    events = [
        _ce(
            timestamp=f"2026-08-29T09:58:{i:02d}",
            category="config",
            severity="low",
            description="Configuration change committed",
            hostname="rt-01",
        )
        for i in range(24)
    ]
    events.extend(
        _ce(
            timestamp=f"2026-08-29T10:00:{i:02d}",
            category="routing",
            severity="high",
            description="BGP peer down / connect failure",
            hostname="spine-01",
        )
        for i in range(20)
    )
    events.extend(
        _ce(
            timestamp=f"2026-08-29T10:05:{i:02d}",
            category="config",
            severity="low",
            description="Configuration change committed",
            hostname="rt-02",
        )
        for i in range(6)
    )
    nodes = build_timeline(events, limit=24)
    assert len(nodes) == 24
    assert sum(1 for n in nodes if n.get("category") != "config") >= 8
    assert any(n.get("device") == "rt-01" and n.get("category") == "config" for n in nodes)
    assert any(n.get("device") == "rt-02" and n.get("category") == "config" for n in nodes)


def _storm_with_commit(commit_ts: str, storm_ts: str) -> list[LogEvent]:
    events = [
        LogEvent(commit_ts, "rt-01", "mgd", "info",
                 "commit complete confirmed"),
    ]
    events.extend(
        LogEvent(
            storm_ts, "spine-01", "rpd", "err",
            f"bgp peer 192.0.2.{i % 200} down",
        )
        for i in range(350)
    )
    return events


def test_analyze_change_window_survives_severity_cap():
    """Config commits are low-severity; a 300+ storm must not hide them.

    The 0.6 causal console treats a commit inside the window as
    change-induced. If analyze() only feeds the severity-priority top_k
    into change_window/timeline, a fabric-wide BGP flap produces a false
    negative on the headline signal.
    """
    result = analyze(
        _storm_with_commit("2026-08-29T09:59:00", "2026-08-29T10:00:00"),
        use_llm=False,
    )
    assert result.change_window["detected"] is True
    assert result.change_window["count"] == 1
    assert "rt-01" in result.change_window["devices"]
    assert any("Change window" in b for b in result.executive_summary)
    assert any(n.get("category") == "config" for n in result.timeline)
    # classified_events stays the severity-priority top-300 contract
    assert all(e.category != "config" for e in result.classified_events)


def test_analyze_late_commit_survives_severity_and_timeline_caps():
    """A commit after the flap must still set change_window and the timeline.

    The severity heap keeps newest-timestamp config rows, so change_window
    already saw this case. The timeline display cap is chronological and
    would otherwise render 24 earlier BGP rows and hide the commit.
    """
    result = analyze(
        _storm_with_commit("2026-08-29T10:01:00", "2026-08-29T10:00:00"),
        use_llm=False,
    )
    assert result.change_window["detected"] is True
    assert result.change_window["count"] == 1
    assert "rt-01" in result.change_window["devices"]
    assert any("Change window" in b for b in result.executive_summary)
    assert any(n.get("category") == "config" for n in result.timeline)
    assert all(e.category != "config" for e in result.classified_events)


def test_analyze_timeline_keeps_storm_after_config_flood():
    """A 24+ commit burst before a BGP storm must still render the outage.

    change_window correctly fires on the commits. The timeline used to
    show only those commits because they sort first and fill the cap.
    """
    events = [
        LogEvent(
            f"2026-08-29T09:58:{i:02d}", "rt-01", "mgd", "info",
            "commit complete confirmed",
        )
        for i in range(30)
    ]
    events.extend(
        LogEvent(
            "2026-08-29T10:00:00", "spine-01", "rpd", "err",
            f"bgp peer 192.0.2.{i % 200} down",
        )
        for i in range(350)
    )
    result = analyze(events, use_llm=False)
    assert result.change_window["detected"] is True
    assert any(n.get("category") == "config" for n in result.timeline)
    assert any(n.get("category") == "routing" for n in result.timeline)
    assert any("BGP" in (n.get("title") or "") for n in result.timeline)
    assert sum(1 for n in result.timeline if n.get("category") != "config") >= 8
    assert all(e.category != "config" for e in result.classified_events)
