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


def test_change_window_devices_follow_earliest_timestamp_not_input_order():
    """analyze() may pass newest-first top_k ahead of reserved extras."""
    events = [
        _ce(timestamp="2026-08-29T09:56:54", category="config", severity="low",
            hostname="rt-02", description="Configuration change committed",
            sample_message="commit complete confirmed"),
        _ce(timestamp="2026-08-29T09:55:00", category="config", severity="low",
            hostname="rt-01", description="Configuration change committed",
            sample_message="commit complete confirmed"),
    ]
    cw = change_window(events)
    assert cw["detected"] is True
    assert cw["count"] == 2
    assert cw["devices"] == ["rt-01", "rt-02"]


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


def test_timeline_surfaces_later_storm_despite_flap_heavy_prefix():
    """23 leftover flaps + one trailing commit must still yield the storm.

    Commit-only eviction has a budget of 0 (keep ≥1 commit), so a
    trailing-config reset that only drops commits would leave the later
    BGP outage invisible behind the morning flaps.
    """
    events = [
        _ce(
            timestamp=f"2026-08-29T09:00:{i:02d}",
            category="interface",
            description="Interface link down",
            hostname="leaf-01",
        )
        for i in range(23)
    ]
    events.append(
        _ce(
            timestamp="2026-08-29T09:58:00",
            category="config",
            severity="low",
            description="Configuration change committed",
            hostname="rt-01",
        )
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
    assert any(n.get("category") == "config" and n.get("device") == "rt-01" for n in nodes)
    assert sum(
        1 for n in nodes
        if n.get("category") == "routing" and n.get("device") == "spine-01"
    ) >= 8


def test_timeline_surfaces_later_storm_when_commit_overflows_flap_cap():
    """24 leftover flaps + a commit after the cap must still yield the storm.

    trailing_config only resets the floor when a commit sits inside the
    prefix. Morning flaps that fill the cap leave that flag false, so the
    later commit is a pin candidate and the BGP storm stays hidden.
    """
    events = [
        _ce(
            timestamp=f"2026-08-29T09:00:{i:02d}",
            category="interface",
            description="Interface link down",
            hostname="leaf-01",
        )
        for i in range(24)
    ]
    events.append(
        _ce(
            timestamp="2026-08-29T09:58:00",
            category="config",
            severity="low",
            description="Configuration change committed",
            hostname="rt-01",
        )
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
    assert any(n.get("category") == "config" and n.get("device") == "rt-01" for n in nodes)
    assert sum(
        1 for n in nodes
        if n.get("category") == "routing" and n.get("device") == "spine-01"
    ) >= 8


def test_timeline_surfaces_later_storm_when_late_commit_follows_storm():
    """24 leftover flaps + a commit after the storm must still yield the storm.

    config_before_later only reset leftover flaps when a commit preceded
    the later outage. A flap-filled cap plus a late pin left that flag
    false, so the BGP storm stayed hidden behind morning flaps.
    """
    events = [
        _ce(
            timestamp=f"2026-08-29T09:00:{i:02d}",
            category="interface",
            description="Interface link down",
            hostname="leaf-01",
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
    events.append(
        _ce(
            timestamp="2026-08-29T10:05:00",
            category="config",
            severity="low",
            description="Configuration change committed",
            hostname="rt-01",
        )
    )
    nodes = build_timeline(events, limit=24)
    assert len(nodes) == 24
    assert any(n.get("category") == "config" and n.get("device") == "rt-01" for n in nodes)
    assert sum(
        1 for n in nodes
        if n.get("category") == "routing" and n.get("device") == "spine-01"
    ) >= 8


def test_timeline_surfaces_later_storm_when_leftover_flaps_overflow_cap():
    """32 leftover flaps + a later storm must still yield the storm.

    Resetting the leftover count still pulled chronological overflow
    first. Eight leftover flaps past the cap filled the floor, so the
    BGP storm stayed hidden (0 routing) even with a commit in the window.
    """
    events = [
        _ce(
            timestamp=f"2026-08-29T09:00:{i:02d}",
            category="interface",
            description="Interface link down",
            hostname="leaf-01",
        )
        for i in range(32)
    ]
    events.append(
        _ce(
            timestamp="2026-08-29T09:58:00",
            category="config",
            severity="low",
            description="Configuration change committed",
            hostname="rt-01",
        )
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
    assert any(n.get("category") == "config" and n.get("device") == "rt-01" for n in nodes)
    assert sum(
        1 for n in nodes
        if n.get("category") == "routing" and n.get("device") == "spine-01"
    ) >= 8


def test_timeline_surfaces_later_storm_despite_intermediate_leftover_category():
    """Overflow leftover + a mid-window hardware burst must not eat the floor.

    A category filter that accepts any non-leftover missing row would pull
    the hardware cluster first and leave the later BGP storm hidden.
    """
    events = [
        _ce(
            timestamp=f"2026-08-29T09:00:{i:02d}",
            category="interface",
            description="Interface link down",
            hostname="leaf-01",
        )
        for i in range(32)
    ]
    events.extend(
        _ce(
            timestamp=f"2026-08-29T09:30:{i:02d}",
            category="hardware",
            description="FPC / linecard error",
            hostname="leaf-02",
        )
        for i in range(10)
    )
    events.append(
        _ce(
            timestamp="2026-08-29T09:58:00",
            category="config",
            severity="low",
            description="Configuration change committed",
            hostname="rt-01",
        )
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
    assert any(n.get("category") == "config" and n.get("device") == "rt-01" for n in nodes)
    assert sum(
        1 for n in nodes
        if n.get("category") == "routing" and n.get("device") == "spine-01"
    ) >= 8


def test_timeline_surfaces_later_storm_with_rfc3164_leftover_overflow():
    """Syslog-stamped leftover overflow must still yield the later storm.

    fromisoformat fails on RFC3164/Junos stamps; a minute-prefix fallback
    treated every 1s flap as a new cluster and pulled a single leftover row.
    """
    events = [
        _ce(
            timestamp=f"Aug 29 09:00:{i:02d}",
            category="routing",
            description="BGP peer down / connect failure",
            hostname="spine-01",
        )
        for i in range(32)
    ]
    events.append(
        _ce(
            timestamp="Aug 29 09:58:00",
            category="config",
            severity="low",
            description="Configuration change committed",
            hostname="rt-01",
        )
    )
    events.extend(
        _ce(
            timestamp=f"Aug 29 10:00:{i:02d}",
            category="routing",
            severity="high",
            description="BGP peer down / connect failure",
            hostname="spine-01",
        )
        for i in range(20)
    )
    nodes = build_timeline(events, limit=24)
    assert len(nodes) == 24
    assert any(n.get("category") == "config" and n.get("device") == "rt-01" for n in nodes)
    assert sum(
        1 for n in nodes
        if n.get("t", "").startswith("Aug 29 10:00") and n.get("device") == "spine-01"
    ) >= 8


def test_timeline_surfaces_later_storm_despite_trailing_leftover_flaps():
    """A leftover-category burst after the storm must not steal the floor.

    Last-cluster selection treated afternoon interface flaps as the
    outage, so the 10:00 BGP storm stayed hidden (0 routing) even when
    the trailing leftover cluster was the same size as the storm.
    """
    events = [
        _ce(
            timestamp=f"2026-08-29T09:00:{i:02d}",
            category="interface",
            description="Interface link down",
            hostname="leaf-01",
        )
        for i in range(32)
    ]
    events.append(
        _ce(
            timestamp="2026-08-29T09:58:00",
            category="config",
            severity="low",
            description="Configuration change committed",
            hostname="rt-01",
        )
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
    events.extend(
        _ce(
            timestamp=f"2026-08-29T11:00:{i:02d}",
            category="interface",
            description="Interface link down",
            hostname="leaf-03",
        )
        for i in range(20)
    )
    nodes = build_timeline(events, limit=24)
    assert len(nodes) == 24
    assert any(n.get("category") == "config" and n.get("device") == "rt-01" for n in nodes)
    assert sum(
        1 for n in nodes
        if n.get("category") == "routing" and n.get("device") == "spine-01"
    ) >= 8


def test_timeline_surfaces_later_storm_when_leftover_flaps_abut_the_storm():
    """Leftover flaps that run up to the commit must not swallow the storm.

    The leftover-contiguous skip used only the 60s gap. Interface flaps
    at 09:58 plus BGP at 09:59 (typical flaps → commit → immediate
    outage) were treated as leftover overflow, so a leftover-category
    burst two minutes later stole the floor (0 routing).
    """
    events = [
        _ce(
            timestamp=f"2026-08-29T09:58:{i:02d}",
            category="interface",
            description="Interface link down",
            hostname="leaf-01",
        )
        for i in range(32)
    ]
    events.append(
        _ce(
            timestamp="2026-08-29T09:58:45",
            category="config",
            severity="low",
            description="Configuration change committed",
            hostname="rt-01",
        )
    )
    events.extend(
        _ce(
            timestamp=f"2026-08-29T09:59:{i:02d}",
            category="routing",
            severity="high",
            description="BGP peer down / connect failure",
            hostname="spine-01",
        )
        for i in range(20)
    )
    events.extend(
        _ce(
            timestamp=f"2026-08-29T10:01:{i:02d}",
            category="interface",
            description="Interface link down",
            hostname="leaf-03",
        )
        for i in range(20)
    )
    nodes = build_timeline(events, limit=24)
    assert len(nodes) == 24
    assert any(n.get("category") == "config" and n.get("device") == "rt-01" for n in nodes)
    assert sum(
        1 for n in nodes
        if n.get("category") == "routing" and n.get("device") == "spine-01"
    ) >= 8


def test_timeline_surfaces_later_storm_when_leftover_resumes_before_storm():
    """Leftover flaps that resume after a commit gap must not swallow the storm.

    The leftover-contiguous skip required a <60s gap from the last leftover
    in the prefix. A trailing commit opened that gap, so leftover flaps
    that resumed immediately before the BGP storm headed the later cluster
    and filled the floor (0 routing).
    """
    events = [
        _ce(
            timestamp=f"2026-08-29T09:00:{i:02d}",
            category="interface",
            description="Interface link down",
            hostname="leaf-01",
        )
        for i in range(32)
    ]
    events.append(
        _ce(
            timestamp="2026-08-29T09:58:00",
            category="config",
            severity="low",
            description="Configuration change committed",
            hostname="rt-01",
        )
    )
    events.extend(
        _ce(
            timestamp=f"2026-08-29T10:00:{i:02d}",
            category="interface",
            description="Interface link down",
            hostname="leaf-02",
        )
        for i in range(8)
    )
    events.extend(
        _ce(
            timestamp=f"2026-08-29T10:00:{i:02d}",
            category="routing",
            severity="high",
            description="BGP peer down / connect failure",
            hostname="spine-01",
        )
        for i in range(10, 30)
    )
    nodes = build_timeline(events, limit=24)
    assert len(nodes) == 24
    assert any(n.get("category") == "config" and n.get("device") == "rt-01" for n in nodes)
    assert sum(
        1 for n in nodes
        if n.get("category") == "routing" and n.get("device") == "spine-01"
    ) >= 8


def test_timeline_surfaces_later_storm_despite_larger_intermediate_hardware():
    """A larger mid-window hardware burst must not eat the floor.

    Largest-cluster selection would pull 25 hardware rows and hide the
    later 20-event BGP storm. Last non-leftover cluster keeps the storm.
    """
    events = [
        _ce(
            timestamp=f"2026-08-29T09:00:{i:02d}",
            category="interface",
            description="Interface link down",
            hostname="leaf-01",
        )
        for i in range(32)
    ]
    events.extend(
        _ce(
            timestamp=f"2026-08-29T09:30:{i:02d}",
            category="hardware",
            description="FPC / linecard error",
            hostname="leaf-02",
        )
        for i in range(25)
    )
    events.append(
        _ce(
            timestamp="2026-08-29T09:58:00",
            category="config",
            severity="low",
            description="Configuration change committed",
            hostname="rt-01",
        )
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
    assert any(n.get("category") == "config" and n.get("device") == "rt-01" for n in nodes)
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


def test_analyze_change_window_keeps_earliest_commit_per_device():
    """Later config noise on another host must not hide the causative commit.

    The newest-50 reserve alone evicts rt-01's 09:55 commit once rt-02
    emits 50+ later commits, so change_window names the wrong device
    while blast.epicenter stays on the storm host.
    """
    events = [
        LogEvent("2026-08-29T09:55:00", "rt-01", "mgd", "info",
                 "commit complete confirmed"),
    ]
    events.extend(
        LogEvent(
            f"2026-08-29T09:56:{i:02d}", "rt-02", "mgd", "info",
            "commit complete confirmed",
        )
        for i in range(55)
    )
    events.extend(
        LogEvent(
            "2026-08-29T10:00:00", "rt-01", "rpd", "err",
            f"bgp peer 192.0.2.{i % 200} down",
        )
        for i in range(350)
    )
    result = analyze(events, use_llm=False)
    assert result.change_window["detected"] is True
    assert "rt-01" in result.change_window["devices"]
    assert result.change_window["devices"][0] == "rt-01"
    assert result.blast["epicenter"] == "rt-01"
    assert any(
        "Change window" in b and "rt-01" in b for b in result.executive_summary
    )
    assert any(
        n.get("category") == "config" and n.get("device") == "rt-01"
        for n in result.timeline
    )
    # After #39 the timeline floor must still surface the storm; the
    # earliest-per-host reserve must not refill the cap with rt-02 commits.
    assert any(n.get("category") == "routing" for n in result.timeline)
    assert sum(1 for n in result.timeline if n.get("category") != "config") >= 8
    assert all(e.category != "config" for e in result.classified_events)


def test_analyze_change_window_names_earliest_host_when_configs_survive_top_k():
    """No storm: top_k keeps configs newest-first and would name rt-02 first."""
    events = [
        LogEvent("2026-08-29T09:55:00", "rt-01", "mgd", "info",
                 "commit complete confirmed"),
    ]
    events.extend(
        LogEvent(
            f"2026-08-29T09:56:{i:02d}", "rt-02", "mgd", "info",
            "commit complete confirmed",
        )
        for i in range(55)
    )
    result = analyze(events, use_llm=False)
    assert result.change_window["detected"] is True
    assert result.change_window["devices"][0] == "rt-01"
    assert "rt-02" in result.change_window["devices"]
    assert any(
        "Change window" in b and b.find("rt-01") < b.find("rt-02")
        for b in result.executive_summary
    )


def test_analyze_change_window_pins_first_arrival_on_timestamp_tie():
    """Same-second commits: the pin must keep the first arrival, not -seq."""
    events = [
        LogEvent("2026-08-29T09:55:00", "rt-01", "mgd", "info",
                 "commit complete confirmed FIRST"),
        LogEvent("2026-08-29T09:55:00", "rt-01", "mgd", "info",
                 "commit complete confirmed SECOND"),
    ]
    events.extend(
        LogEvent(
            f"2026-08-29T09:56:{i:02d}", "rt-02", "mgd", "info",
            "commit complete confirmed",
        )
        for i in range(55)
    )
    events.extend(
        LogEvent(
            "2026-08-29T10:00:00", "rt-01", "rpd", "err",
            f"bgp peer 192.0.2.{i % 200} down",
        )
        for i in range(350)
    )
    result = analyze(events, use_llm=False)
    assert result.change_window["devices"][0] == "rt-01"
    samples = " ".join(result.change_window["samples"])
    assert "FIRST" in samples
    assert "SECOND" not in samples


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
