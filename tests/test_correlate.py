"""Unit tests for cross-source device correlation (ai_log_analyzer.correlate)."""
from __future__ import annotations

import pytest

from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.correlate import correlate_sources


# ── helpers ──────────────────────────────────────────────────────────────────

def _bgp_down_event(hostname: str) -> LogEvent:
    """High-severity routing event (BGP peer down)."""
    return LogEvent("2026-05-09T10:00:00", hostname, "rpd", "err",
                    "bgp peer 10.0.0.1 down (hold timer expired)")


def _link_down_event(hostname: str) -> LogEvent:
    """High-severity interface event (link down)."""
    return LogEvent("2026-05-09T10:00:00", hostname, "mib2d", "err",
                    "snmp_trap_link_down ge-0/0/1")


def _link_up_event(hostname: str) -> LogEvent:
    """Medium-severity interface event (link up)."""
    return LogEvent("2026-05-09T10:00:00", hostname, "mib2d", "info",
                    "snmp_trap_link_up ge-0/0/2")


def _ssh_accepted_event(hostname: str) -> LogEvent:
    """Low-severity auth event (accepted publickey)."""
    return LogEvent("2026-05-09T10:00:00", hostname, "sshd", "info",
                    "accepted publickey for user admin")


# ── tests ────────────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_device_in_two_sources_is_confirmed():
    """A device with actionable events in >=2 sources must be 'confirmed'."""
    events_by_source = {
        "kibana": [_bgp_down_event("fra4-fw-01")],
        "librenms": [_link_down_event("fra4-fw-01")],
    }
    result = correlate_sources(events_by_source)

    assert result["ok"] is True
    assert result["confirmed_count"] == 1
    assert result["suspected_count"] == 0

    device = result["confirmed"][0]
    assert device["hostname"] == "fra4-fw-01"
    assert device["status"] == "confirmed"
    assert device["source_count"] == 2
    assert sorted(device["sources"]) == ["kibana", "librenms"]


@pytest.mark.unit
def test_device_in_one_source_is_suspected():
    """A device with actionable events in exactly 1 source must be 'suspected'."""
    events_by_source = {
        "kibana": [_bgp_down_event("fra4-fw-01")],
    }
    result = correlate_sources(events_by_source)

    assert result["ok"] is True
    assert result["confirmed_count"] == 0
    assert result["suspected_count"] == 1

    device = result["suspected"][0]
    assert device["status"] == "suspected"
    assert device["source_count"] == 1


@pytest.mark.unit
def test_short_hostname_intersection():
    """FQDN and short form of the same device must be correlated as ONE device."""
    events_by_source = {
        "kibana": [_bgp_down_event("fra4-fw-01.dc.example.com")],
        "librenms": [_link_down_event("fra4-fw-01")],
    }
    result = correlate_sources(events_by_source)

    # Should correlate as a single confirmed device.
    assert result["confirmed_count"] == 1
    assert result["suspected_count"] == 0
    assert result["confirmed"][0]["hostname"] == "fra4-fw-01"


@pytest.mark.unit
def test_low_and_info_events_excluded():
    """Low-severity events must not contribute to correlation (default medium threshold)."""
    events_by_source = {
        "kibana": [_ssh_accepted_event("fra4-fw-01")],
        "librenms": [_ssh_accepted_event("fra4-fw-01")],
    }
    result = correlate_sources(events_by_source)

    # The SSH event is low/auth — below the medium threshold.
    assert result["device_count"] == 0
    assert result["confirmed_count"] == 0
    assert result["suspected_count"] == 0


@pytest.mark.unit
def test_min_severity_high_drops_medium():
    """With min_severity='high', a medium event in the 2nd source must not count."""
    events_by_source = {
        "kibana": [_bgp_down_event("fra4-fw-01")],      # high
        "librenms": [_link_up_event("fra4-fw-01")],     # medium
    }
    result = correlate_sources(events_by_source, min_severity="high")

    # Only the 'kibana' high-sev event counts; librenms medium is excluded.
    assert result["confirmed_count"] == 0
    assert result["suspected_count"] == 1
    assert result["suspected"][0]["sources"] == ["kibana"]


@pytest.mark.unit
def test_worst_severity_and_sorting():
    """A device with critical events must sort before one with only mediums."""
    crit_event = LogEvent("2026-05-09T10:00:00", "fra4-sw-01", "kernel", "crit",
                          "kernel panic - not syncing")
    med_event = _link_up_event("fra4-rt-01")

    events_by_source = {
        "kibana": [crit_event, med_event],
        "librenms": [crit_event, med_event],
    }
    result = correlate_sources(events_by_source)

    assert result["confirmed_count"] == 2
    devices = result["confirmed"]
    # Critical device should be first.
    critical_device = next(d for d in devices if d["hostname"] == "fra4-sw-01")
    medium_device = next(d for d in devices if d["hostname"] == "fra4-rt-01")
    assert critical_device["worst_severity"] == "critical"
    assert medium_device["worst_severity"] == "medium"
    assert devices.index(critical_device) < devices.index(medium_device)


@pytest.mark.unit
def test_invalid_min_severity_raises():
    """Passing an unknown min_severity must raise ValueError."""
    with pytest.raises(ValueError, match="bogus"):
        correlate_sources({}, min_severity="bogus")


@pytest.mark.unit
def test_empty_input_returns_zero_counts():
    """An empty events_by_source dict must return a valid zero-count result."""
    result = correlate_sources({})

    assert result["ok"] is True
    assert result["device_count"] == 0
    assert result["confirmed_count"] == 0
    assert result["suspected_count"] == 0
    assert result["confirmed"] == []
    assert result["suspected"] == []
    assert result["devices"] == []


@pytest.mark.unit
def test_input_not_mutated():
    """correlate_sources must not mutate the caller's input dict or its lists."""
    original_event = _bgp_down_event("fra4-fw-01")
    original_list = [original_event]
    events_by_source = {"kibana": original_list}

    correlate_sources(events_by_source)

    # Dict structure and list contents must be identical.
    assert list(events_by_source.keys()) == ["kibana"]
    assert events_by_source["kibana"] is original_list
    assert events_by_source["kibana"] == [original_event]
