"""analyze(): bounded correlation pool, health score, device counts, blast
epicenter, causal timeline links and timestamp parsing cost."""
from __future__ import annotations

from datetime import datetime

import pytest

from ai_log_analyzer import causal
from ai_log_analyzer.analyzer import ActionItem, _finalize_action_items, _group_actionable, analyze
from ai_log_analyzer.causal import blast_radius, build_timeline
from ai_log_analyzer.classifier import ClassifiedEvent, LogEvent

pytestmark = pytest.mark.unit

LINK_DOWN = "SNMP_TRAP_LINK_DOWN: ifIndex 511, ifAdminStatus up(1), ifOperStatus down(2), ifName {ifname}"
LINK_UP = "SNMP_TRAP_LINK_UP: ifIndex 511, ifAdminStatus up(1), ifOperStatus up(1), ifName {ifname}"
BGP_DOWN = ("RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer {peer} (External AS {asn}) changed state from "
            "Established to Idle (event HoldTime) (instance master)")


def _lg(second: int, host: str, msg: str, sev: str = "err") -> LogEvent:
    stamp = f"2026-10-20T{10 + second // 3600:02d}:{second % 3600 // 60:02d}:{second % 60:02d}Z"
    return LogEvent(stamp, host, "mib2d", sev, msg)


def _ce(**kw) -> ClassifiedEvent:
    base = dict(timestamp="2026-08-29T10:00:00", hostname="spine-01", appname="rpd", severity="high",
                severity_raw="err", category="routing", description="BGP peer down / connect failure",
                action="check", message="m", sample_message="m")
    base.update(kw)
    return ClassifiedEvent(**base)


# ── bounded pool, end to end ────────────────────────────────────────────────

def test_storm_noise_does_not_starve_a_later_real_incident():
    noise = [_lg(i, "sw1", LINK_DOWN.format(ifname=f"et-0/0/{i % 100}")) for i in range(2500)]
    real = [_lg(3000, "leaf-a", BGP_DOWN.format(peer="10.9.0.1", asn=65001)),
            _lg(3004, "leaf-b", BGP_DOWN.format(peer="10.9.0.2", asn=65002))]
    result = analyze(noise + real, use_llm=False).to_dict()
    corr = result["entity_correlation"]
    assert any(set(i["devices"]) == {"leaf-a", "leaf-b"} for i in corr["incidents"])
    assert corr["dropped"] == 0
    assert "bounded" in corr["warning"] and corr["collapsed"] > 0
    assert result["suppression"]["warning"] == corr["warning"]
    assert any("bounded" in line for line in result["executive_summary"])


def test_small_runs_carry_no_pool_warning():
    result = analyze([_lg(1, "sw1", LINK_DOWN.format(ifname="et-0/0/1"))], use_llm=False).to_dict()
    assert "warning" not in result["entity_correlation"] and "warning" not in result["suppression"]


# ── health score counts incidents, not events ───────────────────────────────

def test_a_port_that_flapped_and_recovered_is_not_ten_outages():
    events = []
    for i in range(10):
        events.append(_lg(i * 4, "sw1", LINK_DOWN.format(ifname="et-0/0/1")))
        events.append(_lg(i * 4 + 2, "sw1", LINK_UP.format(ifname="et-0/0/1"), "notice"))
    result = analyze(events, use_llm=False)
    assert result.severity_counts["high"] == 10          # raw event counts are unchanged
    assert result.score >= 95 and result.grade == "A"


def test_many_distinct_failed_entities_still_lower_the_score():
    events = [_lg(i, "sw1", LINK_DOWN.format(ifname=f"et-0/0/{i}")) for i in range(15)]
    result = analyze(events, use_llm=False)
    assert result.score <= 72


def test_repeated_events_on_one_down_entity_count_once():
    one = analyze([_lg(i, "sw1", LINK_DOWN.format(ifname="et-0/0/1")) for i in range(1, 30)], use_llm=False)
    assert one.score >= 97


# ── device counts and blast epicenter ───────────────────────────────────────

def test_action_item_reports_the_true_device_count_beyond_the_display_cap():
    events = [_lg(i, f"leaf-{i:02d}", BGP_DOWN.format(peer=f"10.{i}.0.1", asn=65000 + i)) for i in range(15)]
    result = analyze(events, use_llm=False)
    item = next(a for a in result.action_items if "BGP" in a.description)
    assert len(item.devices) == 10 and item.device_count == 15
    assert item.to_dict()["device_count"] == 15
    assert result.blast["device_count"] == 15 and "15 devices" in result.blast["estimated_impact"]


def test_blast_epicenter_is_the_incident_root_not_the_first_alphabetical_device():
    events = [_lg(0, "zzz-core", BGP_DOWN.format(peer="10.9.0.1", asn=65001)),
              _lg(6, "aaa-leaf", BGP_DOWN.format(peer="10.9.0.2", asn=65002))]
    result = analyze(events, use_llm=False)
    assert result.action_items[0].devices[0] == "aaa-leaf"      # what the old guess would name
    assert result.blast["epicenter"] == "zzz-core"
    assert "Epicenter zzz-core" in result.blast["estimated_impact"]


def test_blast_radius_prefers_an_explicit_root_and_falls_back_without_one():
    items = [ActionItem("high", "routing", "BGP peer down / connect failure", 4, ["aaa", "zzz"], ["m"])]
    assert blast_radius(items)["epicenter"] == "aaa"
    rooted = blast_radius(items, None, {"hostname": "zzz", "description": "Interface link down"})
    assert rooted["epicenter"] == "zzz" and "Interface link down".lower() in rooted["estimated_impact"]


# ── suppression status does not depend on the display sample ────────────────

def _bucket_with(entities, plain=(), capped=False):
    return {"severity": "high", "category": "routing", "description": "BGP peer down / connect failure",
            "count": 5, "devices": {"a"}, "msg_heap": [(" ", -1, "m")], "entities": set(entities),
            "plain": set(plain), "capped": capped}


def test_suppressed_by_needs_every_event_judged_not_just_the_sample():
    ents = {("a", "bgp", "default|10.0.0.1")}
    suppressed = {e: "ROOT-1" for e in ents}
    key = ("high", "BGP peer down / connect failure")
    ok = _finalize_action_items({key: _bucket_with(ents)}, 0, None, suppressed)
    assert ok[0].suppressed_by == "ROOT-1"
    for bucket in (_bucket_with(ents, capped=True), _bucket_with(ents, plain={"b"})):
        assert _finalize_action_items({key: bucket}, 0, None, suppressed)[0].suppressed_by == ""


def test_group_actionable_marks_a_group_capped_when_entities_overflow(monkeypatch):
    monkeypatch.setattr("ai_log_analyzer.analyzer._MAX_GROUP_ENTITIES", 2)
    seen: dict = {}
    for i in range(3):
        _group_actionable(_ce(), seen, i, ("a", "bgp", f"p{i}"))
    (bucket,) = seen.values()
    assert bucket["capped"] is True and len(bucket["entities"]) == 2


# ── causal timeline links need a shared device or entity ────────────────────

def test_timeline_does_not_blame_another_devices_link_down():
    events = [_ce(timestamp="2026-08-29T10:00:00", description="Interface link down", category="interface",
                  hostname="swA", event_type="interface_link", interface="Gi1"),
              _ce(timestamp="2026-08-29T10:00:30", description="BGP hold timer expired", hostname="rtrB",
                  event_type="bgp_session", peer_ip="192.0.2.9")]
    assert "cause_of" not in build_timeline(events)[1]


def test_timeline_keeps_the_link_when_the_devices_share_an_address():
    events = [_ce(timestamp="2026-08-29T10:00:00", description="Interface link down", category="interface",
                  hostname="swA", event_type="interface_link", interface="Gi1", peer_ip="10.0.0.1",
                  attrs={"locip": "10.0.0.2"}),
              _ce(timestamp="2026-08-29T10:00:30", description="BGP hold timer expired", hostname="rtrB",
                  event_type="bgp_session", peer_ip="10.0.0.2")]
    assert build_timeline(events)[1]["cause_of"] == "Interface link down"


# ── timestamp parsing ───────────────────────────────────────────────────────

def test_rfc3164_stamps_parse_without_failing_strptime_attempts(monkeypatch):
    calls: list[str] = []

    class Counting(datetime):
        @classmethod
        def strptime(cls, *a):
            calls.append(a[0])
            return super().strptime(*a)

    monkeypatch.setattr(causal, "datetime", Counting)
    assert causal._parse_event_ts.__wrapped__("Oct 20 10:00:00") == datetime(4, 10, 20, 10, 0)
    assert calls == []
    assert causal._parse_event_ts.__wrapped__("2026/10/20 10:00:00") == datetime(2026, 10, 20, 10, 0)
    assert causal._parse_event_ts.__wrapped__("Oct 99 10:00:00") is None
    assert causal._parse_event_ts("") is None
