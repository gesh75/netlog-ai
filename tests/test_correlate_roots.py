"""Entity correlation: confidence honesty, transit-AS wording and root, untimed
events, arrival-order independence and the bounded pool."""
from __future__ import annotations

import itertools
import time

import pytest

from ai_log_analyzer.correlate import CorrelationPool, bound_events, correlate_entities
from tests._w8_events import ev

pytestmark = pytest.mark.unit


def _shape(result):
    return [(i["devices"], i["event_count"], i["confidence"], i["root_cause"]["hostname"],
             i["root_cause"]["event_type"], [c["event_type"] for c in i["chain"]]) for i in result["incidents"]]


# ── (a) timing-only bridges stay "medium" ───────────────────────────────────

def test_unrelated_tunnel_and_isp_session_bridged_only_by_timing_is_not_high():
    events = [ev("A", 0, "ipsec_tunnel", peer="198.51.100.1", tun="HQ1", vendor="fortinet"),
              ev("B", 5, "ipsec_tunnel", peer="198.51.100.1", tun="HQ1", vendor="juniper"),
              ev("A", 200, "bgp_session", peer="10.9.9.2", asn="64512", vendor="fortinet"),
              ev("C", 205, "bgp_session", peer="10.9.9.1", asn="64512", vendor="cisco")]
    (inc,) = correlate_entities(events)["incidents"]
    assert inc["devices"] == ["a", "b", "c"] and inc["confidence"] == "medium"


def test_tunnel_and_the_bgp_session_riding_it_stay_high():
    events = [ev("A", 0, "ipsec_tunnel", peer="198.51.100.1", tun="HQ1", vendor="fortinet"),
              ev("B", 5, "ipsec_tunnel", peer="198.51.100.1", tun="HQ1", vendor="juniper"),
              ev("A", 170, "bgp_session", peer="169.254.10.2", asn="65010", vendor="fortinet"),
              ev("B", 172, "bgp_session", peer="169.254.10.1", asn="65010", vendor="juniper")]
    (inc,) = correlate_entities(events)["incidents"]
    assert inc["devices"] == ["a", "b"] and inc["confidence"] == "high"


# ── (b) transit-AS siblings ─────────────────────────────────────────────────

def test_transit_as_cluster_is_rooted_at_the_external_as_not_a_device():
    events = [ev(f"r{i}", i, asn="65010", peer=f"192.0.{i + 2}.{i * 4 + 1}") for i in range(5)]
    (inc,) = correlate_entities(events)["incidents"]
    assert inc["summary"].startswith("5 devices lost sessions to AS65010")
    assert "downstream" not in inc["summary"]
    root = inc["root_cause"]
    assert root["entity"] == "AS65010" and root["hostname"] == "AS65010"
    assert set(root) == set(inc["chain"][0]) and root["layer"] == "routing"
    assert inc["confidence"] == "medium" and inc["device_count"] == 5


def test_a_device_rooted_incident_keeps_the_downstream_wording():
    events = [ev("A", 0, "interface_link", iface="xe0"), ev("B", 5, "bgp_session", peer="10.0.0.1", asn="1"),
              ev("A", 3, "bgp_session", peer="10.0.0.2", asn="1")]
    (inc,) = correlate_entities(events)["incidents"]
    assert "downstream" in inc["summary"]


# ── (c) untimed events ──────────────────────────────────────────────────────

def test_untimed_events_do_not_join_timed_ones_on_a_shared_key():
    events = [ev("a", 0, peer="10.9.0.1", asn="1"), ev("b", None, peer="10.9.0.1", asn="1")]
    assert correlate_entities(events)["incidents"] == []


def test_untimed_events_still_join_each_other():
    events = [ev("a", None, peer="10.9.0.1", asn="1"), ev("b", None, peer="10.9.0.1", asn="1")]
    assert len(correlate_entities(events)["incidents"]) == 1


# ── (d) arrival order must not matter ───────────────────────────────────────

def test_equal_timestamps_do_not_depend_on_arrival_order():
    bgp, link = ev("A", 0, "bgp_session", peer="1.1.1.1", asn="1"), ev("A", 0, "interface_link", iface="e1")
    assert len(correlate_entities([bgp, link])["incidents"]) == 1
    assert len(correlate_entities([link, bgp])["incidents"]) == 1


def test_all_permutations_of_a_same_second_event_set_give_identical_incidents():
    base = [ev("A", 0, "bgp_session", peer="1.1.1.1", asn="1"), ev("A", 0, "interface_link", iface="e1"),
            ev("A", 0, "ospf_adjacency", peer="2.2.2.2"), ev("B", 0.4, "bgp_session", peer="1.1.1.2", asn="1"),
            ev("B", 0, "interface_link", iface="e9")]
    shapes = {repr(_shape(correlate_entities(list(p)))) for p in itertools.permutations(base)}
    assert len(shapes) == 1
    assert correlate_entities(base)["incidents"]


def test_isis_and_ldp_are_routing_layer_events():
    events = [ev("A", 0, "interface_link", iface="e1"), ev("A", 10, "isis_adjacency", peer="10.0.0.9"),
              ev("A", 12, "ldp_session", peer="10.0.0.8")]
    (inc,) = correlate_entities(events)["incidents"]
    assert [c["layer"] for c in inc["chain"]] == ["physical", "routing", "routing"]


# ── bounded pool ────────────────────────────────────────────────────────────

def test_bound_events_collapses_repeats_to_first_and_last_then_drops_least_severe():
    flap = [ev("sw", i, "interface_link", iface="e1") for i in range(10)]
    kept, dropped, collapsed = bound_events(flap, 5)
    assert (len(kept), dropped, collapsed) == (2, 0, 8)
    assert kept[0] is flap[0] and kept[-1] is flap[-1]
    mixed = [ev(f"h{i}", i, iface=f"e{i}", et="interface_link", sev="medium") for i in range(4)] + \
            [ev("x", 9, "bgp_session", peer="1.2.3.4", asn="1", sev="critical")]
    kept, dropped, _ = bound_events(mixed, 3)
    assert dropped == 2 and any(e.severity == "critical" for e in kept)


def test_storm_noise_before_a_real_incident_no_longer_starves_it():
    noise = [ev("sw1", i * 0.1, "interface_link", iface=f"Eth{i % 100}") for i in range(2500)]
    real = [ev("a", 3600, "ipsec_tunnel", tun="T1", peer="9.9.9.9"), ev("b", 3605, "bgp_session", peer="9.9.9.9", asn="1")]
    result = correlate_entities(noise + real)
    assert [i["devices"] for i in result["incidents"]] == [["a", "b"]]
    assert result["dropped"] == 0 and result["collapsed"] > 0 and "bounded" in result["warning"]


def test_pool_streaming_keeps_a_late_incident_and_reports_what_it_collapsed():
    pool = CorrelationPool(max_events=2000)
    stream = [ev("sw1", i * 0.1, "interface_link", iface=f"Eth{i % 100}") for i in range(2500)] + \
             [ev("a", 3600, "ipsec_tunnel", tun="T1", peer="9.9.9.9"), ev("b", 3605, "bgp_session", peer="9.9.9.9", asn="1")]
    for e in stream:
        pool.add(e)
    kept = pool.events()
    assert len(kept) <= 2000 and {e.hostname for e in kept} >= {"a", "b"}
    assert pool.dropped == 0 and pool.collapsed > 0 and "collapsed" in pool.warning
    assert [i["devices"] for i in correlate_entities(kept)["incidents"]] == [["a", "b"]]


def test_small_inputs_are_never_collapsed():
    pool = CorrelationPool()
    flap = [ev("sw", i, "interface_link", iface="e1") for i in range(50)]
    for e in flap:
        pool.add(e)
    assert pool.events() == flap and pool.warning == ""


# ── 2000-device transit AS outage (regression guard for the ASN join) ───────

def test_2000_device_transit_as_outage_is_one_medium_incident_in_under_a_second():
    events = [ev(f"r{i}", i * 0.3, asn="174", peer=f"10.{i // 250}.{i % 250}.1") for i in range(2000)]
    start = time.perf_counter()
    result = correlate_entities(events)
    assert time.perf_counter() - start < 1.0
    (inc,) = result["incidents"]
    assert inc["confidence"] == "medium" and inc["device_count"] == 2000
    assert inc["root_cause"]["entity"] == "AS174"
