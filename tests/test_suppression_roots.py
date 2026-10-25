"""Suppression must pick real roots: same-device children share an entity with
the root or follow it promptly at a higher layer, never predate it, and the
two engines (suppression, entity correlation) name the same root."""
from __future__ import annotations

import time

import pytest

from ai_log_analyzer.correlate import correlate_entities
from ai_log_analyzer.suppression import suppress_alerts
from tests._w8_events import ev

pytestmark = pytest.mark.unit


def _roots(events):
    return [(g["root"]["event_type"], g["suppressed_count"]) for g in suppress_alerts(events)["groups"]]


def test_unrelated_port_down_does_not_suppress_a_bgp_drop_minutes_later():
    events = [ev("sw1", 0, "interface_link", iface="Gi1/0/47"),
              ev("sw1", 180, "bgp_session", peer="203.0.113.5", asn="64999")]
    assert _roots(events) == []


def test_event_before_the_link_down_is_not_its_child():
    events = [ev("sw1", 0, "bgp_session", peer="203.0.113.5", asn="64999"),
              ev("sw1", 20, "interface_link", iface="xe0")]
    assert _roots(events) == []


def test_independent_port_downs_on_one_host_do_not_suppress_each_other():
    events = [ev("sw1", i, "interface_link", iface=f"Gi1/0/{i}") for i in range(10)]
    result = suppress_alerts(events)
    assert result["suppressed_events"] == 0 and result["groups"] == []


def test_link_down_still_claims_its_own_interface_and_a_prompt_higher_layer_follow_on():
    events = [ev("sw1", 0, "interface_link", iface="xe0"),
              ev("sw1", 5, "sdwan_sla", iface="xe0"),                              # shares the interface
              ev("sw1", 20, "bgp_session", peer="203.0.113.5", asn="64999")]       # prompt follow-on
    assert _roots(events) == [("interface_link", 2)]


def test_link_root_does_not_claim_same_layer_events_even_on_its_interface():
    events = [ev("sw1", 0, "interface_link", iface="xe0"), ev("sw1", 5, "lag_member", iface="xe0")]
    assert _roots(events) == []


def test_tunnel_root_keeps_the_bgp_hold_timer_follow_on_but_only_after_it():
    tunnel = ev("fw1", 0, "ipsec_tunnel", tun="HQ", peer="198.51.100.1", vendor="fortinet")
    late_bgp = ev("fw1", 180, "bgp_session", peer="10.9.9.2", asn="64512", vendor="fortinet")
    assert _roots([tunnel, late_bgp]) == [("ipsec_tunnel", 1)]
    early_bgp = ev("fw1", -20, "bgp_session", peer="10.9.9.2", asn="64512", vendor="fortinet")
    assert _roots([tunnel, early_bgp]) == []


def test_both_engines_name_the_same_root_for_sla_then_link_then_bgp():
    events = [ev("fgA", 0, "sdwan_sla", iface="wan1", vendor="fortinet"),
              ev("fgA", 10, "interface_link", iface="wan1", vendor="fortinet"),
              ev("fgA", 20, "bgp_session", peer="169.254.10.2", asn="65010", vendor="fortinet")]
    incident = correlate_entities(events)["incidents"][0]
    (group,) = suppress_alerts(events)["groups"]
    assert incident["root_cause"]["event_type"] == group["root"]["event_type"] == "interface_link"


def test_suppression_is_not_quadratic():
    burst = [ev("core1", i * 0.01, "interface_link", iface=f"e{i}") for i in range(2000)]
    spaced = [ev("core1", i * 300, "interface_link", iface=f"e{i}") for i in range(2000)]
    ha = [ev(f"fw{i % 50}", i * 1000, "ha_state", vendor="fortinet") for i in range(2000)]
    for events in (burst, spaced, ha):
        start = time.perf_counter()
        suppress_alerts(events)
        assert time.perf_counter() - start < 1.5
