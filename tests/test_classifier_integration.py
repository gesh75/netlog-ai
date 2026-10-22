"""Cross-workstream consistency: new IS-IS / LDP / STP descriptions must flow through the recovery list,
the stability pairing tables, and must not be shadowed by the generic BGP hold-timer rule."""
from __future__ import annotations

import pytest

from ai_log_analyzer import stability
from ai_log_analyzer.adapters.file import parse_lines
from ai_log_analyzer.analyzer import _RECOVERY_DESCRIPTIONS, analyze
from ai_log_analyzer.classifier import classify_events


def _descriptions(lines):
    return [e.description for e in classify_events(list(parse_lines(lines)))[0]]


@pytest.mark.unit
def test_isis_hold_time_expired_is_not_a_bgp_event():
    isis = "Oct 22 10:00:00 r3 %CLNS-5-ADJCHANGE: ISIS: Adjacency to r2 (Gi0/0/1) Down, hold time expired"
    bgp = "Oct 22 10:00:00 r1 rpd[1]: bgp_hold_timeout:4102: NOTIFICATION sent to 10.0.0.2 (External AS 65010): code 4 (Hold Timer Expired Error)"
    assert _descriptions([isis]) == ["IS-IS adjacency down"]
    assert _descriptions([bgp]) == ["BGP hold timer expired"]


@pytest.mark.unit
def test_ospf_dead_interval_config_is_not_an_incident():
    lines = ["Oct 22 10:02:00 r5 router[1]: interface Gi0/1 ip ospf dead-interval 20"]
    assert not [a for a in analyze(list(parse_lines(lines)), use_llm=False).to_dict()["action_items"]]


@pytest.mark.unit
@pytest.mark.parametrize("up", ["IS-IS adjacency up", "LDP neighbor/session up", "STP guard recovered"])
def test_new_recovery_descriptions_never_become_incidents(up):
    assert up in _RECOVERY_DESCRIPTIONS


@pytest.mark.unit
def test_new_protocols_pair_down_with_up_in_the_stability_tables():
    pairs = {"IS-IS adjacency down": "IS-IS adjacency up", "LDP neighbor/session down": "LDP neighbor/session up",
             "STP root/loop/BPDU guard block": "STP guard recovered"}
    for down, up in pairs.items():
        cls = stability._DOWN_DESCRIPTIONS[down]
        assert stability._UP_DESCRIPTIONS[up] == cls
        assert cls in stability._ENTITY_LABELS


@pytest.mark.unit
def test_isis_down_then_up_is_reported_as_recovered():
    lines = ["Oct 22 10:00:00 r3 %CLNS-5-ADJCHANGE: ISIS: Adjacency to r2 (Gi0/0/1) Down, hold time expired",
             "Oct 22 10:00:30 r3 %CLNS-5-ADJCHANGE: ISIS: Adjacency to r2 (Gi0/0/1) Up, new adjacency"]
    states = analyze(list(parse_lines(lines)), use_llm=False).to_dict()["entity_states"]["entities"]
    assert [(e["hostname"], e["status"]) for e in states] == [("r3", "recovered")]
