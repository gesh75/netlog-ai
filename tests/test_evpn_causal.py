"""Protocol-aware EVPN bipartite causal engine."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_log_analyzer.analyzer import analyze
from ai_log_analyzer.causal import evpn_causal_hypotheses
from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.demo import generate_demo_lines
from ai_log_analyzer.evpn_causal import (
    EVPNBipartiteCausalEngine,
    FabricEvent,
    ProtocolLayer,
    adjacency_from_manifest,
    classify_message,
    extract_interface,
    extract_vni,
    fabric_event_from_raw,
)
from ai_log_analyzer.topology import attach_evpn_causal

SITES = Path(__file__).resolve().parents[1] / "src" / "ai_log_analyzer" / "data" / "sites"
CLOS_MANIFEST = SITES / "clab-clos-evpn" / "manifest.json"


def _load_clos() -> dict:
    return json.loads(CLOS_MANIFEST.read_text())


def _fe(
    ts: str,
    device: str,
    message: str,
) -> FabricEvent:
    return fabric_event_from_raw(message, timestamp=ts, device=device)


@pytest.mark.unit
def test_layer_signatures_arista_junos_frr_cisco():
    cases = [
        (
            ProtocolLayer.L1_PHYSICAL,
            "leaf1 Ebra: %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet1, "
            "changed state to down",
        ),
        (
            ProtocolLayer.L1_PHYSICAL,
            "leaf4 %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down",
        ),
        (
            ProtocolLayer.L2_LAG_MLAG,
            "leaf1 LACP: Port-Channel10 member Ethernet3 suspended (timeout)",
        ),
        (
            ProtocolLayer.L3_UNDERLAY,
            "spine1 rpd: RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 10.255.1.11 state Idle",
        ),
        (
            ProtocolLayer.L3_UNDERLAY,
            "leaf3 bgpd[221]: %NOTIFICATION: sent to neighbor 10.0.0.1 4/0",
        ),
        (
            ProtocolLayer.L3_UNDERLAY,
            "%BGP-5-ADJCHANGE: neighbor 10.0.0.2 Down",
        ),
        (
            ProtocolLayer.L4_VTEP_NVE,
            "leaf1 nve: NVE peer 10.0.0.8 lost — VXLAN_TUNNEL_DOWN",
        ),
        (
            ProtocolLayer.L5_OVERLAY_EVPN,
            "leaf1 bgpd: EVPN Type-2 MAC/IP withdraw VNI 10010",
        ),
        (
            ProtocolLayer.L5_OVERLAY_EVPN,
            "spine1 bgpd: BGP EVPN neighbor 10.0.0.1 Down Notification",
        ),
    ]
    for layer, message in cases:
        got, summary = classify_message(message)
        assert got is layer, message
        assert summary


@pytest.mark.unit
def test_underlay_bgp_does_not_steal_evpn_session():
    layer, _ = classify_message("bgpd: BGP EVPN neighbor 10.0.0.1 Down")
    assert layer is ProtocolLayer.L5_OVERLAY_EVPN


@pytest.mark.unit
def test_extract_interface_and_vni():
    msg = (
        "leaf1 Ebra: %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet49/1, "
        "changed state to down VNI 10010"
    )
    assert extract_interface(msg) == "Ethernet49/1"
    assert extract_vni(msg) == "10010"
    assert extract_vni("evpn mac-move vxlan:20020") == "20020"


@pytest.mark.unit
def test_clos_manifest_builds_spine_leaf_adjacency():
    manifest = _load_clos()
    adj = adjacency_from_manifest(manifest)
    assert "leaf1" in adj["spine1"]
    assert "spine1" in adj["leaf1"]
    assert "leaf3" not in adj["leaf1"]
    engine = EVPNBipartiteCausalEngine.from_site_manifest(manifest)
    assert engine.is_adjacent("leaf1", "spine2")
    assert not engine.is_adjacent("leaf1", "leaf6")


@pytest.mark.unit
def test_lowest_layer_root_suppresses_higher_on_same_and_adjacent():
    manifest = _load_clos()
    engine = EVPNBipartiteCausalEngine.from_site_manifest(
        manifest, max_propagation_window_sec=120,
    )
    events = [
        _fe("Oct 13 10:00:01", "leaf1",
            "%LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet1, changed state to down"),
        _fe("Oct 13 10:00:05", "leaf1",
            "LACP: Port-Channel10 member Ethernet1 suspended timeout"),
        _fe("Oct 13 10:00:15", "spine1",
            "RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 10.0.0.1 state Idle"),
        _fe("Oct 13 10:00:20", "leaf1",
            "NVE peer 10.0.0.8 lost VXLAN_TUNNEL_DOWN"),
        _fe("Oct 13 10:00:30", "leaf1",
            "EVPN Type-2 MAC/IP withdraw VNI 10010"),
        # Far-away leaf — not adjacent, must not be swallowed by leaf1's L1
        _fe("Oct 13 10:00:31", "leaf6",
            "EVPN Type-2 MAC/IP withdraw VNI 10010"),
    ]
    hyps = engine.analyze(events)
    assert hyps
    root = hyps[0]
    assert root.root_cause.layer is ProtocolLayer.L1_PHYSICAL
    assert root.root_cause.device == "leaf1"
    layers = {s.layer for s in root.suppressed_symptoms}
    assert ProtocolLayer.L5_OVERLAY_EVPN in layers
    assert ProtocolLayer.L4_VTEP_NVE in layers
    assert ProtocolLayer.L2_LAG_MLAG in layers
    suppressed_devices = {s.device for s in root.suppressed_symptoms}
    assert "leaf1" in suppressed_devices
    assert "spine1" in suppressed_devices
    assert "leaf6" not in suppressed_devices
    assert root.symptom_suppression_ratio > 0
    assert 0.4 <= root.confidence <= 0.95
    assert "suppressed" in root.rationale.lower()
    assert "10010" in root.affected_vnis


@pytest.mark.unit
def test_window_expires_and_unknown_is_ignored():
    engine = EVPNBipartiteCausalEngine({"leaf1": ["spine1"]}, max_propagation_window_sec=30)
    events = [
        _fe("Oct 13 10:00:00", "leaf1",
            "%LINK-3-UPDOWN: Interface Ethernet1, changed state to down"),
        _fe("Oct 13 10:05:00", "leaf1",
            "EVPN Type-2 MAC/IP withdraw VNI 10010"),
        _fe("Oct 13 10:00:05", "leaf1",
            "quantum optics calibration drift exceeded budget"),
    ]
    hyps = engine.analyze(events)
    l1 = next(h for h in hyps if h.root_cause.layer is ProtocolLayer.L1_PHYSICAL)
    assert all(s.layer is not ProtocolLayer.L5_OVERLAY_EVPN for s in l1.suppressed_symptoms)
    assert all(s.layer is not ProtocolLayer.UNKNOWN for s in l1.suppressed_symptoms)


@pytest.mark.unit
def test_cytoscape_elements_shape_and_dashed_overlay():
    engine = EVPNBipartiteCausalEngine({"leaf1": []})
    hyps = engine.analyze([
        _fe("Oct 13 10:00:01", "leaf1",
            "%LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet1, changed state to down"),
        _fe("Oct 13 10:00:10", "leaf1",
            "EVPN Type-2 MAC/IP withdraw VNI 10010"),
    ])
    els = hyps[0].to_cytoscape_elements()
    nodes = [e for e in els if "source" not in e.get("data", {})]
    edges = [e for e in els if e.get("data", {}).get("kind") == "causal_propagation"]
    assert any(n["data"]["id"] == "leaf1:L1_PHYSICAL" for n in nodes)
    assert any(n["data"]["id"] == "leaf1:L5_OVERLAY_EVPN" for n in nodes)
    assert all(n["data"]["device"] == "leaf1" for n in nodes)
    assert {n["data"]["layer"] for n in nodes} == {"underlay", "overlay"}
    assert any(n["data"]["causal_role"] == "root_cause" for n in nodes)
    assert edges
    assert any("causal-dashed" in (e.get("classes") or "") for e in edges)


@pytest.mark.unit
def test_analyze_evpn_causal_default_off_and_opt_in():
    events = [
        LogEvent("Oct 13 10:00:01", "leaf1", "Ebra", "err",
                 "%LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet1, changed state to down"),
        LogEvent("Oct 13 10:00:10", "leaf1", "bgpd", "err",
                 "EVPN Type-2 MAC/IP withdraw VNI 10010"),
    ]
    off = analyze(events, use_llm=False)
    assert off.evpn_causal == {}
    assert off.to_dict()["evpn_causal"] == {}

    on = analyze(events, use_llm=False, evpn_causal=True, site_manifest=_load_clos())
    assert on.evpn_causal.get("enabled") is True
    assert on.evpn_causal.get("hypotheses")
    assert on.evpn_causal.get("cytoscape_elements")


@pytest.mark.unit
def test_causal_wrapper_and_topology_attach():
    payload = evpn_causal_hypotheses([
        _fe("Oct 13 10:00:01", "leaf1",
            "%LINK-3-UPDOWN: Interface Ethernet1, changed state to down"),
        _fe("Oct 13 10:00:08", "leaf1",
            "EVPN Type-2 duplicate MAC_MOVE_LIMIT VNI 10010"),
    ], manifest=_load_clos())
    assert payload["enabled"] is True
    attached = attach_evpn_causal({"nodes": [], "edges": []}, payload["cytoscape_elements"])
    assert attached["evpn_causal_elements"]
    assert attach_evpn_causal({"nodes": []}, None) == {"nodes": []}


@pytest.mark.unit
def test_demo_storyline_classifies_l1_and_l3():
    lines = generate_demo_lines()
    engine = EVPNBipartiteCausalEngine()
    fabric = engine.ingest(lines)
    layers = {e.layer for e in fabric}
    assert ProtocolLayer.L1_PHYSICAL in layers
    assert ProtocolLayer.L3_UNDERLAY in layers
    hyps = engine.analyze([
        e for e in fabric if e.layer is not ProtocolLayer.UNKNOWN
    ])
    assert hyps


@pytest.mark.unit
def test_protocol_layer_values():
    assert ProtocolLayer.L1_PHYSICAL == 1
    assert ProtocolLayer.L5_OVERLAY_EVPN == 5
    assert ProtocolLayer.UNKNOWN == 99
