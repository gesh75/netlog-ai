"""Unit tests for the EVPN-VXLAN Bipartite Causal Inference Engine."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
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
def test_underlay_spine_link_failure_suppresses_overlay_evpn_symptoms() -> None:
    manifest = {
        "site": "clab-clos-evpn",
        "links": [
            {"source": "spine1", "target": "leaf1"},
            {"source": "spine1", "target": "leaf2"},
            {"source": "spine2", "target": "leaf1"},
            {"source": "spine2", "target": "leaf2"},
        ],
    }
    engine = EVPNBipartiteCausalEngine.from_site_manifest(manifest)
    t0 = datetime(2026, 10, 13, 18, 0, 0, tzinfo=timezone.utc)

    raw_stream = [
        (
            "ev-1",
            t0,
            "leaf1",
            "%LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet1/1, changed state to down (OPTICAL_PWR_LOW)",
        ),
        (
            "ev-2",
            t0 + timedelta(seconds=1),
            "spine1",
            "BFDD_TRAP_SHOP_DOWN: BFD session to neighbor 10.0.1.2 on xe-0/0/1 went Down",
        ),
        (
            "ev-3",
            t0 + timedelta(seconds=2),
            "leaf1",
            "%BGP-5-ADJCHANGE: neighbor 10.0.1.1 Down BFD session down",
        ),
        (
            "ev-4",
            t0 + timedelta(seconds=4),
            "leaf2",
            "%VXLAN_TUNNEL_DOWN: VTEP 192.168.255.11 unreachable on nve1",
        ),
        (
            "ev-5",
            t0 + timedelta(seconds=6),
            "leaf2",
            "BGP-EVPN: Type-2 MAC/IP route withdraw for VNI 10010 from peer 192.168.255.11",
        ),
    ]

    events = [
        engine.classify_event(eid, ts, dev, msg)
        for eid, ts, dev, msg in raw_stream
    ]

    hypotheses = engine.analyze(events)

    assert len(hypotheses) == 1
    top = hypotheses[0]
    assert top.root_cause.event_id == "ev-1"
    assert top.root_cause.layer == ProtocolLayer.L1_PHYSICAL
    assert top.root_cause.device == "leaf1"
    assert top.root_cause.interface == "Ethernet1/1"

    assert len(top.suppressed_symptoms) == 4
    assert top.symptom_suppression_ratio == 0.8
    assert top.affected_devices == {"leaf1", "spine1", "leaf2"}
    assert top.affected_vnis == {10010}
    assert top.confidence >= 0.90

    cyto = top.to_cytoscape_elements()
    dashed_edges = [
        el for el in cyto if el["data"].get("line_style") == "dashed"
    ]
    assert len(dashed_edges) >= 1


@pytest.mark.unit
def test_layer_signatures_arista_junos_frr_cisco() -> None:
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
def test_underlay_bgp_does_not_steal_evpn_session() -> None:
    layer, _ = classify_message("bgpd: BGP EVPN neighbor 10.0.0.1 Down")
    assert layer is ProtocolLayer.L5_OVERLAY_EVPN


@pytest.mark.unit
def test_extract_interface_and_vni() -> None:
    msg = (
        "leaf1 Ebra: %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet49/1, "
        "changed state to down VNI 10010"
    )
    assert extract_interface(msg) == "Ethernet49/1"
    assert extract_vni(msg) == "10010"
    assert extract_vni("evpn mac-move vxlan:20020") == "20020"


@pytest.mark.unit
def test_clos_manifest_builds_spine_leaf_adjacency() -> None:
    manifest = _load_clos()
    adj = adjacency_from_manifest(manifest)
    assert "leaf1" in adj["spine1"]
    assert "spine1" in adj["leaf1"]
    assert "leaf3" not in adj["leaf1"]
    engine = EVPNBipartiteCausalEngine.from_site_manifest(manifest)
    assert engine.is_adjacent("leaf1", "spine2")
    assert not engine.is_adjacent("leaf1", "leaf6")


@pytest.mark.unit
def test_window_expires_and_unknown_is_ignored() -> None:
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
def test_cytoscape_elements_shape_and_dashed_overlay() -> None:
    engine = EVPNBipartiteCausalEngine({"leaf1": []})
    hyps = engine.analyze([
        _fe("Oct 13 10:00:01", "leaf1",
            "%LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet1, changed state to down"),
        _fe("Oct 13 10:00:10", "leaf1",
            "EVPN Type-2 MAC/IP withdraw VNI 10010"),
    ])
    els = hyps[0].to_cytoscape_elements()
    nodes = [e for e in els if "source" not in e.get("data", {})]
    edges = [e for e in els if e.get("data", {}).get("edge_type") == "causal_propagation"]
    assert any(n["data"]["id"] == "leaf1:L1_PHYSICAL" for n in nodes)
    assert any(n["data"]["id"] == "leaf1:L5_OVERLAY_EVPN" for n in nodes)
    assert all(n["data"]["device"] == "leaf1" for n in nodes)
    assert {n["data"]["layer"] for n in nodes} == {"underlay", "overlay"}
    assert any(n["data"]["causal_role"] == "root_cause" for n in nodes)
    assert edges
    assert any(e["data"].get("line_style") == "dashed" for e in edges)


@pytest.mark.unit
def test_analyze_evpn_causal_default_off_and_opt_in() -> None:
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
def test_causal_wrapper_and_topology_attach() -> None:
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
def test_demo_storyline_classifies_l1_and_l3() -> None:
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
def test_protocol_layer_values() -> None:
    assert ProtocolLayer.L1_PHYSICAL == 1
    assert ProtocolLayer.L5_OVERLAY_EVPN == 5
    assert ProtocolLayer.UNKNOWN == 99
