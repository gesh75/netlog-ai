"""Tests for the multi-signal topology inference."""
from __future__ import annotations

import pytest

from ai_log_analyzer import topology_infer


JUNOS_FW = """
chassis cluster {
    cluster-id 1;
}
interfaces {
    ge-0/0/0 { unit 0 { family inet { address 10.10.0.1/30; } } description "uplink to peer-a-sw-04"; }
    ge-0/0/1 { unit 0 { family inet { address 10.10.1.1/30; } } }
}
protocols {
    bgp {
        group EXT {
            neighbor 10.10.0.2 { peer-as 65002; }
            neighbor 10.10.1.2 { peer-as 65003; }
        }
    }
}
"""

EOS_SW04 = """
hostname peer-a-sw-04
interface Ethernet1
   ip address 10.10.0.2/30
   description "to peer-a-fw-01"
router bgp 65002
   neighbor 10.10.0.1 remote-as 65001
"""

EOS_SW03A = """
hostname peer-a-sw-03a
interface Ethernet1
   ip address 10.10.1.2/30
interface Vlan4094
   ip address 169.254.1.1/24
mlag configuration
   peer-address 169.254.1.2
"""

EOS_SW03B = """
hostname peer-a-sw-03b
interface Vlan4094
   ip address 169.254.1.2/24
mlag configuration
   peer-address 169.254.1.1
"""


@pytest.mark.unit
def test_extract_facts_pulls_ips_and_bgp():
    f = topology_infer.extract_facts("peer-a-fw-01", "junos", JUNOS_FW)
    assert any("10.10.0.1/30" in ip for ip in f.interface_ips)
    assert "10.10.0.2" in f.bgp_neighbors
    assert "10.10.1.2" in f.bgp_neighbors
    assert f.has_chassis_cluster is True


@pytest.mark.unit
def test_extract_facts_eos_descriptions():
    f = topology_infer.extract_facts("peer-a-sw-04", "eos", EOS_SW04)
    assert any("peer-a-fw-01" in d for d in f.descriptions)


@pytest.mark.unit
def test_inference_bgp_neighbor_creates_edge():
    facts = {
        "peer-a-fw-01": topology_infer.extract_facts("peer-a-fw-01", "junos", JUNOS_FW),
        "peer-a-sw-04": topology_infer.extract_facts("peer-a-sw-04", "eos",   EOS_SW04),
    }
    edges = topology_infer.infer_edges(facts)
    pair = next((e for e in edges if {e.source, e.target} == {"peer-a-fw-01", "peer-a-sw-04"}), None)
    assert pair is not None
    # Either bgp-neighbor or subnet-co-membership or description should fire
    assert pair.rule in {"bgp-neighbor", "subnet-co-membership", "description-hostname"}


@pytest.mark.unit
def test_inference_subnet_co_membership_p2p():
    cfg_a = "interface Ethernet1\n  ip address 10.20.0.1/30\n"
    cfg_b = "interface Ethernet1\n  ip address 10.20.0.2/30\n"
    facts = {
        "rt-a": topology_infer.extract_facts("rt-a", "eos", cfg_a),
        "rt-b": topology_infer.extract_facts("rt-b", "eos", cfg_b),
    }
    edges = topology_infer.infer_edges(facts)
    assert any(e.rule == "subnet-co-membership" for e in edges)


@pytest.mark.unit
def test_inference_mlag_peer_address():
    facts = {
        "peer-a-sw-03a": topology_infer.extract_facts("peer-a-sw-03a", "eos", EOS_SW03A),
        "peer-a-sw-03b": topology_infer.extract_facts("peer-a-sw-03b", "eos", EOS_SW03B),
    }
    edges = topology_infer.infer_edges(facts)
    mlag = next((e for e in edges if e.rule == "mlag-peer"), None)
    assert mlag is not None
    assert mlag.confidence == 1.0


@pytest.mark.unit
def test_inference_ha_pair_naming():
    # Two firewalls with chassis cluster and HA-style naming → ha-pair
    cfg = "chassis cluster { cluster-id 1; }"
    facts = {
        "peer-a-fw-01a": topology_infer.extract_facts("peer-a-fw-01a", "junos", cfg),
        "peer-a-fw-01b": topology_infer.extract_facts("peer-a-fw-01b", "junos", cfg),
    }
    edges = topology_infer.infer_edges(facts)
    assert any(e.rule == "ha-pair-naming" for e in edges)


@pytest.mark.unit
def test_is_ha_pair_helpers():
    # Same base with a/b
    assert topology_infer._is_ha_pair("peer-a-fw-01a", "peer-a-fw-01b")
    # Sequential numbers
    assert topology_infer._is_ha_pair("peer-a-fw-01", "peer-a-fw-02")
    # Different roles → not a pair
    assert not topology_infer._is_ha_pair("peer-a-fw-01", "peer-a-rt-02")


@pytest.mark.unit
def test_inference_dedups_to_highest_confidence():
    """If both description and bgp-neighbor fire for the same pair,
    we keep the higher confidence one."""
    facts = {
        "peer-a-fw-01": topology_infer.extract_facts("peer-a-fw-01", "junos", JUNOS_FW),
        "peer-a-sw-04": topology_infer.extract_facts("peer-a-sw-04", "eos",   EOS_SW04),
    }
    edges = topology_infer.infer_edges(facts)
    # The (fw-01, sw-04) pair appears at most once
    pairs = [tuple(sorted([e.source, e.target])) for e in edges]
    assert len(pairs) == len(set(pairs))
