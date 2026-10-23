"""Topology edge inference: whole-name description matches, bounded subnet
cliques, indexed address ownership, and its cost at fabric size."""
from __future__ import annotations

import time

import pytest

from ai_log_analyzer.topology_infer import DeviceFacts, infer_edges

pytestmark = pytest.mark.unit


def _facts(host: str, *, descriptions=(), ips=(), neighbors=(), mlag=()) -> DeviceFacts:
    return DeviceFacts(hostname=host, platform="eos", interface_ips=list(ips), bgp_neighbors=list(neighbors),
                       mlag_peers=list(mlag), descriptions=list(descriptions), has_chassis_cluster=False)


def _edges(facts: list[DeviceFacts]) -> dict[tuple[str, str], tuple[str, float]]:
    return {(e.source, e.target): (e.rule, e.confidence) for e in infer_edges({f.hostname: f for f in facts})}


def test_description_names_the_whole_hostname_not_a_prefix_of_it():
    edges = _edges([_facts("sw-1"), _facts("sw-10", descriptions=["uplink to sw-10 port 3"]),
                    _facts("core"), _facts("core-02", descriptions=["to core-02 xe1"]),
                    _facts("leaf-7", descriptions=["to sw-10 xe-0/0/1"])])
    assert ("sw-1", "sw-10") not in edges and ("core", "core-02") not in edges
    assert edges[("leaf-7", "sw-10")] == ("description-hostname", 0.95)


def test_description_still_matches_exact_and_dotted_names_and_short_forms():
    edges = _edges([_facts("a-spine-01", descriptions=["to b-leaf-02.example.com eth1", "link leaf-03 e2"]),
                    _facts("b-leaf-02.example.com"), _facts("x-leaf-03")])
    assert edges[("a-spine-01", "b-leaf-02.example.com")] == ("description-hostname", 0.95)
    assert edges[("a-spine-01", "x-leaf-03")] == ("description-shortform", 0.7)


def test_dotted_hostname_is_not_matched_inside_a_longer_name():
    edges = _edges([_facts("sw-1.dc1", descriptions=["to leaf-1.dc1x"]), _facts("leaf-1.dc1")])
    assert edges == {}


def test_a_shared_lan_segment_is_not_a_clique_but_a_small_link_is():
    lan = [_facts(f"h{i}", ips=[f"10.9.0.{i + 1}/28"]) for i in range(8)]
    assert _edges(lan) == {}
    trio = [_facts(f"t{i}", ips=[f"10.8.0.{i + 1}/29"]) for i in range(3)]
    assert len(_edges(trio)) == 3
    link = [_facts("l1", ips=["10.7.0.1/31"]), _facts("l2", ips=["10.7.0.0/31"])]
    assert _edges(link) == {("l1", "l2"): ("subnet-co-membership", 0.85)}


def test_bgp_and_mlag_peers_resolve_through_the_address_index():
    edges = _edges([_facts("r1", neighbors=["10.0.0.2"], mlag=["10.1.0.2"], ips=["10.0.0.1/30", "10.1.0.1/30"]),
                    _facts("r2", ips=["10.0.0.2/30", "10.1.0.2/30"]),
                    _facts("r3", neighbors=["10.0.0.2"], ips=["10.5.0.1/30"])])
    assert edges[("r1", "r2")] == ("mlag-peer", 1.0)       # the stronger rule wins
    assert edges[("r2", "r3")] == ("bgp-neighbor", 0.95)


def test_address_owned_by_two_devices_links_the_asker_to_both():
    edges = _edges([_facts("a", neighbors=["10.0.0.9"]), _facts("b", ips=["10.0.0.9/24"]),
                    _facts("c", ips=["10.0.0.9/24"])])
    assert ("a", "b") in edges and ("a", "c") in edges


def test_inference_at_fabric_size_is_fast():
    n, ifs = 120, 24
    facts = [_facts(f"dc1-sw-{i:03d}", descriptions=[f"to dc1-sw-{(i + 1) % n:03d} eth1"] * 4,
                    ips=[f"10.{i // 250}.{i % 250}.{k}/31" for k in range(ifs)],
                    neighbors=[f"10.{(i + k) % n // 250}.{(i + k) % n % 250}.{k}" for k in range(1, 25)])
             for i in range(n)]
    start = time.perf_counter()
    infer_edges({f.hostname: f for f in facts})
    assert time.perf_counter() - start < 1.5
