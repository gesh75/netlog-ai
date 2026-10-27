"""Hermetic tests for flap physics, blast radius, and config-drift correlation."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ai_log_analyzer.analytics import (
    Finding,
    analyze_blast_radius,
    analyze_flap_dynamics,
    correlate_config_drift,
)
from ai_log_analyzer.diff import ConfigDiff
from ai_log_analyzer.topology import Edge, Node, Topology

pytestmark = pytest.mark.unit

_T0 = datetime(2026, 10, 16, 14, 0, 0, tzinfo=timezone.utc)


def _line(offset_s: int, host: str, message: str) -> str:
    stamp = (_T0 + timedelta(seconds=offset_s)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"{stamp} {host} {message}"


def test_flap_exponential_decay_and_dampened_storm() -> None:
    lines = [
        _line(0, "leaf01", "bgp neighbor 192.0.2.1 down"),
        _line(1, "leaf01", "bgp neighbor 192.0.2.1 up"),
        _line(2, "leaf01", "bgp neighbor 192.0.2.1 down"),
    ]
    report = analyze_flap_dynamics(lines)
    assert report.dampened_count == 1
    entity = report.entities[0]
    assert entity.entity_id == "192.0.2.1"
    assert entity.state == "DAMPENED_STORM"
    assert entity.peak_penalty >= 2000.0
    # Second event is one second later: penalty ≈ 1000 * 0.5**(1/900) + 1000.
    expected_second = 1000.0 * (0.5 ** (1 / 900.0)) + 1000.0
    assert entity.current_penalty > expected_second
    assert entity.pattern == "PERIODIC_TIMER_DRIVEN"
    assert entity.coefficient_of_variation is not None
    assert entity.coefficient_of_variation < 0.25
    assert report.most_unstable_entity == "leaf01:192.0.2.1"
    cli = report.recommended_dampening_cli
    assert "bgp dampening 15 750 2000 60" in " ".join(cli["arista_eos"])
    assert any("damping" in line for line in cli["juniper_junos"])
    assert any("dampening" in line for line in cli["cisco_iosxr"])
    assert report.to_dict()["dampened_count"] == 1


def test_flap_half_life_decay_is_active_churn() -> None:
    lines = [
        _line(0, "leaf01", "interface Ethernet1 down"),
        _line(900, "leaf01", "interface Ethernet1 up"),
    ]
    report = analyze_flap_dynamics(lines)
    entity = report.entities[0]
    assert entity.entity_id == "Ethernet1"
    assert entity.peak_penalty == pytest.approx(1500.0, abs=0.01)
    assert entity.state == "ACTIVE_CHURN"
    assert entity.pattern == "INSUFFICIENT_DATA"
    assert report.active_churn_count == 1


def test_flap_bursty_versus_isolated() -> None:
    burst = [
        _line(0, "leaf01", "ge-0/0/0 carrier down"),
        _line(1, "leaf01", "ge-0/0/0 carrier up"),
        _line(400, "leaf01", "ge-0/0/0 carrier down"),
    ]
    burst_report = analyze_flap_dynamics(burst)
    assert burst_report.entities[0].pattern == "BURSTY_PHYSICAL_NOISE"

    isolated = analyze_flap_dynamics(
        [_line(0, "leaf01", "xe-0/0/1 down")],
        flap_penalty=100.0,
    )
    assert isolated.entities[0].state == "ISOLATED_TRANSITION"
    assert isolated.entities[0].pattern == "INSUFFICIENT_DATA"


def test_blast_radius_hub_is_critical_spof() -> None:
    topo = Topology(
        site_id="lab",
        nodes=[
            Node(id="spine01", label="spine01", role="router", platform="eos", tier="spine"),
            Node(id="leaf01", label="leaf01", role="switch", platform="eos", tier="leaf"),
            Node(id="leaf02", label="leaf02", role="switch", platform="eos", tier="leaf"),
        ],
        edges=[
            Edge(source="spine01", target="leaf01"),
            Edge(source="spine01", target="leaf02"),
        ],
    )
    findings = [
        Finding(device="spine01", severity="CRITICAL", message="bfd down Ethernet1"),
        Finding(device="leaf01", severity="HIGH", message="bgp 192.0.2.8 down"),
    ]
    report = analyze_blast_radius(topo, findings)
    by_name = {node.device: node for node in report.nodes}
    assert by_name["spine01"].is_articulation_point is True
    assert by_name["spine01"].risk_tier == "CRITICAL_SPOF"
    assert by_name["leaf02"].risk_tier == "HEALTHY"
    assert by_name["leaf01"].risk_tier == "DEGRADED_REDUNDANT"
    assert by_name["leaf01"].is_articulation_point is False
    assert "spine01" in report.critical_spofs
    assert by_name["spine01"].redundancy_loss_pct == pytest.approx(50.0)
    assert report.blast_radius_score > 35.0

    latent = analyze_blast_radius(topo, [])
    latent_spine = next(node for node in latent.nodes if node.device == "spine01")
    assert latent_spine.risk_tier == "LATENT_SPOF"
    assert latent.blast_radius_score < report.blast_radius_score


def test_blast_radius_dict_topology_and_to_dict() -> None:
    topo = {
        "nodes": [
            {"id": "spine-a", "role": "spine"},
            {"id": "leaf-a", "role": "leaf"},
            {"id": "leaf-b", "role": "leaf"},
        ],
        "links": [("spine-a", "leaf-a"), ("spine-a", "leaf-b")],
    }
    report = analyze_blast_radius(
        topo,
        [{"hostname": "leaf-a", "severity": "error", "message": "ospf adjacency down"}],
    )
    payload = report.to_dict()
    assert "spine-a" in payload["articulation_points"]
    assert payload["blast_radius_score"] >= 0.0
    assert payload["nodes"]


def test_config_drift_links_mtu_and_bgp_neighbor() -> None:
    diff = ConfigDiff(
        hostname="leaf01",
        added=[
            "interface Ethernet1",
            "   mtu 9000",
            "router bgp 65000",
            "   neighbor 192.0.2.10 remote-as 65001",
        ],
    )
    findings = [
        Finding(
            device="leaf01",
            severity="HIGH",
            message="Ethernet1 mtu mismatch dropped bgp neighbor 192.0.2.10",
        ),
        Finding(device="leaf02", severity="info", message="snmp poll ok"),
    ]
    report = correlate_config_drift(diff, findings)
    assert report.correlated_count == 1
    hit = report.hits[0]
    assert hit.device == "leaf01"
    blob = " ".join(hit.matched_keywords) + " " + hit.changed_line
    assert any(token in blob.lower() for token in ("mtu", "bgp", "ethernet1", "192.0.2.10"))
    assert hit.confidence > 0.5
    assert "leaf01" in hit.explanation
    assert report.to_dict()["correlated_count"] == 1


def test_config_drift_none_is_empty() -> None:
    report = correlate_config_drift(None, [Finding("leaf01", "HIGH", "bgp down")])
    assert report.hits == []


@pytest.mark.parametrize("stamp", ["0001-01-01T00:00:00+01:00", "9999-12-31T23:30:00-01:00"])
def test_deep_report_survives_edge_of_range_stamp(stamp: str) -> None:
    # Year-1/9999 offset stamps overflow datetime; the report must still run.
    from ai_log_analyzer.deep_report import run_deep_report

    log_text = "\n".join([
        f"{stamp} r1 %BGP-5-ADJCHANGE: neighbor 10.0.0.1 Down",
        _line(0, "leaf01", "%BGP-5-ADJCHANGE: neighbor 10.0.0.2 Down"),
    ])
    assert run_deep_report(log_text=log_text).payload


def test_untimed_rows_after_year_9999_anchor_keep_order_and_spacing() -> None:
    # A year-9999 anchor overflowed once the untimed offset passed a year.
    from ai_log_analyzer.analytics import _parse_ts

    ref = datetime(9999, 12, 31, 23, 0)
    stamps = [_parse_ts("", index, ref, 3600.0) for index in (8759, 8760, 40000)]
    assert stamps == sorted(stamps)
    assert stamps[1] - stamps[0] == timedelta(hours=1)
