"""Tests for the site-wide strategic optimization analyzer."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from ai_log_analyzer import llm, site_optimize


JUNOS_FW = """
version 19.2R3.5;
chassis cluster {
    cluster-id 1;
}
interfaces {
    reth0 {
        unit 0 {
            description "site1-fw-wan";
            family inet { address 89.116.175.21/26; }
        }
    }
}
protocols {
    bgp {
        group EXT {
            neighbor 10.200.0.12 { peer-as 65002; }
        }
    }
}
security-zone trust;
security-zone untrust;
"""

EOS_SW = """
hostname site1-sw-01
! Software image file is flash:/EOS-4.30.4M-x86_64.swi
no lldp run
ntp server 10.1.1.10
router bgp 65003
   neighbor 10.200.0.13 remote-as 65004
interface Ethernet1
   ip address 10.10.0.2/30
"""


@pytest.fixture(autouse=True)
def restore_llm_state():
    snap = dict(llm._state)
    yield
    for k, v in snap.items():
        llm._state[k] = v


@pytest.mark.unit
def test_collect_site_facts_returns_structured_summary():
    facts = site_optimize.collect_site_facts("TEST1", [
        {"hostname": "test1-fw-01", "platform": "junos", "config_text": JUNOS_FW},
        {"hostname": "test1-sw-01", "platform": "eos",   "config_text": EOS_SW},
    ])
    assert facts["site_id"] == "TEST1"
    assert facts["device_count"] == 2
    assert facts["by_role"]["firewall"] == 1
    assert facts["by_role"]["switch"] == 1
    assert facts["protocols"]["chassis_cluster_ha"] is True
    assert facts["bgp"]["total_neighbors"] >= 2
    # Software risk detection — 19.2R3.5 should appear in risky_devices
    risky_versions = [r["version"] for r in facts["software"]["risky_devices"]]
    assert "19.2R3.5" in risky_versions


@pytest.mark.unit
def test_facts_include_compliance_score():
    facts = site_optimize.collect_site_facts("X", [
        {"hostname": "x-fw-01", "platform": "junos", "config_text": JUNOS_FW},
    ])
    assert "compliance" in facts
    assert 0 <= facts["compliance"]["pass_rate"] <= 100


@pytest.mark.unit
def test_facts_detect_missing_operations():
    facts = site_optimize.collect_site_facts("X", [
        {"hostname": "x-fw-01", "platform": "junos", "config_text": JUNOS_FW},
    ])
    # Junos snippet above has no NTP/syslog/AAA → all should flag
    assert "x-fw-01" in facts["operations"]["devices_without_ntp"]


@pytest.mark.unit
def test_analyze_site_wide_returns_deterministic_advice_when_llm_off():
    llm.set_enabled(False)
    r = site_optimize.analyze_site_wide("X", [
        {"hostname": "x-fw-01", "platform": "junos", "config_text": JUNOS_FW},
    ])
    assert r["llm_powered"] is False
    assert "disabled" in r["site_summary"].lower()
    # Deterministic baseline: this fixture has no NTP/syslog/AAA → some gaps
    assert isinstance(r["gaps"], list)
    assert len(r["gaps"]) >= 1
    assert all("requires_human_review" in g for g in r["gaps"])
    # Schema additions
    assert "best_practices_missing" in r
    # Facts should still be present
    assert "facts" in r and r["facts"]["device_count"] == 1


@pytest.mark.unit
def test_analyze_site_wide_with_mocked_llm_parses_json():
    fake_response = (
        '{"site_summary": "Tier 2 site with single ISP exposure.", '
        '"maturity_score": 55, "maturity_tier": "Tier 2", '
        '"best_practices_applied": ["chassis cluster HA"], '
        '"gaps": [{"category": "isp_redundancy", "severity": "critical", '
        '"title": "Single ISP exposure", '
        '"current_state": "Only one ISP detected", '
        '"ideal_state": "Dual ISPs from different transits", '
        '"rationale": "ISP failure = full outage", '
        '"implementation": ["Procure second ISP", "Add BGP peering"], '
        '"config_changes": {"x-fw-01": ["set protocols bgp group EXT2 peer-as 65010"]}, '
        '"estimated_effort": "L", "roi": "high"}], '
        '"roadmap": {"phase_1_immediate_0_30_days": ["Single ISP exposure"]}}'
    )
    llm.set_enabled(True)
    with patch.object(llm, "query", return_value=fake_response):
        r = site_optimize.analyze_site_wide("X", [
            {"hostname": "x-fw-01", "platform": "junos", "config_text": JUNOS_FW},
        ])
    assert r["llm_powered"] is True
    assert r["maturity_score"] == 55
    assert r["maturity_tier"] == "Tier 2"
    assert len(r["gaps"]) == 1
    assert r["gaps"][0]["category"] == "isp_redundancy"
    assert "Single ISP exposure" in r["roadmap"]["phase_1_immediate_0_30_days"]


@pytest.mark.unit
def test_analyze_site_wide_falls_back_to_deterministic_on_non_json():
    llm.set_enabled(True)
    # Both first query AND retry return non-JSON prose → fall back to deterministic
    with patch.object(llm, "query", return_value="This site looks great!"):
        r = site_optimize.analyze_site_wide("X", [
            {"hostname": "x-fw-01", "platform": "junos", "config_text": JUNOS_FW},
        ])
    # New behavior: not just empty — we return useful deterministic advice
    assert r["llm_powered"] is False
    assert r.get("llm_parse_failed") is True
    assert isinstance(r["gaps"], list) and len(r["gaps"]) >= 1
    assert "raw" in r  # raw LLM text preserved for debugging


@pytest.mark.unit
def test_split_scores_present_in_deterministic_path():
    """Deterministic path always emits fabric_design + operational_readiness scores."""
    r = site_optimize.analyze_site_wide("Z", [
        {"hostname": "z-fw-01", "platform": "junos", "config_text": JUNOS_FW},
    ])
    assert "fabric_design_score" in r
    assert "operational_readiness_score" in r
    assert "maturity_score" in r
    assert 0 <= r["fabric_design_score"] <= 100
    assert 0 <= r["operational_readiness_score"] <= 100


@pytest.mark.unit
def test_split_scores_categorize_correctly():
    """isp_redundancy → fabric_design; aaa/monitoring → operational_readiness."""
    fabric_only = [
        {"category": "isp_redundancy", "severity": "critical"},
        {"category": "ha", "severity": "high"},
    ]
    ops_only = [
        {"category": "aaa", "severity": "critical"},
        {"category": "monitoring", "severity": "high"},
    ]
    s1 = site_optimize._score_split(fabric_only)
    s2 = site_optimize._score_split(ops_only)
    # Fabric gaps shouldn't penalize ops score and vice versa
    assert s1["fabric_design_score"] < 100
    assert s1["operational_readiness_score"] == 100
    assert s2["operational_readiness_score"] < 100
    assert s2["fabric_design_score"] == 100


@pytest.mark.unit
def test_llm_hostname_anchoring_drops_invented_hosts():
    """Unknown hostnames in config_changes are filtered out post-validation."""
    fake = (
        '{"site_summary": "Test", "maturity_score": 50, "maturity_tier": "Tier 2", '
        '"gaps": [{"category": "bgp_tuning", "severity": "high", '
        '"title": "Add BFD", "current_state": "x", "ideal_state": "y", '
        '"rationale": "z", "implementation": ["step"], '
        '"config_changes": {"x-fw-01": ["set bfd"], "CR-01": ["bogus"], "BR-99": ["fake"]}, '
        '"estimated_effort": "M", "roi": "high"}], "roadmap": {}}'
    )
    llm.set_enabled(True)
    with patch.object(llm, "query", return_value=fake):
        r = site_optimize.analyze_site_wide("X", [
            {"hostname": "x-fw-01", "platform": "junos", "config_text": JUNOS_FW},
        ])
    assert r["llm_powered"] is True
    assert len(r["gaps"]) == 1
    changes = r["gaps"][0]["config_changes"]
    # Real host kept, invented placeholders dropped
    assert "x-fw-01" in changes
    assert "CR-01" not in changes
    assert "BR-99" not in changes


@pytest.mark.unit
def test_allowed_hostnames_helper_extracts_from_facts():
    facts = site_optimize.collect_site_facts("T", [
        {"hostname": "t-fw-01", "platform": "junos", "config_text": JUNOS_FW},
        {"hostname": "t-sw-01", "platform": "eos",   "config_text": EOS_SW},
    ])
    hosts = site_optimize._allowed_hostnames(facts)
    assert "t-fw-01" in hosts
    assert "t-sw-01" in hosts
    assert hosts == sorted(hosts)  # deterministic ordering


@pytest.mark.unit
def test_facts_isps_detection_active_vs_shutdown():
    cfg_with_telia = (
        "interfaces {\n  ge-0/0/0 {\n    unit 0 {\n"
        '      description "telia ISP transit";\n'
        "      family inet { address 89.116.175.21/26; }\n"
        "    }\n  }\n}\n"
    )
    facts = site_optimize.collect_site_facts("Y", [
        {"hostname": "y-fw-01", "platform": "junos", "config_text": cfg_with_telia},
    ])
    # ISP detection runs through site_diagram — should pick up Telia
    assert any(i["name"].lower() == "telia" for i in facts["isps"])
