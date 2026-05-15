"""Smoke tests for the batch of new feature modules.

Covers: topology, compliance, postmortem, diff, runbook, reports.
"""
from __future__ import annotations

import pytest

from ai_log_analyzer import (compliance, diff as diff_mod, postmortem,
                              reports, runbook, topology)


JUNOS_CFG = """
system {
    host-name peer-a-fw-01;
    services {
        ssh { protocol-version v2; root-login deny; }
    }
    syslog {
        host 10.1.1.1 any notice;
    }
    ntp {
        server 10.1.1.10;
        server 10.1.1.11;
    }
}
protocols {
    bgp {
        group EXTERNAL {
            neighbor 10.200.0.12 { peer-as 65002; authentication-key "<REDACTED>"; }
        }
    }
}
interfaces {
    ge-0/0/0 { description "uplink to peer-a-rt-01"; mtu 9000; }
}
"""

EOS_CFG = """
! device: peer-a-sw-04
hostname peer-a-sw-04
no lldp run
ntp server 10.1.1.10
router bgp 65003
   neighbor 10.200.0.13 remote-as 65004
interface Ethernet1
   description uplink to peer-a-rt-02
   mtu 9214
"""


# ── Topology ─────────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_topology_extracts_role_from_hostname():
    topo = topology.build_topology("PEER-A", [
        {"hostname": "peer-a-fw-01", "config_text": JUNOS_CFG, "platform": "junos"},
        {"hostname": "peer-a-sw-04", "config_text": EOS_CFG,   "platform": "eos"},
    ])
    roles = {n.id: n.role for n in topo.nodes}
    assert roles["peer-a-fw-01"] == "firewall"
    assert roles["peer-a-sw-04"] == "switch"


@pytest.mark.unit
def test_topology_detects_bgp():
    topo = topology.build_topology("X", [
        {"hostname": "h1", "config_text": JUNOS_CFG, "platform": "junos"},
    ])
    assert topo.nodes[0].has_bgp


@pytest.mark.unit
def test_topology_to_mermaid_contains_nodes():
    topo = topology.build_topology("X", [
        {"hostname": "peer-a-fw-01", "config_text": JUNOS_CFG, "platform": "junos"},
        {"hostname": "peer-a-sw-04", "config_text": EOS_CFG, "platform": "eos"},
    ])
    out = topology.to_mermaid(topo)
    assert "graph TD" in out
    assert "peer_a_fw_01" in out and "peer_a_sw_04" in out


@pytest.mark.unit
def test_topology_to_graphviz_is_valid_dot():
    topo = topology.build_topology("X", [
        {"hostname": "h1", "config_text": JUNOS_CFG, "platform": "junos"},
    ])
    out = topology.to_graphviz(topo)
    assert out.startswith('digraph "X"') and out.endswith("}")


@pytest.mark.unit
def test_topology_overlay_findings_sets_severity():
    topo = topology.build_topology("X", [
        {"hostname": "h1", "config_text": JUNOS_CFG, "platform": "junos"},
    ])
    topology.overlay_findings(topo, [
        {"severity": "critical", "affected_devices": ["h1"]},
        {"severity": "low", "affected_devices": ["h1"]},
    ])
    assert topo.nodes[0].finding_severity == "critical"  # worst wins


# ── Compliance ───────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_compliance_ssh_v2_passes():
    checks = compliance.check_device(JUNOS_CFG, "junos", "h1")
    ssh = next(c for c in checks if c.rule_id == "ssh-v2-only")
    assert ssh.passed


@pytest.mark.unit
def test_compliance_no_lldp_fails_when_disabled():
    checks = compliance.check_device(EOS_CFG, "eos", "sw1")
    lldp = next(c for c in checks if c.rule_id == "lldp-enabled")
    assert not lldp.passed


@pytest.mark.unit
def test_compliance_bundle_report_structure():
    devs = [{"hostname": "h1", "platform": "junos", "config_text": JUNOS_CFG},
            {"hostname": "h2", "platform": "eos",   "config_text": EOS_CFG}]
    r = compliance.check_bundle(devs)
    assert r["total_checks"] > 0
    assert "rules" in r and "checks" in r
    assert 0 <= r["pass_rate"] <= 100


# ── Post-mortem search ───────────────────────────────────────────────────────

@pytest.mark.unit
def test_postmortem_literal_pattern_finds_match():
    devs = [{"hostname": "sw1", "platform": "eos", "config_text": EOS_CFG}]
    r = postmortem.search_fleet(devs, "no lldp run")
    assert r["devices_with_matches"] == 1
    assert r["total_matches"] >= 1


@pytest.mark.unit
def test_postmortem_no_match_returns_zero():
    devs = [{"hostname": "sw1", "platform": "eos", "config_text": EOS_CFG}]
    r = postmortem.search_fleet(devs, "this-text-not-present")
    assert r["devices_with_matches"] == 0


@pytest.mark.unit
def test_postmortem_invalid_regex_returns_error():
    devs = [{"hostname": "sw1", "platform": "eos", "config_text": "x"}]
    r = postmortem.search_fleet(devs, "*invalid[regex")
    assert "error" in r


@pytest.mark.unit
def test_fingerprint_finding_extracts_quoted_config():
    f = {"evidence": "Config shows 'no lldp run' on the device"}
    assert postmortem.fingerprint_finding(f) == "no lldp run"


# ── Diff ─────────────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_diff_structured_counts_additions():
    before = "interface ge-0/0/0\n  mtu 1500\n"
    after  = "interface ge-0/0/0\n  mtu 9000\n  description uplink\n"
    s = diff_mod.structured_diff(before, after)
    assert s["lines_added"] >= 1 and s["lines_removed"] >= 1


@pytest.mark.unit
def test_text_diff_produces_unified():
    out = diff_mod.text_diff("a\nb\n", "a\nc\n")
    assert "--- before" in out and "+++ after" in out


# ── Runbook generator ───────────────────────────────────────────────────────

@pytest.mark.unit
def test_ansible_playbook_includes_commands():
    finding = {"title": "Enable BFD", "severity": "high",
               "fix_per_device": {"h1": ["set protocols bgp group X bfd-liveness-detection minimum-interval 300"]}}
    pb = runbook.to_ansible_playbook(finding, ["h1"], platform_hint="junos")
    assert "junipernetworks.junos.junos_config" in pb
    assert "bfd-liveness-detection" in pb


@pytest.mark.unit
def test_netmiko_script_includes_device_type():
    finding = {"title": "x", "patch": ["lldp run"]}
    s = runbook.to_netmiko_script(finding, ["sw1"], platform_hint="eos")
    assert "arista_eos" in s
    assert "lldp run" in s


# ── Reports ──────────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_markdown_site_report_includes_findings():
    result = {
        "site_id": "TEST1", "site_score": 80, "site_summary": "Looks fine.",
        "cross_device_findings": [
            {"severity": "high", "category": "convergence", "title": "BFD missing",
             "affected_devices": ["a", "b"], "evidence": "no bfd line",
             "rationale": "slow failover",
             "fix_per_device": {"a": ["neighbor X bfd"]}},
        ],
        "monitoring_gaps": ["alert on BGP flap"], "llm_powered": True,
    }
    md = reports.to_markdown_site(result)
    assert "TEST1" in md and "BFD missing" in md and "neighbor X bfd" in md


@pytest.mark.unit
def test_html_report_is_well_formed():
    result = {"site_id": "T", "site_score": 50, "site_summary": "x",
              "cross_device_findings": [{"severity": "high", "title": "t",
                                          "affected_devices": ["a"]}]}
    h = reports.to_html_site(result)
    assert h.startswith("<!DOCTYPE html>") and h.endswith("</html>")


@pytest.mark.unit
def test_csv_findings_export_has_header():
    result = {"findings": [{"severity": "high", "category": "x",
                             "title": "t", "evidence": "e", "rationale": "r"}],
              "hostname": "h1"}
    csv_text = reports.to_csv_findings(result)
    assert "severity,category,title" in csv_text
    assert "high,x,t" in csv_text
