"""Coverage for modules phases 0-12 left untested: reports.py, runbook.py,
topology.py, and their web routes (/api/report, /api/runbook, /api/topology,
plus the 400-paths of /api/diff and /api/copilot).
"""
from __future__ import annotations

import pytest

from ai_log_analyzer import reports, runbook
from ai_log_analyzer import topology as topo_mod


pytestmark = pytest.mark.unit


SITE_RESULT = {
    "site_id": "LAB-X",
    "site_summary": "Two HA firewalls drifted.",
    "site_score": 72,
    "llm_powered": True,
    "topology": {
        "devices_seen": ["fw-01", "fw-02"],
        "roles": {"firewall": ["fw-01", "fw-02"]},
        "isp_uplinks": ["fw-01: isp_a"],
    },
    "cross_device_findings": [{
        "severity": "high",
        "category": "ha_drift",
        "title": "BFD enabled on fw-01 but not fw-02",
        "affected_devices": ["fw-01", "fw-02"],
        "evidence": "fw-01: set protocols bgp bfd",
        "rationale": "Asymmetric failover detection.",
        "fix_per_device": {"fw-02": ["set protocols bgp group isp bfd-liveness-detection minimum-interval 300"]},
        "verify_cli": ["show bfd session"],
    }],
    "monitoring_gaps": ["Alert when BFD session count drops"],
}

OPTIMIZE_RESULT = {
    "hostname": "rt-01",
    "platform": "junos",
    "score": 80,
    "summary": "Mostly sane.",
    "llm_powered": False,
    "findings": [{
        "severity": "medium",
        "category": "monitoring",
        "title": "No SNMPv3",
        "evidence": "snmp { community public; }",
        "rationale": "Cleartext SNMP.",
        "patch": ["set snmp v3 usm local-engine user monitor"],
    }],
}


# ── reports.py ───────────────────────────────────────────────────────────────

def test_markdown_site_report_carries_findings_and_fixes():
    md = reports.to_markdown_site(SITE_RESULT)
    assert "# Site Analysis: LAB-X" in md
    assert "[HIGH] BFD enabled on fw-01 but not fw-02" in md
    assert "set protocols bgp group isp bfd-liveness-detection" in md
    assert "Monitoring Gaps (1)" in md


def test_markdown_optimize_report():
    md = reports.to_markdown_optimize(OPTIMIZE_RESULT)
    assert "rt-01" in md
    assert "[MEDIUM] No SNMPv3" in md
    assert "set snmp v3" in md


def test_csv_findings_handles_both_result_shapes():
    site_csv = reports.to_csv_findings(SITE_RESULT)
    assert "severity,category,title,affected,evidence,rationale" in site_csv
    assert "fw-01, fw-02" in site_csv
    dev_csv = reports.to_csv_findings(OPTIMIZE_RESULT)
    assert "No SNMPv3" in dev_csv
    assert "rt-01" in dev_csv


def test_html_site_report_is_standalone_html():
    html = reports.to_html_site(SITE_RESULT, mermaid_diagram="graph TD; a-->b")
    assert "<html" in html.lower()
    assert "BFD enabled on fw-01" in html
    assert "graph TD" in html


# ── runbook.py ───────────────────────────────────────────────────────────────

def test_ansible_playbook_per_platform_module():
    f = SITE_RESULT["cross_device_findings"][0]
    junos = runbook.to_ansible_playbook(f, ["fw-02"], platform_hint="junos")
    assert "junipernetworks.junos.junos_config" in junos
    assert "bfd-liveness-detection" in junos
    eos = runbook.to_ansible_playbook(f, ["sw-01"], platform_hint="eos")
    assert "arista.eos.eos_config" in eos
    frr = runbook.to_ansible_playbook(f, ["r1"], platform_hint="frr")
    assert "ansible.builtin.shell" in frr


def test_netmiko_script_device_type_and_commands():
    f = OPTIMIZE_RESULT["findings"][0]
    py = runbook.to_netmiko_script(f, ["rt-01"], platform_hint="junos")
    assert "juniper_junos" in py
    assert "set snmp v3" in py
    assert "PASSWORD = os.environ.get" in py  # never hardcoded


def test_extract_cmds_dedups_across_shapes():
    finding = {
        "patch": ["cmd a", "cmd b"],
        "fix_per_device": {"h1": ["cmd a"]},
        "deep_analysis": {"phases": [{"actions": [
            {"cli": {"junos": "cmd c"}},
            {"cli": {"any": "cmd b"}},
        ]}]},
    }
    cmds = runbook._extract_cmds(finding, "junos")
    assert cmds == ["cmd a", "cmd b", "cmd c"]


# ── topology.py (against a bundled site) ─────────────────────────────────────

@pytest.fixture(scope="module")
def lab_alpha_topo():
    from ai_log_analyzer.web.app import _load_site_devices
    devices, manifest = _load_site_devices("lab-alpha")
    assert devices, "bundled lab-alpha site must be present"
    topo = topo_mod.build_topology("LAB-ALPHA", devices)
    if manifest:
        topo_mod.apply_manifest_metadata(topo, manifest)
    return topo


def test_build_topology_finds_nodes_and_edges(lab_alpha_topo):
    d = lab_alpha_topo.to_dict()
    assert len(d["nodes"]) == 5
    assert d["edges"], "edge inference should find at least one link"
    hostnames = {n["id"] for n in d["nodes"]}
    assert any("fw-" in h for h in hostnames)


def test_topology_export_formats(lab_alpha_topo):
    mermaid = topo_mod.to_mermaid(lab_alpha_topo)
    assert "graph TD" in mermaid
    assert "alpha_fw_01a" in mermaid
    dot = topo_mod.to_graphviz(lab_alpha_topo)
    assert "graph" in dot.split("\n", 1)[0]


def test_overlay_findings_marks_affected_nodes(lab_alpha_topo):
    d0 = lab_alpha_topo.to_dict()
    target = d0["nodes"][0]["id"]
    topo_mod.overlay_findings(lab_alpha_topo, [
        {"severity": "critical", "affected_devices": [target]},
    ])
    node = next(n for n in lab_alpha_topo.to_dict()["nodes"] if n["id"] == target)
    assert node.get("finding_severity") == "critical"


# ── web routes ───────────────────────────────────────────────────────────────

@pytest.fixture()
def client():
    from ai_log_analyzer.web.app import create_app
    app = create_app()
    app.testing = True
    with app.test_client() as c:
        yield c


def test_api_topology_json_mermaid_dot(client):
    r = client.get("/api/topology/lab-alpha")
    assert r.status_code == 200
    assert len(r.get_json()["nodes"]) == 5
    r = client.get("/api/topology/lab-alpha?format=mermaid")
    assert r.status_code == 200 and b"graph" in r.data
    r = client.get("/api/topology/lab-alpha?format=dot")
    assert r.status_code == 200
    assert client.get("/api/topology/no-such-site").status_code == 404
    assert client.get("/api/topology/bad.id").status_code == 400


def test_api_runbook_formats(client):
    body = {"finding": OPTIMIZE_RESULT["findings"][0],
            "hostnames": ["rt-01"], "platform": "junos"}
    r = client.post("/api/runbook", json={**body, "format": "ansible"})
    assert r.status_code == 200 and b"junos_config" in r.data
    r = client.post("/api/runbook", json={**body, "format": "python"})
    assert r.status_code == 200 and b"ConnectHandler" in r.data
    assert client.post("/api/runbook", json={**body, "format": "bogus"}).status_code == 400
    assert client.post("/api/runbook", json={"format": "ansible"}).status_code == 400


def test_api_report_md_and_csv(client):
    r = client.post("/api/report/lab-alpha",
                    json={"format": "md", "analysis_result": SITE_RESULT})
    assert r.status_code == 200 and b"Site Analysis" in r.data
    r = client.post("/api/report/lab-alpha",
                    json={"format": "csv", "analysis_result": OPTIMIZE_RESULT})
    assert r.status_code == 200 and b"No SNMPv3" in r.data
    assert client.post("/api/report/lab-alpha", json={"format": "md"}).status_code == 400


def test_api_diff_and_copilot_validation(client):
    assert client.post("/api/diff", json={"before": "x"}).status_code == 400
    assert client.post("/api/copilot", json={}).status_code == 400
    assert client.post("/api/copilot", json={"question": "hi"}).status_code == 400
