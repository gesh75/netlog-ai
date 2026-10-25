"""Topology-aware alert suppression and Ansible / Nornir remediation export."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from ai_log_analyzer import webhooks
from ai_log_analyzer.adapters.file import parse_file
from ai_log_analyzer.analyzer import analyze
from ai_log_analyzer.classifier import LogEvent, classify_events
from ai_log_analyzer.remediation import (
    RemediationActionType,
    RemediationGenerator,
    RemediationPlan,
    SafetyViolationError,
    VendorOS,
)
from ai_log_analyzer.remediation_export import (
    ExportUnsupportedError,
    config_blocks,
    export_plan,
    to_ansible_playbook,
    to_nornir_script,
)
from ai_log_analyzer.suppression import Topology, load_topology, suppress_alerts

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).parent / "fixtures" / "multivendor"

# core-01 dies and logs nothing; four leafs lose their /31 sessions to it.
CORE_STORM = [
    LogEvent(f"2026-10-20T10:00:0{i}Z", f"leaf-0{i}", "rpd", "err",
             f"RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 10.0.0.{2 * i} (External AS 65000) changed state "
             f"from Established to Idle (event HoldTime) (instance master)")
    for i in range(1, 5)
] + [
    LogEvent(f"2026-10-20T10:00:1{i}Z", f"leaf-0{i}", "mib2d", "err",
             f"SNMP_TRAP_LINK_DOWN: ifIndex 51{i}, ifAdminStatus up(1), ifOperStatus down(2), ifName et-0/0/{i}")
    for i in range(1, 5)
] + [
    LogEvent("2026-10-20T10:00:30Z", "spine-09", "rpd", "err",
             "RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 10.9.9.9 (External AS 65999) changed state "
             "from Established to Idle (event HoldTime) (instance master)"),
]
CORE_MAP = {"devices": {"core-01": {"ips": ["10.0.0.2", "10.0.0.4", "10.0.0.6", "10.0.0.8"],
                                    "children": ["leaf-01", "leaf-02", "leaf-03", "leaf-04"],
                                    "role": "core"}}}


def _analyze(events, manifest=None):
    return analyze(events, use_llm=False, site_manifest=manifest).to_dict()


# ── Suppression ─────────────────────────────────────────────────────────────

def test_dead_core_router_groups_leaf_storm_under_one_root():
    result = _analyze(CORE_STORM, CORE_MAP)
    groups = result["suppression"]["groups"]
    assert len(groups) == 1
    g = groups[0]
    assert g["kind"] == "device_unreachable" and g["root_hosts"] == ["core-01"]
    assert g["inferred"] is True                          # core-01 itself logged nothing
    assert g["child_devices"] == ["leaf-01", "leaf-02", "leaf-03", "leaf-04"]
    assert g["suppressed_count"] == 8                      # 4 BGP + 4 link-down
    items = {a["description"]: a for a in result["action_items"]}
    # spine-09's unrelated peer keeps the BGP group live; the link-downs are all children
    assert items["Interface link down"]["suppressed_by"] == g["id"]
    assert "suppressed_by" not in items["BGP hold timer expired"]


def test_core_root_inferred_from_addresses_without_children_list():
    topo = Topology(ips={ip: "core-01" for ip in CORE_MAP["devices"]["core-01"]["ips"]})
    res = suppress_alerts(classify_events(CORE_STORM[:4])[0], topo)
    assert res["groups"][0]["kind"] == "device_unreachable"
    assert res["groups"][0]["suppressed_count"] == 4


def test_single_reporter_does_not_invent_a_dead_device():
    topo = Topology(ips={"10.0.0.2": "core-01"})
    res = suppress_alerts(classify_events(CORE_STORM[:1])[0], topo)
    assert res["groups"] == []


def test_sdwan_transport_root_groups_ipsec_and_bgp_across_vendors():
    result = _analyze(parse_file(FIXTURES / "fortigate_sdwan_ipsec_bgp_cascade.log"))
    (g,) = result["suppression"]["groups"]
    assert g["kind"] == "transport" and g["root"]["event_type"] == "sdwan_sla"
    assert g["root_hosts"] == ["fgt-hq-01"] and g["child_devices"] == ["dc1-edge-01"]
    child_types = {(c["hostname"], c["event_type"]) for c in g["children"]}
    assert ("dc1-edge-01", "bgp_session") in child_types      # far end via the /30
    assert ("dc1-edge-01", "ipsec_tunnel") in child_types     # peer = FortiGate locip
    items = {a["description"]: a for a in result["action_items"]}
    assert items["BGP hold timer expired"]["suppressed_by"] == g["id"]
    assert items["VPN/IPsec tunnel failure"]["suppressed_by"] == g["id"]
    assert "suppressed_by" not in items["SD-WAN SLA violation / member out of SLA"]   # the root
    assert "suppressed_by" not in items["BGP peer idle / notification"]               # unrelated EOS
    # roots rank above their suppressed children of the same severity
    high = [a for a in result["action_items"] if a["severity"] == "high"]
    flags = [bool(a.get("suppressed_by")) for a in high]
    assert flags == sorted(flags)


def test_firewall_ha_pair_root_absorbs_vpn_and_bgp_fallout():
    result = _analyze(parse_file(FIXTURES / "panos_ha_vpn_routing.log"))
    g = next(g for g in result["suppression"]["groups"] if g["kind"] == "platform")
    assert g["root_hosts"] == ["pa-dc2-01", "pa-dc2-02"]       # HA peer inferred
    assert {c["event_type"] for c in g["children"]} >= {"ike_phase1", "ike_phase2", "bgp_session"}


def test_declared_ha_peer_and_children_from_dependency_file(tmp_path, monkeypatch):
    path = tmp_path / "deps.json"
    path.write_text(json.dumps({"devices": {"fw-a": {"ha_peer": "fw-b", "children": ["branch-1"]}}}))
    monkeypatch.setenv("AI_LOG_ANALYZER_DEPENDENCIES", str(path))
    topo = load_topology()
    assert topo.ha_peer == {"fw-a": "fw-b", "fw-b": "fw-a"} and topo.children == {"fw-a": {"branch-1"}}


def test_webhook_pages_roots_not_children():
    result = _analyze(parse_file(FIXTURES / "fortigate_sdwan_ipsec_bgp_cascade.log"))
    payload = webhooks.build_payload(result, "fgt", "generic", "high")
    descriptions = [a["description"] for a in payload["action_items"]]
    assert "BGP hold timer expired" not in descriptions
    assert "SD-WAN SLA violation / member out of SLA" in descriptions
    assert payload["suppressed_alerts"] >= 6
    slack = webhooks.build_payload(result, "fgt", "slack", "high")["text"]
    assert "dependent alert(s) grouped" in slack


# ── Ansible export ──────────────────────────────────────────────────────────

GEN = RemediationGenerator()


def _drain(vendor: VendorOS, intf: str) -> RemediationPlan:
    return GEN.build_graceful_link_drain("dev1", vendor, intf, bgp_neighbor_ip="10.0.0.1")


def _play(plan: RemediationPlan) -> dict:
    text = to_ansible_playbook(plan)
    assert text.startswith("# netlog-ai remediation")
    (play,) = yaml.safe_load(text)
    return play


def _task(play: dict, prefix: str) -> dict:
    return next(t for t in play["tasks"] if t["name"].startswith(prefix))


@pytest.mark.parametrize("vendor,intf,module", [
    (VendorOS.CISCO_IOS_XE, "GigabitEthernet0/1", "cisco.ios.ios_config"),
    (VendorOS.CISCO_NXOS, "Ethernet1/1", "cisco.nxos.nxos_config"),
    (VendorOS.ARISTA_EOS, "Ethernet1", "arista.eos.eos_config"),
    (VendorOS.JUNIPER_JUNOS, "xe-0/0/1", "junipernetworks.junos.junos_config"),
    (VendorOS.FORTINET_FORTIOS, "wan1", "fortinet.fortios.fortios_system_interface"),
    (VendorOS.PALOALTO_PANOS, "ethernet1/1", "paloaltonetworks.panos.panos_interface"),
])
def test_playbook_has_dry_run_then_guarded_apply_with_rollback(vendor, intf, module):
    play = _play(_drain(vendor, intf))
    assert play["hosts"] == "dev1" and play["gather_facts"] is False
    first = play["tasks"][0]
    assert first["name"].startswith("Pre-check") and first.get("check_mode") is False
    dry = _task(play, "Dry run")
    assert dry["check_mode"] is True and dry["diff"] is True and dry["tags"] == ["dry_run"]
    assert module in dry
    guarded = next(t for t in play["tasks"] if "block" in t)
    assert guarded["when"] == "not ansible_check_mode"
    assert any(module in t for t in guarded["block"])
    rollback = guarded["rescue"][0]
    assert rollback["when"] == "netlog_apply is defined and netlog_apply.changed"
    assert "ansible.builtin.fail" in guarded["rescue"][-1]


def test_junos_playbook_uses_native_commit_confirmed_and_rollback():
    play = _play(GEN.build_graceful_link_drain("mx1", VendorOS.JUNIPER_JUNOS, "xe-0/0/1", rollback_minutes=7))
    block = next(t for t in play["tasks"] if "block" in t)
    apply, confirm = block["block"][0], block["block"][-1]   # the verification gate sits in between
    assert apply["junipernetworks.junos.junos_config"]["confirm"] == 7
    assert confirm["junipernetworks.junos.junos_config"] == {"confirm_commit": True}
    assert block["rescue"][0]["junipernetworks.junos.junos_config"] == {"rollback": 1}
    assert play["connection"] == "ansible.netcommon.netconf"


def test_nxos_playbook_checkpoints_and_rolls_back_to_it():
    play = _play(_drain(VendorOS.CISCO_NXOS, "Ethernet1/1"))
    block = next(t for t in play["tasks"] if "block" in t)
    checkpoint = block["block"][0]["cisco.nxos.nxos_command"]["commands"][0]
    assert checkpoint.startswith("checkpoint netlog-")
    assert block["rescue"][0]["cisco.nxos.nxos_rollback"]["rollback_to"] == checkpoint.split()[-1]


def test_ios_blocks_and_inverse_use_parents():
    play = _play(_drain(VendorOS.CISCO_IOS_XE, "GigabitEthernet0/1"))
    assert play["vars"]["netlog_blocks"] == [{"parents": ["interface GigabitEthernet0/1"], "lines": ["shutdown"]}]
    assert play["vars"]["netlog_inverse_blocks"] == [{"parents": ["interface GigabitEthernet0/1"],
                                                     "lines": ["no shutdown"]}]


def test_panos_playbook_snapshots_and_restores():
    play = _play(_drain(VendorOS.PALOALTO_PANOS, "ethernet1/1"))
    block = next(t for t in play["tasks"] if "block" in t)
    save = block["block"][0]["paloaltonetworks.panos.panos_op"]
    assert save["cmd"].startswith("<save><config><to>netlog-ai-") and save["cmd_is_xml"] is True
    assert block["rescue"][0]["paloaltonetworks.panos.panos_op"]["cmd"].startswith("<load><config><from>")
    assert any("paloaltonetworks.panos.panos_commit_firewall" in t for t in block["rescue"])


def test_frr_playbook_backs_up_and_restores_frr_conf():
    play = _play(_drain(VendorOS.FRR, "eth1"))
    block = next(t for t in play["tasks"] if "block" in t)
    assert block["block"][0]["ansible.builtin.copy"]["src"] == "/etc/frr/frr.conf"
    assert "ansible.builtin.systemd" in block["rescue"][1]


def test_custom_cli_plan_rescue_lists_manual_rollback_when_no_inverse():
    plan = GEN.build_custom_safe_plan("r1", VendorOS.CISCO_IOS_XE, ["router bgp 65000", " bgp log-neighbor-changes"],
                                      ["show ip bgp summary"], ["show ip bgp summary"], "enable logging")
    play = _play(plan)
    rescue = next(t for t in play["tasks"] if "block" in t)["rescue"]
    assert rescue[0]["ansible.builtin.fail"]["msg"].endswith("configure revert now")
    assert play["vars"]["netlog_blocks"] == [{"parents": ["router bgp 65000"], "lines": ["bgp log-neighbor-changes"]}]


def test_object_based_vendors_refuse_unmapped_actions_and_sdwan_points_to_vmanage():
    custom = GEN.build_custom_safe_plan("fgt", VendorOS.FORTINET_FORTIOS, ["config system dns"], [], [], "x")
    with pytest.raises(ExportUnsupportedError, match="only graceful_link_drain"):
        to_ansible_playbook(custom)
    with pytest.raises(ExportUnsupportedError, match="vManage"):
        to_ansible_playbook(_drain(VendorOS.CISCO_SDWAN, "GigabitEthernet1"))


def test_export_rescreens_with_safety_guardrail():
    plan = _drain(VendorOS.CISCO_IOS_XE, "Gi1")
    plan.body_commands = ["interface Gi1", " shutdown", "write erase"]   # tampered after build
    with pytest.raises(SafetyViolationError):
        to_ansible_playbook(plan)
    plan.body_commands = ["interface Gi1", " shutdown"]
    plan.inverse_commands = ["reload"]
    with pytest.raises(SafetyViolationError):
        to_nornir_script(plan)


def test_config_blocks_hierarchy():
    assert config_blocks(["ip as-path access-list X permit .*", "interface Ethernet1", "   shutdown",
                          "router bgp 1", "  address-family ipv4", "    network 10.0.0.0/8"]) == [
        {"parents": [], "lines": ["ip as-path access-list X permit .*"]},
        {"parents": ["interface Ethernet1"], "lines": ["shutdown"]},
        {"parents": ["router bgp 1", "address-family ipv4"], "lines": ["network 10.0.0.0/8"]},
    ]


def test_yaml_emitter_quotes_jinja_and_specials():
    plan = _drain(VendorOS.ARISTA_EOS, "Ethernet1")
    plan.rationale = 'contains: colon, "quotes" and # hash'
    play = _play(plan)
    assert _task(play, "Dry run")["arista.eos.eos_config"]["lines"] == "{{ item.lines }}"


# ── Nornir export + CLI wiring ──────────────────────────────────────────────

def test_nornir_script_is_valid_python_and_dry_run_by_default():
    script = to_nornir_script(_drain(VendorOS.JUNIPER_JUNOS, "xe-0/0/1"))
    compile(script, "netlog_nornir.py", "exec")
    assert "dry_run=not APPLY" in script and 'APPLY = "--apply" in sys.argv' in script
    with pytest.raises(ExportUnsupportedError):
        to_nornir_script(_drain(VendorOS.FORTINET_FORTIOS, "wan1"))


def test_export_plan_formats():
    plan = _drain(VendorOS.ARISTA_EOS, "Ethernet1")
    assert json.loads(export_plan(plan, "json"))["plan_id"] == plan.plan_id
    assert export_plan(plan, "markdown").startswith("### Remediation Plan")
    with pytest.raises(ExportUnsupportedError):
        export_plan(plan, "terraform")


def test_cli_remediation_format_ansible(capsys, monkeypatch):
    from ai_log_analyzer import cli
    monkeypatch.setattr("sys.argv", ["ai-log-analyzer", "remediation", "--device", "fgt-1", "--vendor",
                                     "fortinet_fortios", "--interface", "wan1", "--format", "ansible"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert yaml.safe_load(out)[0]["hosts"] == "fgt-1"


def test_body_and_inverse_recorded_on_plans():
    plan = _drain(VendorOS.JUNIPER_JUNOS, "xe-0/0/1")
    assert plan.body_commands[-1] == "set interfaces xe-0/0/1 disable"
    assert plan.inverse_commands[-1] == "delete interfaces xe-0/0/1 disable"
    assert plan.action_type == RemediationActionType.GRACEFUL_LINK_DRAIN
