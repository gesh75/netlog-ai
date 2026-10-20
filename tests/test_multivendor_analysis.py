"""End-to-end multi-vendor analysis: classification, KB playbooks, down→up
state pairing, BGP anomaly detection, cross-vendor entity correlation and
vendor remediation wrappers — over realistic FortiGate / PAN-OS / Cisco
SD-WAN / Junos / EOS / FRR / NX-OS fixtures.

Fixture lines are representative of each vendor's documented syslog format
(FortiOS key=value, PAN-OS CSV field positions, Viptela notifications); they
are not captures from a production network.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from ai_log_analyzer import kb
from ai_log_analyzer.adapters.file import parse_file
from ai_log_analyzer.analyzer import analyze, build_action_items
from ai_log_analyzer.bgp_anomaly import decode_notification, shutdown_communication
from ai_log_analyzer.classifier import LogEvent, classify_events
from ai_log_analyzer.correlate import correlate_entities
from ai_log_analyzer.entity_state import EntityStateTracker
from ai_log_analyzer.remediation import (
    RemediationGenerator,
    SafetyViolationError,
    VendorOS,
)

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).parent / "fixtures" / "multivendor"


def _analyze(name: str) -> dict:
    return analyze(parse_file(FIXTURES / name), use_llm=False).to_dict()


def _items(result: dict) -> dict[str, dict]:
    return {a["description"]: a for a in result["action_items"]}


# ── Classification ──────────────────────────────────────────────────────────

def test_fortigate_cascade_classification():
    ce = classify_events(list(parse_file(FIXTURES / "fortigate_sdwan_ipsec_bgp_cascade.log")))[0]
    by_host_desc = {(e.hostname, e.description) for e in ce}
    assert ("FGT-HQ-01", "SD-WAN SLA violation / member out of SLA") in by_host_desc
    assert ("FGT-HQ-01", "IPsec IKE Phase 1 negotiation failure") in by_host_desc
    assert ("FGT-HQ-01", "VPN/IPsec tunnel failure") in by_host_desc
    assert ("dc1-edge-01", "VPN/IPsec tunnel failure") in by_host_desc
    assert ("dc1-edge-01", "BGP hold timer expired") in by_host_desc
    assert ("FGT-HQ-01", "BGP hold timer expired") in by_host_desc
    assert ("FGT-BR-07", "FortiGate memory conserve mode") in by_host_desc
    assert ("FGT-HQ-01", "SD-WAN member back in SLA") in by_host_desc
    assert ("FGT-HQ-01", "VPN/IPsec tunnel up") in by_host_desc


def test_panos_classification():
    ce = classify_events(list(parse_file(FIXTURES / "panos_ha_vpn_routing.log")))[0]
    descs = {e.description for e in ce}
    assert {"Firewall HA failover / state change", "Firewall HA split-brain / heartbeat loss",
            "IPsec IKE Phase 1 negotiation failure", "IPsec IKE Phase 2 negotiation failure",
            "BGP peer down / connect failure", "Authentication failure", "Firewall/ACL deny event",
            "IPS/threat signature match", "BGP peer established"} <= descs
    split = next(e for e in ce if e.description.startswith("Firewall HA split-brain"))
    assert split.severity == "critical"


def test_sdwan_classification():
    ce = classify_events(list(parse_file(FIXTURES / "cisco_sdwan_bfd_omp_flaps.log")))[0]
    descs = [e.description for e in ce]
    assert descs.count("SD-WAN BFD session down") == 4
    assert descs.count("SD-WAN BFD session up") == 3
    assert "SD-WAN OMP peer down" in descs and "SD-WAN control connection down" in descs


@pytest.mark.parametrize("message,description", [
    ("%BGP-4-MAXPFX: No. of prefix received from 198.51.100.9 (afi 0) reaches 80, max 100",
     "BGP max-prefix threshold warning"),
    ("%BGP-3-MAXPFXEXCEED: No. of prefix received from 198.51.100.9 (afi 0): prefix 101 exceed limit 100",
     "BGP max-prefix limit exceeded"),
    ("%NOTIFICATION: received from neighbor 10.0.1.9 6/4 (Cease/Administrative Reset) 0 bytes",
     "BGP administrative shutdown / reset (Cease)"),
    ("%NOTIFICATION: sent to neighbor 10.0.0.1 4/0", "BGP hold timer expired"),
    ("%NOTIFICATION: received from neighbor 10.0.2.2 2/2 (OPEN Message Error/Bad Peer AS) 2 bytes FD E9",
     "BGP NOTIFICATION — protocol / OPEN / UPDATE error"),
    ("BGP origin AS changed for prefix 203.0.113.0/24: AS64500 -> AS64666",
     "BGP origin / AS-path change (possible hijack or leak)"),
])
def test_bgp_anomaly_classification(message, description):
    ce = classify_events([LogEvent("", "r1", "bgpd", "err", message)])[0][0]
    assert ce.description == description and ce.category == "routing"


def test_interface_slash_six_two_is_not_a_cease_code():
    msg = "%LINK-3-UPDOWN: Interface Ethernet1/6/2, changed state to down"
    ce = classify_events([LogEvent("", "sw1", "", "err", msg)])[0][0]
    assert ce.description == "Interface link down"


# ── KB playbooks ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("category,description,platform,needle", [
    ("vpn", "IPsec IKE Phase 1 negotiation failure", "fortios", "diagnose vpn ike gateway list"),
    ("vpn", "IPsec IKE Phase 1 negotiation failure", "panos", "show vpn ike-sa gateway"),
    ("vpn", "IPsec IKE Phase 2 negotiation failure", "panos", "show vpn ipsec-sa tunnel"),
    ("sdwan", "SD-WAN SLA violation / member out of SLA", "fortios", "diagnose sys sdwan health-check"),
    ("sdwan", "SD-WAN BFD session down", "sdwan", "show sdwan bfd sessions"),
    ("sdwan", "SD-WAN OMP peer down", "sdwan", "show sdwan omp peers"),
    ("sdwan", "SD-WAN control connection down", "sdwan", "show sdwan control connections"),
    ("redundancy", "Firewall HA split-brain / heartbeat loss", "panos", "show high-availability state"),
    ("system", "FortiGate memory conserve mode", "fortios", "diagnose hardware sysinfo conserve"),
    ("firewall", "Firewall session table exhaustion", "fortios", "diagnose sys session full-stat"),
    ("routing", "BGP max-prefix limit exceeded", "junos", "show bgp neighbor"),
    ("routing", "BGP hold timer expired", "junos", "show bgp neighbor"),
])
def test_vendor_playbooks_resolve_with_platform_cli(category, description, platform, needle):
    entry = kb.lookup(category, description)
    assert [p["name"] for p in entry["phases"]] == ["Diagnose", "Mitigate", "Remediate", "Verify", "Optimize"]
    cli = kb.phase_cli_for(entry["phases"][0], platform)
    assert any(needle in c for c in cli), cli


def test_generic_bgp_lookup_unchanged_by_vendor_entries():
    assert kb.lookup("routing", "BGP peer down / connect failure") is kb.KB["routing"]["bgp_down"]
    assert kb.lookup("vpn", "VPN/IPsec tunnel failure") is kb.KB["vpn"]["tunnel_down"]
    assert kb.lookup("redundancy", "VRRP/gateway failover") is kb.KB["redundancy"]["failover"]


def test_hold_timer_and_admin_shutdown_get_different_playbooks():
    hold = kb.lookup("routing", "BGP hold timer expired")
    admin = kb.lookup("routing", "BGP administrative shutdown / reset (Cease)")
    assert hold is not admin
    assert "transport" in hold["root_cause"].lower()
    assert "rfc 8203" in admin["root_cause"].lower()


# ── State pairing (down → up) ───────────────────────────────────────────────

def test_recovered_outages_are_not_active_hard_outages():
    items = _items(_analyze("fortigate_sdwan_ipsec_bgp_cascade.log"))
    assert items["VPN/IPsec tunnel failure"]["state"] == "recovered"
    assert items["VPN/IPsec tunnel failure"]["entity_states"]["counts"] == {"recovered": 2}
    assert items["BGP hold timer expired"]["state"] == "recovered"
    assert items["SD-WAN SLA violation / member out of SLA"]["state"] == "recovered"
    # the unrelated iBGP drop on dc1-core-01 never came back
    assert items["BGP peer idle / notification"]["state"] == "active"
    assert items["FortiGate memory conserve mode"]["state"] == "active"
    # recovery events themselves never become action items
    assert "VPN/IPsec tunnel up" not in items and "SD-WAN member back in SLA" not in items


def test_active_items_rank_before_recovered_items_of_same_severity():
    result = _analyze("fortigate_sdwan_ipsec_bgp_cascade.log")
    high = [a for a in result["action_items"] if a["severity"] == "high"]
    states = [a.get("state", "") for a in high]
    assert states.index("active") < states.index("recovered")
    assert states == sorted(states, key=lambda s: {"active": 0, "flapping": 1, "recovered": 2}.get(s, 0))


def test_repeated_flaps_are_flagged_flapping():
    result = _analyze("cisco_sdwan_bfd_omp_flaps.log")
    bfd = _items(result)["SD-WAN BFD session down"]
    # vedge-br02 flapped 3x in < 3 min; cedge-br01 is still down → group active
    assert bfd["state"] == "active"
    assert bfd["entity_states"]["counts"] == {"active": 1, "flapping": 1}
    flapping = next(e for e in bfd["entity_states"]["entities"] if e["status"] == "flapping")
    assert flapping["hostname"] == "vedge-br02" and flapping["downs"] == 3
    assert _items(result)["SD-WAN OMP peer down"]["state"] == "recovered"


def test_single_down_up_pair_reports_outage_length():
    events = [
        LogEvent("2026-10-20T10:00:00Z", "sw1", "Ebra", "err",
                 "%LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet7, changed state to down"),
        LogEvent("2026-10-20T10:00:20Z", "sw1", "Ebra", "notice",
                 "%LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet7, changed state to up"),
    ]
    tracker = EntityStateTracker()
    for i, ce in enumerate(classify_events(events)[0]):
        tracker.add(ce, i)
    (state,) = tracker.report().values()
    assert state.status == "recovered" and state.outage_seconds == 20.0
    items = build_action_items(classify_events(events)[0], llm_top_n=0)
    assert items[0].description == "Interface link down" and items[0].state == "recovered"


def test_legacy_events_without_entities_keep_old_shape():
    items = build_action_items(
        classify_events([LogEvent("", "sw-01", "kernel", "crit", "kernel panic - not syncing")])[0],
        llm_top_n=0,
    )
    assert items[0].state == "" and "state" not in items[0].to_dict()


# ── BGP anomalies ───────────────────────────────────────────────────────────

def _findings(result: dict, ftype: str) -> list[dict]:
    return [f for f in result["bgp_anomalies"]["findings"] if f["type"] == ftype]


def test_bgp_anomaly_findings():
    result = _analyze("bgp_anomalies.log")
    counts = result["bgp_anomalies"]["counts"]
    assert counts["max_prefix_warning"] == 2 and counts["max_prefix_exceeded"] == 2
    assert counts["admin_shutdown"] == 2 and counts["admin_reset"] == 1
    assert counts["notification_error"] == 2 and counts["hold_timer_expired"] == 1
    assert counts["path_change"] == 2
    assert counts["peer_flapping"] == 4 and counts["route_flap_storm"] == 1

    warn = next(f for f in _findings(result, "max_prefix_warning") if f["hostname"] == "pe-01")
    assert (warn["received"], warn["limit"]) == (8001, 10000)
    cease1 = next(f for f in _findings(result, "max_prefix_exceeded") if "subcode" in f)
    assert (cease1["code"], cease1["subcode"], cease1["subcode_name"]) == (6, 1, "Maximum Number of Prefixes Reached")


def test_admin_shutdown_is_planned_and_carries_rfc8203_message():
    result = _analyze("bgp_anomalies.log")
    shut = {f["hostname"]: f for f in _findings(result, "admin_shutdown")}
    assert shut["spine1"]["shutdown_communication"] == "CHG0012345 planned leaf1 maintenance"
    assert shut["leaf2"]["shutdown_communication"] == "drain for RMA RITM0099"
    assert all(f["planned"] and f["subcode"] == 2 for f in shut.values())
    hold = _findings(result, "hold_timer_expired")[0]
    assert hold["planned"] is False and "transport" in hold["interpretation"]
    assert result["bgp_anomalies"]["planned"] == 3


def test_origin_and_as_path_change_details():
    result = _analyze("bgp_anomalies.log")
    origin, path = _findings(result, "path_change")
    assert (origin["prefix"], origin["old_origin"], origin["new_origin"]) == ("203.0.113.0/24", "64500", "64666")
    assert path["prefix"] == "198.51.100.0/24"
    assert path["old_path"] == "65010 3356 64500" and path["new_path"] == "65010 174 64666 64500"
    assert "old_origin" not in path  # same origin, different transit → leak signature


def test_route_flap_storm_lists_all_flapping_peers():
    storm = _findings(_analyze("bgp_anomalies.log"), "route_flap_storm")[0]
    assert storm["hosts"] == ["leaf5", "leaf6"]
    assert len(storm["peers"]) == 4 and storm["severity"] == "critical"


@pytest.mark.parametrize("message,expected", [
    ("NOTIFICATION sent to 10.0.1.5: code 6 (Cease) subcode 2 (Administratively Shutdown)", (6, 2)),
    ("%NOTIFICATION: received from neighbor 10.0.1.9 6/4 (Cease/Administrative Reset)", (6, 4)),
    ("NOTIFICATION sent to 169.254.10.2 (External AS 65010): code 4 (Hold Timer Expired Error)", (4, None)),
    ("BGP peer 10.0.0.1 down", (None, None)),
])
def test_decode_notification(message, expected):
    assert decode_notification(message) == expected


def test_shutdown_communication_unquoted():
    assert shutdown_communication("Cease 6/2 shutdown communication: CHG42 drain, peer 1") == "CHG42 drain"


# ── Cross-vendor entity correlation ─────────────────────────────────────────

def test_fortigate_ipsec_sla_failure_cascades_into_junos_bgp_drop():
    corr = _analyze("fortigate_sdwan_ipsec_bgp_cascade.log")["entity_correlation"]
    assert len(corr["incidents"]) == 1
    inc = corr["incidents"][0]
    assert inc["root_cause"]["hostname"] == "FGT-HQ-01"
    assert inc["root_cause"]["event_type"] == "sdwan_sla"
    assert inc["devices"] == ["dc1-edge-01", "fgt-hq-01"]
    assert inc["vendors"] == ["fortinet", "juniper"]
    assert inc["confidence"] == "high"
    keys = {(e["type"], e["key"]) for e in inc["evidence"]}
    assert ("shared_ip", "198.51.100.2") in keys          # FortiGate locip == Junos VPN peer
    assert ("p2p_subnet", "169.254.10.0/30") in keys       # both ends of the BGP session
    hosts_in_chain = {(c["hostname"], c["event_type"]) for c in inc["chain"]}
    assert ("dc1-edge-01", "bgp_session") in hosts_in_chain
    assert ("FGT-HQ-01", "bgp_session") in hosts_in_chain
    # the unrelated EOS iBGP drop and the other FortiGate are not pulled in
    assert "dc1-core-01" not in inc["devices"] and "fgt-br-07" not in inc["devices"]


def test_panos_ha_failover_roots_the_vpn_and_bgp_failures():
    inc = _analyze("panos_ha_vpn_routing.log")["entity_correlation"]["incidents"][0]
    assert inc["root_cause"]["hostname"] == "PA-DC2-02"
    assert inc["root_cause"]["event_type"] == "ha_state"
    chain_types = [c["event_type"] for c in inc["chain"]]
    assert chain_types[0] == "ha_state" and "ike_phase1" in chain_types and "bgp_session" in chain_types


def test_sdwan_bfd_flap_roots_omp_and_control_loss_without_false_joins():
    inc = _analyze("cisco_sdwan_bfd_omp_flaps.log")["entity_correlation"]["incidents"][0]
    assert inc["root_cause"]["event_type"] == "bfd_session"
    assert inc["devices"] == ["vedge-br02"]   # system-IP /30 overlap must not join cedge-br01
    assert {"omp_peer", "control_connection"} <= {c["event_type"] for c in inc["chain"]}


def test_correlation_ignores_recoveries_and_bounds_its_pool():
    events = classify_events([
        LogEvent("2026-10-20T10:00:00Z", "a", "rpd", "err", "BGP peer 10.9.0.1 (External AS 1) changed state from Established to Idle"),
        LogEvent("2026-10-20T10:00:05Z", "b", "rpd", "err", "BGP peer 10.9.0.2 (External AS 2) changed state from Established to Idle"),
        LogEvent("2026-10-20T10:01:00Z", "a", "rpd", "info", "BGP peer 10.9.0.1 (External AS 1) changed state from OpenConfirm to Established"),
    ])[0]
    corr = correlate_entities(events)
    assert corr["events_considered"] == 2
    assert corr["incidents"][0]["devices"] == ["a", "b"]
    assert correlate_entities(events, max_events=1)["dropped"] == 1


def test_correlation_window_is_respected():
    events = classify_events([
        LogEvent("2026-10-20T10:00:00Z", "a", "rpd", "err", "BGP peer 10.9.0.1 (External AS 1) changed state from Established to Idle"),
        LogEvent("2026-10-20T11:00:00Z", "b", "rpd", "err", "BGP peer 10.9.0.2 (External AS 2) changed state from Established to Idle"),
    ])[0]
    assert correlate_entities(events, window_s=300)["incidents"] == []


# ── Vendor remediation ──────────────────────────────────────────────────────

def test_new_vendor_os_values():
    assert {v.value for v in VendorOS} >= {"fortinet_fortios", "paloalto_panos", "cisco_sdwan"}


def test_fortios_drain_uses_revert_mode_and_is_honest_about_restart():
    plan = RemediationGenerator().build_graceful_link_drain("FGT-HQ-01", VendorOS.FORTINET_FORTIOS, "wan1")
    assert "    set cfg-save revert" in plan.config_commands
    assert "    set cfg-revert-timeout 300" in plan.config_commands
    assert plan.config_commands[0].startswith("execute backup config flash")
    assert plan.confirm_commit_commands[0] == "execute cfg save"
    assert "Unit Restarts" in plan.to_markdown_card()


def test_panos_plan_snapshots_and_rolls_back_manually():
    plan = RemediationGenerator().build_graceful_link_drain("PA-DC2-02", VendorOS.PALOALTO_PANOS, "ethernet1/1")
    snapshot = next(c for c in plan.config_commands if c.startswith("save config to "))
    assert f"load config from {snapshot.split()[-1]}" in plan.manual_rollback_commands
    assert "set network interface ethernet ethernet1/1 link-state down" in plan.config_commands
    card = plan.to_markdown_card()
    assert "No Native Auto-Revert" in card and "Auto-Reverts in" not in card


def test_sdwan_plan_uses_commit_confirmed():
    plan = RemediationGenerator().build_graceful_link_drain("cedge-br01", VendorOS.CISCO_SDWAN,
                                                            "GigabitEthernet1", rollback_minutes=10)
    assert plan.config_commands[0] == "config-transaction"
    assert plan.commit_with_timer_commands == ["commit confirmed 10"]


@pytest.mark.parametrize("vendor", [VendorOS.FORTINET_FORTIOS, VendorOS.PALOALTO_PANOS, VendorOS.CISCO_SDWAN])
def test_qos_template_refused_for_firewall_and_sdwan_vendors(vendor):
    with pytest.raises(SafetyViolationError, match="No vetted QoS"):
        RemediationGenerator().build_qos_copp_remediation("d1", vendor, "port1")


@pytest.mark.parametrize("vendor,cmd", [
    (VendorOS.FORTINET_FORTIOS, "execute factoryreset"),
    (VendorOS.FORTINET_FORTIOS, "execute reboot"),
    (VendorOS.PALOALTO_PANOS, "request system private-data-reset"),
    (VendorOS.PALOALTO_PANOS, "request restart system"),
    (VendorOS.CISCO_SDWAN, "request software reset"),
])
def test_custom_plan_guardrail_applies_to_new_vendors(vendor, cmd):
    with pytest.raises(SafetyViolationError):
        RemediationGenerator().build_custom_safe_plan("d1", vendor, [cmd], [], [], "x")
