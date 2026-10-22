"""Regression tests: guardrail bypasses, read-only checks, input validation, vendor-accurate wording."""

from __future__ import annotations

import pytest

from ai_log_analyzer.remediation import (
    RemediationActionType,
    RemediationGenerator,
    SafetyGuardrail,
    SafetyViolationError,
    VendorOS,
    screen_llm_cli,
)

pytestmark = pytest.mark.unit

BYPASSES = [
    "do reload", "rel", "wr er", "wr erase", "wri er", "erase /all nvram:", "erase /all flash:",
    "cle ip bgp *", "clear bgp ipv4 unicast *", "clear ip bgp vrf X *", "delete flash:startup-config",
    "delete /force /recursive flash:", "request vmhost reboot", "exec reboot", "systemctl reboot", "init 6",
    "crypto key zeroize rsa", "configure replace flash:golden.cfg force",
    "copy tftp://192.0.2.1/evil.cfg startup-config", "no feature bgp", "bash rm -rf /*",
    "delete protocols bgp group X", "  DO   RELOAD  ", "sudo reboot", "vtysh -c 'do reload'",
    "show version\ndo reload", "req sys zero", "execute factoryreset", "exe reb",
]
STILL_BLOCKED = ["reload", "write erase", "erase startup-config", "clear ip bgp *", "request system zeroize"]
LEGIT = [
    "clear ip bgp 10.0.0.1", "clear ip bgp * soft", "clear ip bgp * in", "clear bgp neighbor 10.0.0.1",
    "clear ip bgp vrf BLUE 10.1.1.1", "copy running-config startup-config", "write memory", "wr mem",
    "delete protocols bgp group UNDERLAY neighbor 10.0.0.1 import NETLOG-DRAIN-IN",
    "delete interfaces xe-0/0/1 disable", "delete policy-options policy-statement NETLOG-DRAIN-IN",
    "rollback 0", "commit confirmed 5", "shutdown", "configure terminal", "interface Ethernet1",
    "rm -rf /tmp/netlog", "do show ip bgp summary", "no shutdown",
]


@pytest.mark.parametrize("cmd", BYPASSES + STILL_BLOCKED)
def test_destructive_commands_are_blocked(cmd):
    assert SafetyGuardrail.violation(cmd), cmd
    with pytest.raises(SafetyViolationError):
        SafetyGuardrail.validate([cmd], 5)
    safe, blocked = SafetyGuardrail.screen([cmd])
    assert blocked and safe[0].startswith("# BLOCKED")
    assert screen_llm_cli({"eos": [cmd]})["eos"][0].startswith("# BLOCKED")


@pytest.mark.parametrize("cmd", LEGIT)
def test_targeted_commands_are_not_blocked(cmd):
    assert SafetyGuardrail.violation(cmd) is None, cmd


def test_custom_plan_rejects_abbreviated_destructive_command():
    for cmd in ("rel", "wr er", "do reload"):
        with pytest.raises(SafetyViolationError):
            RemediationGenerator().build_custom_safe_plan("r1", VendorOS.CISCO_IOS_XE, [cmd], [], [], "x")


ALL_DRAINS = [(v, "xe-0/0/1" if v == VendorOS.JUNIPER_JUNOS else "Ethernet1/1") for v in VendorOS]


@pytest.mark.parametrize("vendor,intf", ALL_DRAINS)
def test_every_builtin_drain_plan_passes_the_strict_guardrail(vendor, intf):
    gen = RemediationGenerator()
    for ip in (None, "10.0.0.1"):
        plan = gen.build_graceful_link_drain("dev1", vendor, intf, bgp_neighbor_ip=ip)
        assert not [c for c in plan.body_commands + plan.inverse_commands if SafetyGuardrail.violation(c)]
        SafetyGuardrail.validate_read_only(plan.pre_checks + plan.post_checks)


@pytest.mark.parametrize("vendor", [VendorOS.ARISTA_EOS, VendorOS.JUNIPER_JUNOS, VendorOS.CISCO_NXOS,
                                    VendorOS.CISCO_IOS_XE, VendorOS.FRR])
def test_every_builtin_qos_plan_passes_the_strict_guardrail(vendor):
    plan = RemediationGenerator().build_qos_copp_remediation("dev1", vendor, "Ethernet1")
    assert not [c for c in plan.body_commands if SafetyGuardrail.violation(c)]
    SafetyGuardrail.validate_read_only(plan.pre_checks + plan.post_checks)


# ── read-only pre/post checks ───────────────────────────────────────────────

@pytest.mark.parametrize("check", ["reload", "write erase", "configure terminal", "clear ip bgp 10.0.0.1",
                                   "show version; reload", "show version\nreboot", "show run > flash:x",
                                   "show version | bash", "show $(reload)", "delete flash:x", "execute reboot"])
def test_checks_must_be_read_only(check):
    assert SafetyGuardrail.read_only_violation(check)
    with pytest.raises(SafetyViolationError):
        RemediationGenerator().build_custom_safe_plan("r1", VendorOS.ARISTA_EOS, ["interface Ethernet1", " shutdown"],
                                                      [check], ["show version"], "x")
    with pytest.raises(SafetyViolationError):
        RemediationGenerator().build_custom_safe_plan("r1", VendorOS.ARISTA_EOS, ["interface Ethernet1", " shutdown"],
                                                      ["show version"], [check], "x")


@pytest.mark.parametrize("check", ["show ip bgp summary", "show interfaces Et1 | include error", "display version",
                                   "get router info bgp summary", "diagnose sys sdwan member", "ping 10.0.0.1",
                                   "traceroute 10.0.0.1", "execute ping 10.0.0.1", 'show interfaces x | match "a|b"',
                                   "vtysh -c 'show ip bgp summary'"])
def test_read_only_checks_are_accepted(check):
    assert SafetyGuardrail.read_only_violation(check) is None, check


# ── input validation ────────────────────────────────────────────────────────

@pytest.mark.parametrize("device", ['x"""\nimport os', "a\nb", "all and more", "", "a b", "rt1;reload", "r'1", "x" * 256])
def test_bad_device_names_are_rejected(device):
    gen = RemediationGenerator()
    with pytest.raises(SafetyViolationError, match="device"):
        gen.build_graceful_link_drain(device, VendorOS.ARISTA_EOS, "Ethernet1")
    with pytest.raises(SafetyViolationError, match="device"):
        gen.build_qos_copp_remediation(device, VendorOS.ARISTA_EOS, "Ethernet1")
    with pytest.raises(SafetyViolationError, match="device"):
        gen.build_custom_safe_plan(device, VendorOS.ARISTA_EOS, ["interface Ethernet1"], [], [], "x")


@pytest.mark.parametrize("interface", ["Ethernet1\nreload", "Eth 1", "", "Et1;reload", "Ethernet1'", "E" * 65])
def test_bad_interfaces_are_rejected(interface):
    with pytest.raises(SafetyViolationError, match="interface"):
        RemediationGenerator().build_graceful_link_drain("r1", VendorOS.ARISTA_EOS, interface)
    with pytest.raises(SafetyViolationError, match="interface"):
        RemediationGenerator().build_qos_copp_remediation("r1", VendorOS.ARISTA_EOS, interface)


@pytest.mark.parametrize("ip", ["10.0.0.300", "peer", "10.0.0.1\nreload", "10.0.0.1; reload", "10.0.0.0/24"])
def test_bad_neighbor_ips_are_rejected(ip):
    with pytest.raises(SafetyViolationError, match="bgp_neighbor_ip"):
        RemediationGenerator().build_graceful_link_drain("r1", VendorOS.JUNIPER_JUNOS, "xe-0/0/1", bgp_neighbor_ip=ip)


def test_valid_inputs_and_ipv6_neighbor_are_canonicalised():
    plan = RemediationGenerator().build_graceful_link_drain(
        "spine-1.example.net", VendorOS.JUNIPER_JUNOS, "xe-0/0/1:0", bgp_neighbor_ip=" 2001:DB8::1 ")
    assert plan.bgp_neighbor_ip == "2001:db8::1" and plan.interface == "xe-0/0/1:0"
    assert any("neighbor 2001:db8::1 import" in c for c in plan.body_commands)


def test_non_integer_rollback_is_a_safety_violation():
    with pytest.raises(SafetyViolationError, match="integer"):
        RemediationGenerator().build_graceful_link_drain("r1", VendorOS.ARISTA_EOS, "Ethernet1", rollback_minutes="5")  # type: ignore[arg-type]


# ── vendor-accurate wording and self-contained plans ────────────────────────

def test_only_platforms_with_a_timer_claim_auto_revert():
    gen = RemediationGenerator()
    for vendor in (VendorOS.JUNIPER_JUNOS, VendorOS.CISCO_IOS_XE, VendorOS.ARISTA_EOS):
        card = gen.build_graceful_link_drain("r1", vendor, "Ethernet1", bgp_neighbor_ip="10.0.0.1").to_markdown_card()
        assert "Auto-Reverts in 5m" in card and "Auto-Rollback Timer:** `5 min`" in card
    for vendor in (VendorOS.CISCO_NXOS, VendorOS.PALOALTO_PANOS, VendorOS.FORTINET_FORTIOS):
        card = gen.build_graceful_link_drain("r1", vendor, "Ethernet1").to_markdown_card()
        assert "Auto-Reverts in" not in card and "Auto-Rollback Timer" not in card
    nxos = gen.build_graceful_link_drain("r1", VendorOS.CISCO_NXOS, "Ethernet1").to_markdown_card()
    assert "No Automatic Rollback" in nxos and "manual rollback commands" in nxos
    pan = gen.build_graceful_link_drain("r1", VendorOS.PALOALTO_PANOS, "ethernet1/1").to_markdown_card()
    assert "Auto-Rollback:** none" in pan


def test_eos_commit_timer_uses_hh_mm_ss_and_ios_confirm_saves():
    gen = RemediationGenerator()
    eos = gen.build_graceful_link_drain("r1", VendorOS.ARISTA_EOS, "Ethernet1", rollback_minutes=5)
    assert eos.commit_with_timer_commands == ["commit timer 00:05:00"]
    ios = gen.build_graceful_link_drain("r1", VendorOS.CISCO_IOS_XE, "Gi0/1")
    assert ios.confirm_commit_commands == ["configure confirm", "copy running-config startup-config"]


def test_eos_drain_text_says_to_verify_the_syntax():
    plan = RemediationGenerator().build_graceful_link_drain("r1", VendorOS.ARISTA_EOS, "Ethernet1")
    assert "verify the syntax on your EOS release" in plan.blast_radius_notes


def test_junos_drain_is_self_contained_and_never_emits_placeholder_peer():
    gen = RemediationGenerator()
    with_ip = gen.build_graceful_link_drain("mx1", VendorOS.JUNIPER_JUNOS, "xe-0/0/1", bgp_neighbor_ip="10.0.0.1")
    body = "\n".join(with_ip.body_commands)
    for policy in ("NETLOG-DRAIN-IN", "NETLOG-DRAIN-OUT"):  # every referenced policy is defined in the plan
        assert f"set policy-options policy-statement {policy} term drain then" in body
    assert "DRAIN-IN" not in body.replace("NETLOG-DRAIN-IN", "")
    assert "neighbor 10.0.0.1 import NETLOG-DRAIN-IN" in body
    no_ip = gen.build_graceful_link_drain("mx1", VendorOS.JUNIPER_JUNOS, "xe-0/0/1")
    assert no_ip.body_commands == ["set interfaces xe-0/0/1 disable"]
    assert "peer" not in " ".join(no_ip.body_commands + no_ip.inverse_commands).split()
    assert "No bgp_neighbor_ip given" in no_ip.blast_radius_notes


def test_frr_backup_name_is_unique_per_plan():
    gen = RemediationGenerator()
    a = gen.build_graceful_link_drain("frr1", VendorOS.FRR, "eth1")
    b = gen.build_graceful_link_drain("frr1", VendorOS.FRR, "eth1")
    assert a.plan_id == b.plan_id
    assert a.config_commands[0] != b.config_commands[0] and a.manual_rollback_commands != b.manual_rollback_commands


def test_action_type_enum_still_exposed():
    assert RemediationActionType.GRACEFUL_LINK_DRAIN.value == "graceful_link_drain"
