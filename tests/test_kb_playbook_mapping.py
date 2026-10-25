"""Every actionable (category, description) the classifier can emit gets a playbook that fits it.

Before this, dhcp / wireless / stp / switching / performance fell through to
"Event detected: ..."; IPS, ACL deny and DDoS got the brute-force playbook; BFD,
EIGRP, IS-IS and EVPN route updates got BGP/OSPF; memory exhaustion and process
crashes got the kernel-panic playbook; and the `qos` entry was unreachable.
"""
from __future__ import annotations

import pytest

from ai_log_analyzer import judge, kb
from ai_log_analyzer.classifier import _KB_PATTERNS, _STATE_VERDICTS


def _emitted(severities=("critical", "high", "medium")) -> set[tuple[str, str]]:
    pairs = {(cat, desc) for (_p, sev, cat, desc) in _KB_PATTERNS if sev in severities}
    pairs |= {(cat, desc) for (sev, cat, desc) in _STATE_VERDICTS.values() if sev in severities}
    return pairs


@pytest.mark.unit
def test_every_actionable_emitted_description_has_a_real_playbook():
    # Low-severity rows (SSH accepted, config commit, ...) never become action items.
    generic = [(c, d) for c, d in sorted(_emitted()) if kb.lookup(c, d)["root_cause"].startswith("Event detected:")]
    assert not generic, generic


@pytest.mark.unit
def test_new_playbooks_are_phased_and_score_well():
    for category, description in sorted(_emitted()):
        entry = kb.lookup(category, description)
        assert {p["name"] for p in entry["phases"]} >= {"Diagnose", "Mitigate", "Remediate", "Verify", "Optimize"}
        verdict = judge.judge(entry)
        assert verdict["scores"]["overall"] >= 7.0, (category, description, verdict["scores"], verdict["notes"])


@pytest.mark.unit
@pytest.mark.parametrize("description", ["IPS/threat signature match", "Firewall/ACL deny event",
                                          "DDoS/storm detected", "DDoS protection event"])
def test_security_events_do_not_get_the_brute_force_playbook(description):
    entry = kb.lookup("security", description)
    assert entry is not kb.KB["security"]["auth_fail"]
    assert "brute" not in entry["root_cause"].lower() and "credential" not in entry["root_cause"].lower()


@pytest.mark.unit
def test_auth_failures_keep_the_auth_playbook():
    for desc in ("Authentication failure", "802.1X authentication failure"):
        assert kb.lookup("security", desc) is kb.KB["security"]["auth_fail"]


@pytest.mark.unit
@pytest.mark.parametrize("description, needle", [
    ("BFD session down", "bfd"),
    ("Cumulus PTMD link/BFD down", "bfd"),
    ("EIGRP neighbor down (IOS)", "eigrp"),
    ("IS-IS adjacency change", "is-is"),
    ("IS-IS adjacency down", "is-is"),
    ("LDP neighbor/session down", "ldp"),
])
def test_routing_adjacency_events_get_their_own_playbook(description, needle):
    entry = kb.lookup("routing", description)
    assert entry is not kb.KB["routing"]["bgp_down"] and entry is not kb.KB["routing"]["ospf"]
    assert needle in entry["root_cause"].lower()


@pytest.mark.unit
def test_evpn_route_update_gets_the_evpn_playbook_not_bgp():
    entry = kb.lookup("routing", "EVPN route update")
    assert entry["root_cause"] == kb.KB["evpn"]["cascade"]["root_cause"]
    assert entry is not kb.KB["routing"]["bgp_down"]
    # the cascade lookup used by the existing tests is unchanged
    assert kb.lookup("routing", "evpn underlay failure cascade vtep flap")["match"] == kb.KB["evpn"]["cascade"]["match"]


@pytest.mark.unit
@pytest.mark.parametrize("description", ["Memory exhaustion / OOM", "Kernel swap space exhaustion",
                                         "Low memory / allocation failure", "High CPU / memory utilization",
                                         "CPU hog — process holding the CPU"])
def test_resource_exhaustion_does_not_get_the_kernel_panic_playbook(description):
    entry = kb.lookup("system", description)
    assert entry is not kb.KB["system"]["_default"]
    assert any(w in entry["root_cause"].lower() for w in ("cpu", "memory"))


@pytest.mark.unit
@pytest.mark.parametrize("description", ["SONiC orchagent crash", "SONiC syncd/ASIC crash", "Cumulus switchd crash",
                                         "NX-OS service crash", "SONiC SWSS failure", "Monitored process not running",
                                         "Device restart / reload", "Routing Engine failover/switchover"])
def test_process_crashes_get_the_process_playbook(description):
    entry = kb.lookup("system", description)
    assert entry is not kb.KB["system"]["_default"]
    assert entry is kb.KB["system"]["process_restart"]


@pytest.mark.unit
def test_kernel_panic_and_conserve_mode_keep_their_playbooks():
    assert kb.lookup("system", "Kernel panic / core dump — OS failure") is kb.KB["system"]["_default"]
    assert kb.lookup("system", "FortiGate memory conserve mode") is kb.KB["system"]["conserve_mode"]


@pytest.mark.unit
@pytest.mark.parametrize("category, description", [
    ("dhcp", "DHCP pool exhausted"),
    ("wireless", "Access point down"),
    ("stp", "STP topology change"),
    ("stp", "STP root/loop/BPDU guard block"),
    ("switching", "MAC learning/move event"),
    ("performance", "Packet drops/policer discard"),
    ("performance", "Flow control / pause frames"),
    ("aaa", "AAA server unreachable (TACACS+/RADIUS)"),
])
def test_previously_unmapped_categories_have_a_playbook(category, description):
    assert category in kb.KB
    assert not kb.lookup(category, description)["root_cause"].startswith("Event detected:")


@pytest.mark.unit
def test_performance_category_reaches_the_congestion_playbook_and_qos_alias_still_works():
    assert kb.lookup("performance", "Packet drops/policer discard") is kb.KB["qos"]["_default"]
    assert kb.lookup("qos", "output queue discards bfd timeout").get("match") == \
        kb.lookup("routing", "control-plane microburst congestion output queue discard bfd drop").get("match")


@pytest.mark.unit
def test_unknown_category_still_falls_back_to_generic_event():
    assert kb.lookup("no-such-category", "something odd")["root_cause"].startswith("Event detected:")
