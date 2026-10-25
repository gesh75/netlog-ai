"""State-aware severity: direction comes from the parsed state / "from X to Y" grammar,
not from whichever keyword ("established", "down") happens to appear in the line.

Vendor sample lines are the formats the review reconstructed; the assertions
pin the verdict, not the vendor wording.
"""
from __future__ import annotations

import pytest

from ai_log_analyzer.classifier import LogEvent, classify_events

BGP_DOWN = ("high", "routing", "BGP peer down / connect failure")
BGP_UP = ("medium", "routing", "BGP peer established")
LINK_DOWN = ("high", "interface", "Interface link down")
LINK_UP = ("medium", "interface", "Interface link up")


def verdict(appname: str, message: str, **structured) -> tuple[str, str, str]:
    """Classify one line; ``structured`` fields skip parser enrichment (attrs carries a parser tag)."""
    attrs = {"parser": "test"} if structured else {}
    ev = LogEvent("2026-05-09T10:00:00", "r1", appname, "info", message, attrs=attrs, **structured)
    out, _, _ = classify_events([ev])
    return out[0].severity, out[0].category, out[0].description


@pytest.mark.unit
@pytest.mark.parametrize("appname, message", [
    ("rpd", "RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 10.1.1.2 (External AS 65001) changed state from Established to Active (event Stop)"),
    ("rpd", "RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 10.1.1.2 (External AS 65001) changed state from Established to Connect (event Stop)"),
    ("rpd", "RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 10.1.1.2 (External AS 65001) changed state from Established to OpenSent"),
    ("Bgp", "%BGP-5-ADJCHANGE: peer 10.0.0.2 (VRF default AS 65001) old state Established event Stop new state Active"),
    ("bgp", "neighbor 10.1.1.2 - Established -> Idle"),
    ("bgpd", "%ADJCHANGE: neighbor 10.1.1.2 (Established->Clearing)"),
])
def test_established_to_other_state_is_a_down_event(appname, message):
    assert verdict(appname, message) == BGP_DOWN


@pytest.mark.unit
@pytest.mark.parametrize("message", [
    "RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 10.1.1.2 (External AS 65001) changed state from OpenConfirm to Established (event RecvKeepAlive) (last down 00:00:12 ago)",
    "%BGP-5-ADJCHANGE: peer 10.0.0.2 (VRF default AS 65001) old state OpenConfirm event RecvKeepAlive new state Established",
    "neighbor 10.1.1.2 - Active -> Established",
])
def test_transition_into_established_is_up_even_if_the_line_says_down(message):
    assert verdict("bgp", message) == BGP_UP


@pytest.mark.unit
def test_parsed_state_overrides_a_state_blind_keyword_match():
    # Wording the grammar rules do not know: the parser's state decides.
    assert verdict("bgpd", "peer 10.0.0.1 session is established (flapped earlier)",
                   event_type="bgp_session", state="down") == BGP_DOWN
    assert verdict("bgpd", "peer 10.0.0.1 down before, session healthy",
                   event_type="bgp_session", state="up") == BGP_UP


@pytest.mark.unit
def test_parsed_state_does_not_flip_specific_rules():
    # A hold-timer verdict is already specific and directional.
    v = verdict("rpd", "BGP peer 10.0.0.1 hold timer expired", event_type="bgp_session", state="up")
    assert v[2] == "BGP hold timer expired"


@pytest.mark.unit
@pytest.mark.parametrize("appname, message", [
    ("kernel", "e1000e: Ethernet0: NIC Link is Down"),
    ("", "%PKT_INFRA-LINK-3-UPDOWN : Interface GigabitEthernet0/0/0/0, changed state to Down"),
    ("zebra", "Intf swp1(0) is down"),
    ("srlinux", "Interface ethernet-1/1 is now down"),
    ("fortios-event", 'logdesc="Interface status changed" msg="Interface port1 is down"'),
    ("panos-system", "Port ethernet1/1: Down"),
    ("sros", "Interface 1/1/1 is not operational"),
    ("vdaemon", "interface-state-change vpn-id:0 if-name:ge0/0 new-state:down"),
])
def test_known_interface_down_lines_are_high(appname, message):
    assert verdict(appname, message) == LINK_DOWN


@pytest.mark.unit
@pytest.mark.parametrize("appname, message", [
    ("kernel", "e1000e: Ethernet0: NIC Link is Up 1000 Mbps Full Duplex"),
    ("", "%PKT_INFRA-LINK-3-UPDOWN : Interface GigabitEthernet0/0/0/0, changed state to Up"),
    ("srlinux", "Interface ethernet-1/1 is now up"),
    ("panos-system", "Port ethernet1/1: Up 10Gb/s-full duplex"),
])
def test_known_interface_up_lines_are_recovery(appname, message):
    assert verdict(appname, message) == LINK_UP


@pytest.mark.unit
def test_admin_down_and_port_numbers_are_not_link_faults():
    assert verdict("", "%LINK-5-CHANGED: Interface GigabitEthernet0/1, changed state to administratively down")[0] == "info"
    assert verdict("app", "tcp port 22 is down for maintenance")[1] != "interface"


@pytest.mark.unit
def test_etherchannel_member_leaving_and_joining():
    assert verdict("", "%EC-5-UNBUNDLE: Interface GigabitEthernet0/1 left the port-channel Port-channel1") == \
        ("high", "lag", "LAG member leaving bundle")
    assert verdict("", "%EC-5-BUNDLE: Interface GigabitEthernet0/1 joined port-channel Port-channel1") == \
        ("medium", "lag", "LAG member joining bundle")


@pytest.mark.unit
def test_structured_state_drives_severity_when_no_rule_matches():
    assert verdict("odd", "uplink eth9 went sideways", event_type="interface_link", state="down") == LINK_DOWN
    assert verdict("odd", "uplink eth9 went sideways", event_type="interface_link", state="up") == LINK_UP
    assert verdict("odd", "member xe-0/0/3 flap xyz", event_type="lag_member", state="down")[:2] == ("high", "lag")
    assert verdict("odd", "adjacency flap xyz", event_type="isis_adjacency", state="down")[:2] == ("high", "routing")
    # OSPF/BFD parsed state is too loose ("dead-interval" reads as down): config echo stays info
    assert verdict("syslog", "ip ospf dead-interval 20", event_type="ospf_adjacency", state="down")[0] == "info"
    assert verdict("odd", "tunnel thing", event_type="ipsec_tunnel", state="down")[1] == "vpn"
    # no state, no rule: stays unclassified
    assert verdict("odd", "uplink eth9 went sideways", event_type="interface_link")[0] == "info"


@pytest.mark.unit
def test_structured_state_replaces_generic_activity_rules_but_not_specific_ones():
    # "chassisd" is a low "activity" catch-all: a typed down event outranks it.
    assert verdict("chassisd", "port xe-0/0/1 poll result", event_type="interface_link", state="down") == LINK_DOWN
    # a specific high rule is kept
    assert verdict("rpd", "BGP peer 10.0.0.1 hold timer expired", event_type="interface_link",
                   state="down")[2] == "BGP hold timer expired"


@pytest.mark.unit
def test_custom_rules_still_beat_state_derivation():
    from ai_log_analyzer import classifier
    try:
        classifier.add_custom_rules([{"pattern": "weirdo", "severity": "low", "category": "custom",
                                      "description": "mine"}])
        assert verdict("odd", "weirdo", event_type="interface_link", state="down") == ("low", "custom", "mine")
    finally:
        classifier._CUSTOM_RULES.clear()
