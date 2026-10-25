"""Entity extraction regressions (asdot ASNs, NX-OS / FRR / PAN-OS peers and VRFs,
FSM arrows, IKE failures, vendor attribution)."""
from __future__ import annotations

import pytest

from ai_log_analyzer.adapters.file import parse_lines
from ai_log_analyzer.classifier import classify_events
from ai_log_analyzer.correlate import correlate_entities
from ai_log_analyzer.parsers import parse_line
from ai_log_analyzer.parsers.entities import detect_vendor, extract_asn, final_state_word, valid_ip

pytestmark = pytest.mark.unit

JUNOS_BGP = ("Oct 22 10:00:{s:02d} {host} rpd[2210]: RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer {peer} "
             "(External AS {asn}) changed state from Established to Idle (event HoldTime) (instance master)")


# ── asdot ASNs ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("text,expected", [
    ("BGP peer 10.1.1.2 (External AS 1.10) changed state", "1.10"),
    ("neighbor 10.1.1.2 (VRF default AS 65000.100)", "65000.100"),
    ("remote-as 4200000001", "4200000001"),
    ("peer-as 1.20 reset", "1.20"),
    ("Neighbor 10.1.1.2 Up (VRF: default) (AS: 65000)", "65000"),
    ("sentence ends with AS 65010.", "65010"),
    ("AS 10.1.1.1 is not an asdot ASN", ""),
])
def test_extract_asn_keeps_asdot(text, expected):
    assert extract_asn(text) == expected


def test_asdot_asn_survives_every_parser_path():
    ev = parse_line(JUNOS_BGP.format(s=0, host="r1", peer="203.0.113.1", asn="1.10"))
    assert ev.asn == "1.10"
    eos = parse_line("Oct 22 10:15:01 r1 Bgp: %BGP-5-ADJCHANGE: peer 10.1.1.2 (VRF default AS 65000.100) "
                     "old state Established event Stop new state Idle")
    assert eos.asn == "65000.100"


def _incidents(lines):
    events, _, _ = classify_events(list(parse_lines(lines)))
    return correlate_entities(events)["incidents"]


def test_distinct_asdot_asns_do_not_join_end_to_end():
    lines = [JUNOS_BGP.format(s=0, host="edge-01", peer="203.0.113.1", asn="1.10"),
             JUNOS_BGP.format(s=20, host="edge-02", peer="198.51.100.9", asn="1.20")]
    assert _incidents(lines) == []


def test_same_asdot_asn_on_two_routers_joins_end_to_end():
    lines = [JUNOS_BGP.format(s=0, host="edge-01", peer="203.0.113.1", asn="1.10"),
             JUNOS_BGP.format(s=20, host="edge-02", peer="198.51.100.9", asn="1.10")]
    incidents = _incidents(lines)
    assert len(incidents) == 1
    assert ("shared_asn", "65546") in {(e["type"], e["key"]) for e in incidents[0]["evidence"]}


# ── NX-OS / FRR / PAN-OS / SR Linux peers and VRFs ──────────────────────────

def test_nxos_bgp_tag_yields_vrf_and_local_as_not_peer_as():
    ev = parse_line("Oct 22 10:15:01 nx1 %BGP-5-ADJCHANGE: bgp-65001 [12345] (VRF-A) neighbor 10.1.1.2 Down - "
                    "holdtimer expired error")
    assert (ev.vendor, ev.event_type, ev.state, ev.peer_ip) == ("cisco_nxos", "bgp_session", "down", "10.1.1.2")
    assert ev.vrf == "VRF-A"
    # bgp-65001 is the router's own AS: kept as an attribute, never as the (remote) asn
    assert ev.asn == "" and ev.attrs["local_asn"] == "65001"


def test_frr_peer_colon_ipv6_and_description_forms():
    ev = parse_line("Oct 22 10:15:01 leaf1 bgpd[12]: peer:2001:db8::2 went down")
    assert (ev.peer_ip, ev.state) == ("2001:db8::2", "down")
    ev = parse_line("Oct 22 10:15:01 leaf1 bgpd[12]: %ADJCHANGE: neighbor 10.1.1.2(spine1) in vrf default Up")
    assert (ev.peer_ip, ev.vrf, ev.state) == ("10.1.1.2", "default", "up")
    ev = parse_line("Oct 22 10:15:01 leaf1 bgpd[12]: 10.1.1.2(spine1) went from Established to Idle")
    assert (ev.peer_ip, ev.state) == ("10.1.1.2", "down")


def test_ipv4_mapped_peer_is_normalised():
    assert valid_ip("::ffff:10.1.1.2") == "10.1.1.2"
    assert valid_ip("::FFFF:10.1.1.2") == "10.1.1.2"
    assert valid_ip("2001:db8::2") == "2001:db8::2"
    ev = parse_line("Oct 22 10:15:01 leaf1 bgpd[12]: %ADJCHANGE: neighbor ::ffff:10.1.1.2 in vrf default Down")
    assert ev.peer_ip == "10.1.1.2"


def test_sr_linux_bgp_session_with_peer():
    ev = parse_line("Oct 22 10:15:01 sr1 srlinux[12]: BGP session with 10.1.1.2 moved from Established to Idle")
    assert (ev.event_type, ev.peer_ip, ev.state) == ("bgp_session", "10.1.1.2", "down")


def test_panos_virtual_router_becomes_vrf():
    ev = parse_line("Oct 22 10:15:01 pa1 BGP peer 10.1.1.2 (virtual router vr-corp) state changed from "
                    "Established to Idle")
    assert (ev.event_type, ev.peer_ip, ev.vrf, ev.state) == ("bgp_session", "10.1.1.2", "vr-corp", "down")


def test_iosxr_vrf_and_as_in_parentheses():
    ev = parse_line("Oct 22 10:15:01 xr1 bgp[1052]: %ROUTING-BGP-5-ADJCHANGE : neighbor 10.1.1.2 Up "
                    "(VRF: default) (AS: 65000)")
    assert (ev.peer_ip, ev.vrf, ev.asn, ev.state) == ("10.1.1.2", "default", "65000", "up")


# ── FSM arrows / IKE failures ───────────────────────────────────────────────

@pytest.mark.parametrize("text,word", [
    ("neighbor 10.1.1.2 (Established->Clearing)", "clearing"),
    ("neighbor 10.1.1.2 Established -> Idle", "idle"),
    ("went from Established->Idle", "idle"),
    ("from Idle to Established", "established"),
])
def test_final_state_word_handles_arrows(text, word):
    assert final_state_word(text) == word


@pytest.mark.parametrize("line", [
    "Oct 22 10:15:01 leaf1 bgpd[12]: [EC 33554433] 10.1.1.2 state changed (Established->Clearing)",
    "Oct 22 10:15:01 leaf1 bgpd[12]: 10.1.1.2(spine1) went from Established to Clearing",
    "Oct 22 10:15:01 xr1 bgp[1052]: %ROUTING-BGP-5-ADJCHANGE : neighbor 10.1.1.2 Established -> Idle",
])
def test_established_to_clearing_or_idle_is_down(line):
    assert parse_line(line).state == "down"


def test_ike_negotiation_failure_is_down():
    ev = parse_line("Oct 22 10:15:01 fw1 iked[1]: IKE_NEGOTIATION_FAILED peer 10.2.2.2")
    assert (ev.event_type, ev.state) == ("ipsec_tunnel", "down")
    ev = parse_line("Oct 22 10:15:01 pa1 vpn[1]: IKE phase-1 negotiation failed with error 10.2.2.2")
    assert (ev.event_type, ev.state) == ("ipsec_tunnel", "down")


# ── vendor attribution ──────────────────────────────────────────────────────

def test_junos_bfdd_is_juniper_but_frr_bfdd_stays_frr():
    junos = parse_line("Oct 22 10:15:01 mx1 bfdd[1234]: BFDD_STATE_UP_TO_DOWN: BFD Session 10.1.1.2 "
                       "(IFL 345) state Up -> Down")
    assert junos.vendor == "juniper" and junos.event_type == "bfd_session"
    frr = parse_line("Oct 22 10:15:01 leaf1 bfdd[12]: [XXXX] session 10.1.1.2 down")
    assert frr.vendor == "frr"


def test_iosxr_bgp_agent_is_not_arista():
    assert detect_vendor("bgp", "%ROUTING-BGP-5-ADJCHANGE : neighbor 10.1.1.2 Down") == "cisco_ios"
    # EOS keeps its agent-name rule
    assert detect_vendor("Bgp", "%BGP-5-ADJCHANGE: peer 10.1.1.2 (VRF default AS 65000) old state "
                                "Established event Stop new state Idle") == "arista"
    assert detect_vendor("bgp", "peer 10.1.1.2 down") == "arista"
