"""Event typing: IS-IS / OSPF / LDP are not BGP, CLI-audit records are not
incidents, and a "commit operation" is a configuration change."""
from __future__ import annotations

import pytest

from ai_log_analyzer.entity_state import EntityStateTracker, entity_key
from ai_log_analyzer.parsers import parse_line

pytestmark = pytest.mark.unit


# ── IGP / LDP adjacencies ───────────────────────────────────────────────────

@pytest.mark.parametrize("line,vendor,etype,state,intf", [
    ("Oct 22 10:15:01 r1 %CLNS-5-ADJCHANGE: ISIS: Adjacency to r2 (GigabitEthernet0/0/1) Down, hold time expired",
     "cisco_ios", "isis_adjacency", "down", "GigabitEthernet0/0/1"),
    ("Oct 22 10:15:02 r1 %CLNS-5-ADJCHANGE: ISIS: Adjacency to r2 (GigabitEthernet0/0/1) Up, new adjacency",
     "cisco_ios", "isis_adjacency", "up", "GigabitEthernet0/0/1"),
    ("Oct 22 10:15:01 xr1 RP/0/RP0/CPU0:Oct 22 10:15:01.1 UTC: isis[1010]: %ROUTING-ISIS-5-ADJCHANGE : "
     "Adjacency to r2 (GigabitEthernet0/0/0/1) (L2) Down, Holdtime expired",
     "cisco_ios", "isis_adjacency", "down", "GigabitEthernet0/0/0/1"),
    ("Oct 22 10:15:01 nx1 %ISIS-5-ADJCHANGE: isis-1 [4321] L1 adj r2 over Ethernet1/1 - DOWN",
     "", "isis_adjacency", "down", "Ethernet1/1"),   # reconstructed sample: vendor not asserted
    ("Oct 22 10:15:01 mx1 rpd[2210]: RPD_ISIS_ADJDOWN: IS-IS lost L2 adjacency to r2 on ge-0/0/1.0, reason: Aged",
     "juniper", "isis_adjacency", "down", "ge-0/0/1.0"),
    ("Oct 22 10:15:02 mx1 rpd[2210]: RPD_ISIS_ADJUP: IS-IS new L2 adjacency to r2 on ge-0/0/1.0",
     "juniper", "isis_adjacency", "up", "ge-0/0/1.0"),
])
def test_isis_adjacency_is_not_bgp(line, vendor, etype, state, intf):
    ev = parse_line(line)
    assert (ev.event_type, ev.state, ev.interface) == (etype, state, intf)
    assert not vendor or ev.vendor == vendor


def test_ospf_adjchange_is_ospf():
    ev = parse_line("Oct 22 10:15:01 r1 %OSPF-5-ADJCHANGE: Process 1, Nbr 10.0.0.2 on GigabitEthernet0/1 "
                    "from FULL to DOWN, Neighbor Down: Dead timer expired")
    assert (ev.event_type, ev.state, ev.peer_ip) == ("ospf_adjacency", "down", "10.0.0.2")
    ev = parse_line("Oct 22 10:15:09 r1 %OSPF-5-ADJCHANGE: Process 1, Nbr 10.0.0.2 on GigabitEthernet0/1 "
                    "from LOADING to FULL, Loading Done")
    assert (ev.event_type, ev.state) == ("ospf_adjacency", "up")


@pytest.mark.parametrize("line,vendor,state,peer", [
    ("Oct 22 10:15:01 mx1 rpd[2210]: RPD_LDP_NBRDOWN: LDP neighbor 10.0.0.2 (ge-0/0/1.0) is down",
     "juniper", "down", "10.0.0.2"),
    ("Oct 22 10:15:01 r1 %LDP-5-NBRCHG: LDP Neighbor 10.0.0.2:0 (1) is DOWN (Session KeepAlive Timer expired)",
     "cisco_ios", "down", "10.0.0.2"),
    ("Oct 22 10:15:09 r1 %LDP-5-NBRCHG: LDP Neighbor 10.0.0.2:0 (1) is UP",
     "cisco_ios", "up", "10.0.0.2"),
    ("Oct 22 10:15:01 leaf1 ldpd[22]: Neighbor 10.0.0.2 is down: session closed",
     "frr", "down", "10.0.0.2"),
])
def test_ldp_session_events(line, vendor, state, peer):
    ev = parse_line(line)
    assert (ev.vendor, ev.event_type, ev.state, ev.peer_ip) == (vendor, "ldp_session", state, peer)


def test_frr_bare_adjchange_is_still_bgp():
    ev = parse_line("Oct 22 10:15:01 leaf1 bgpd[12]: %ADJCHANGE: neighbor 10.1.1.2 in vrf default Down")
    assert (ev.event_type, ev.state) == ("bgp_session", "down")
    # ... with no app tag at all (relay without a tag)
    ev = parse_line("Oct 22 10:15:01 leaf1 %ADJCHANGE: neighbor 10.1.1.2 in vrf default Down")
    assert (ev.event_type, ev.state, ev.peer_ip) == ("bgp_session", "down", "10.1.1.2")


def test_isis_and_ldp_down_up_pair_in_entity_state():
    tracker = EntityStateTracker()
    lines = [
        "Oct 22 10:15:01 r1 %CLNS-5-ADJCHANGE: ISIS: Adjacency to r2 (GigabitEthernet0/0/1) Down, hold time expired",
        "Oct 22 10:16:01 r1 %CLNS-5-ADJCHANGE: ISIS: Adjacency to r2 (GigabitEthernet0/0/1) Up, new adjacency",
        "Oct 22 10:15:05 r1 %LDP-5-NBRCHG: LDP Neighbor 10.0.0.2:0 (1) is DOWN (Session KeepAlive Timer expired)",
        "Oct 22 10:15:50 r1 %LDP-5-NBRCHG: LDP Neighbor 10.0.0.2:0 (1) is UP",
    ]
    for i, line in enumerate(lines):
        assert tracker.add(parse_line(line), i) is not None
    report = tracker.report()
    kinds = {k[1]: st.status for k, st in report.items()}
    assert kinds == {"isis": "recovered", "ldp": "recovered"}
    assert entity_key(parse_line(lines[2])) == ("r1", "ldp", "10.0.0.2")


# ── CLI audit / accounting records ──────────────────────────────────────────

@pytest.mark.parametrize("line", [
    "Oct 22 10:15:01 r1 mgd[1]: UI_CMDLINE_READ_LINE: User 'bob', command 'show bgp neighbor | match down'",
    "Oct 22 10:15:01 r1 mgd[1]: UI_CMDLINE_READ_LINE: User 'bob', command 'show chassis alarms'",
    "Oct 22 10:15:01 r1 mgd[1]: UI_CMDLINE_READ_LINE: User 'bob', command 'commit'",
    "Oct 22 10:15:01 sw1 Aaa: %ACCOUNTING-5-CMD: bob ssh 10.9.9.9 stop service=shell priv-lvl=15 "
    "cmd=show interface Ethernet1 | include down",
    "Oct 22 10:15:01 r1 %PARSER-5-CFGLOG_LOGGEDCMD: User:bob  logged command:show bgp neighbor 10.1.1.2 down",
])
def test_cli_audit_lines_get_no_event_type_or_state(line):
    ev = parse_line(line)
    assert ev.event_type == "" and ev.state == "" and ev.peer_ip == "" and ev.interface == ""
    assert ev.attrs["audit"] == "cli"


def test_real_commit_is_a_config_change():
    ev = parse_line("Oct 22 10:15:01 r1 mgd[1]: UI_COMMIT: User 'bob' requested 'commit' operation (comment: x)")
    assert (ev.vendor, ev.event_type, ev.state) == ("juniper", "config_change", "")
    ev = parse_line("Oct 22 10:15:01 nx1 %VSHD-5-VSHD_SYSLOG_CONFIG_I: Configured from vty by bob on 10.9.9.9@pts/0")
    assert ev.event_type == "config_change"


def test_operational_state_still_counts_as_link_state():
    ev = parse_line("Oct 22 10:15:01 sw1 portd[1]: Ethernet12 operational state down")
    assert (ev.event_type, ev.interface, ev.state) == ("interface_link", "Ethernet12", "down")


def test_panos_config_log_and_sdwan_commit_are_config_changes():
    pan = ("<14>Oct 20 08:16:30 PA-DC2-02 1,2026/10/20 08:16:30,013201001235,CONFIG,0,0,2026/10/20 08:16:30,"
           "10.0.0.5,,commit,admin,Web,Succeeded,,1234,0x0,0,0,0,0,,PA-DC2-02")
    assert parse_line(pan).event_type == "config_change"
    sdwan = ("Oct 20 09:00:01 vedge-br02 vdaemon[1]: %Viptela-vedge-SYSMGR-5-NTCE-200025: "
             "system-config-commit completed by admin")
    ev = parse_line(sdwan)
    assert (ev.vendor, ev.event_type) == ("cisco_sdwan", "config_change")
