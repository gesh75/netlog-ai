"""False-positive guards and the rule classes the review found missing.

Lines come from formats the rules are written against (IOS/NX-OS mnemonics,
Junos tags, sshd, systemd); several vendor samples were reconstructed by the
review, so each assertion pins the verdict (severity, category) rather than
exact wording.
"""
from __future__ import annotations

import pytest

from ai_log_analyzer.classifier import LogEvent, classify_events


def verdict(appname: str, message: str) -> tuple[str, str, str]:
    ev = LogEvent("2026-05-09T10:00:00", "r1", appname, "info", message)
    out, _, _ = classify_events([ev])
    return out[0].severity, out[0].category, out[0].description


# ── false positives ──────────────────────────────────────────────────────

@pytest.mark.unit
def test_ike_needs_a_word_boundary():
    assert verdict("keepalived", "I would like to test failover of the web VIP")[1] != "vpn"
    assert verdict("unlikely", "unlike the previous run the failover completed")[1] != "vpn"
    # the real thing still matches, including ike_/ikev2 spellings
    assert verdict("charon", "ike negotiation failed with peer 203.0.113.9")[:2] == ("high", "vpn")
    assert verdict("charon", "ikev2 exchange fail: no proposal chosen")[:2] == ("high", "vpn")


@pytest.mark.unit
def test_thermal_daemon_startup_is_not_a_temperature_warning():
    assert verdict("thermalctld", "Started thermal control daemon")[2] != "Temperature warning"
    assert verdict("systemd", "Started thermal control daemon.")[2] != "Temperature warning"
    assert verdict("sensord", "thermal shutdown imminent on slot 2")[:2] == ("medium", "hardware")
    assert verdict("sensord", "temperature 91C above high threshold")[:2] == ("medium", "hardware")


@pytest.mark.unit
def test_core_dump_configuration_is_not_a_crash():
    for msg in ("Core dump disabled", "core dumps are disabled by policy", "Core dump enabled",
                "core dump limit set to unlimited"):
        assert verdict("kernel", msg)[0] != "critical", msg
    for msg in ("systemd-coredump: Process 1234 (bgpd) of user 0 dumped core.", "bgpd: core dumped (signal 11)",
                "kernel panic - not syncing"):
        assert verdict("kernel", msg)[0] == "critical", msg


@pytest.mark.unit
def test_memory_percent_full_below_threshold_is_not_exhaustion():
    assert verdict("kernel", "memory: 20% full, no problem")[0] != "critical"
    assert verdict("kernel", "memory: 99% full")[0] == "critical"
    assert verdict("kernel", "buffer memory is full")[0] == "critical"
    assert verdict("kernel", "Out of memory: Kill process 4242 (bgpd)")[0] == "critical"


@pytest.mark.unit
def test_vxlan_flood_list_is_not_a_ddos():
    assert verdict("Vxlan", "VTEP 10.0.0.5 added to flood list for VNI 10010")[2] != "DDoS/storm detected"
    assert verdict("fw", "TCP SYN flood detected from 198.51.100.7")[2] == "DDoS/storm detected"
    assert verdict("sw", "storm-control broadcast threshold exceeded on Ethernet3")[2] == "DDoS/storm detected"


@pytest.mark.unit
@pytest.mark.parametrize("appname, message", [
    ("mgd", "UI_CMDLINE_READ_LINE: User 'netops', command 'show chassis alarms'"),
    ("mgd", "UI_CMDLINE_READ_LINE: User 'netops', command 'show bgp neighbor | match down'"),
    ("", "%PARSER-5-CFGLOG_LOGGEDCMD: User:admin  logged command:show bgp summary | include Down"),
    ("Aaa", "%ACCOUNTING-5-CMD: admin ssh 10.1.1.1 stop service=shell priv-lvl=15 cmd=show ip bgp summary | include Idle"),
    ("sudo", "netops : TTY=pts/0 ; PWD=/home/netops ; USER=root ; COMMAND=/usr/bin/vtysh -c 'show bgp summary' | grep down"),
])
def test_cli_audit_records_do_not_raise_incidents(appname, message):
    sev, cat, desc = verdict(appname, message)
    assert sev == "low" and cat == "config" and desc == "CLI management activity"


# ── missing rule classes ─────────────────────────────────────────────────

@pytest.mark.unit
@pytest.mark.parametrize("appname, message, expected", [
    ("", "%SPANTREE-2-ROOTGUARD_BLOCK: Root guard blocking port GigabitEthernet0/1 on VLAN0010.", ("high", "stp")),
    ("", "%SPANTREE-2-LOOPGUARD_BLOCK: Loop guard blocking port GigabitEthernet0/2 on VLAN0010.", ("high", "stp")),
    ("", "%STP-2-BLOCK_BPDUGUARD: Received BPDU on port Ethernet1/5 with BPDU Guard enabled. Disabling port.", ("high", "stp")),
    ("", "%SPANTREE-2-ROOTGUARD_UNBLOCK: Root guard unblocking port GigabitEthernet0/1 on VLAN0010.", ("low", "stp")),
    ("", "%SPANTREE-2-LOOPGUARD_UNBLOCK: Loop guard unblocking port GigabitEthernet0/2 on VLAN0010.", ("low", "stp")),
    ("", "%SYS-3-CPUHOG: Task is running for (2000)msecs, more than (2000)msecs (0/0),process = Net Background.", ("medium", "system")),
    ("", "%SYS-1-CPURISINGTHRESHOLD: Threshold: Total CPU Utilization(Total/Intr): 85%/2%, Top 3 processes(Pid/Util): 94/40%", ("high", "system")),
    ("", "%SYS-2-MALLOCFAIL: Memory allocation of 65536 bytes failed from 0x1234, alignment 0 Pool: Processor", ("high", "system")),
    ("fortios-event", 'logdesc="System CPU usage is high" level="warning" msg="CPU usage high: 96%"', ("high", "system")),
    ("monit", "'sonic' cpu usage of 96.0% matches resource limit [cpu usage>90.0%]", ("high", "system")),
    ("", "%SYS-5-RESTART: System restarted --", ("high", "system")),
    ("", "%AAA-3-TACACS_SERVER_DOWN: TACACS+ server 10.1.1.5 is DOWN", ("high", "aaa")),
    ("", "%RADIUS-4-RADIUS_DEAD: RADIUS server 10.1.1.6:1812,1813 is not responding.", ("high", "aaa")),
    ("", "%STANDBY-6-STATECHANGE: GigabitEthernet0/1 Grp 1 state Standby -> Active", ("high", "redundancy")),
    ("jsrpd", "JSRPD_HA_CONTROL_LINK_DOWN: HA control link monitor status is marked down", ("critical", "redundancy")),
    ("jsrpd", "JSRPD_RG_STATE_CHANGE: Redundancy-group 1 transitioned from 'secondary' to 'primary' state due to preempt", ("high", "redundancy")),
    ("chassisd", "CHASSISD_FRU_OFFLINE_NOTICE: Power Supply 1 offline", ("critical", "hardware")),
    ("alarmd", "Alarm set: RE color=RED, class=CHASSIS, reason=RE 0 Hard disk error", ("critical", "hardware")),
    ("alarmd", "Alarm set: FPC color=YELLOW, class=CHASSIS, reason=FPC 3 Minor Errors", ("medium", "hardware")),
    ("alarmd", "Alarm cleared: RE color=RED, class=CHASSIS, reason=RE 0 Hard disk error", ("low", "hardware")),
    ("xcvrd", "Ethernet1/1: Rx power low alarm", ("high", "hardware")),
    ("psud", "PSU absence warning: PSU 1 is not present.", ("critical", "hardware")),
    ("fortios-event", 'logdesc="Object attribute configured" action="Edit" cfgpath="firewall.policy" cfgobj="3"', ("low", "config")),
    ("", "%CLNS-5-ADJCHANGE: ISIS: Adjacency to r2 (GigabitEthernet0/0/1) Down, hold time expired", ("high", "routing")),
    ("", "%CLNS-5-ADJCHANGE: ISIS: Adjacency to r2 (GigabitEthernet0/0/1) Up, new adjacency", ("low", "routing")),
    ("", "%ROUTING-ISIS-5-ADJCHANGE : Adjacency to r2 (GigabitEthernet0/0/0/0) (L2) Down, Neighbor forgot us", ("high", "routing")),
    ("rpd", "RPD_ISIS_ADJDOWN: IS-IS lost L2 adjacency to r2 on ge-0/0/0.0, reason: Aged", ("high", "routing")),
    ("rpd", "RPD_ISIS_ADJUP: IS-IS new L2 adjacency to r2 on ge-0/0/0.0", ("low", "routing")),
    ("rpd", "RPD_LDP_NBRDOWN: LDP neighbor 10.0.0.2 (ge-0/0/1.0) is down", ("high", "routing")),
    ("rpd", "RPD_LDP_SESSIONDOWN: LDP session 10.0.0.2 is down, reason: received notification from peer", ("high", "routing")),
    ("", "%LDP-5-NBRCHG: LDP Neighbor 10.1.1.2:0 (1) is DOWN (Interface not operational)", ("high", "routing")),
    ("", "%LDP-5-NBRCHG: LDP Neighbor 10.1.1.2:0 (1) is UP", ("low", "routing")),
    ("sshd", "Failed password for admin from 203.0.113.5 port 52114 ssh2", ("high", "security")),
    ("sshd", "Invalid user oracle from 203.0.113.5 port 40000", ("high", "security")),
    ("sshd", "error: PAM: authentication error for root from 203.0.113.5", ("high", "security")),
])
def test_missing_rule_classes(appname, message, expected):
    sev, cat, _ = verdict(appname, message)
    assert (sev, cat) == expected, (message, sev, cat)


@pytest.mark.unit
def test_isis_up_counterparts_are_never_high():
    for msg in ("%CLNS-5-ADJCHANGE: ISIS: Adjacency to r2 (GigabitEthernet0/0/1) Up, new adjacency",
                "RPD_ISIS_ADJUP: IS-IS new L2 adjacency to r2 on ge-0/0/0.0",
                "%LDP-5-NBRCHG: LDP Neighbor 10.1.1.2:0 (1) is UP"):
        assert verdict("x", msg)[0] not in ("critical", "high", "medium"), msg


@pytest.mark.unit
def test_successful_ssh_login_stays_low():
    assert verdict("sshd", "Accepted password for admin from 10.0.0.9 port 51000 ssh2")[:2] == ("low", "auth")
