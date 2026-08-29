"""Coverage for the Cisco IOS-XE / NX-OS / Nokia SR Linux classifier patterns
and the new per-event confidence score."""
from __future__ import annotations

import pytest

from ai_log_analyzer.classifier import LogEvent, classify_events


pytestmark = pytest.mark.unit


def _classify_one(message: str, appname: str = "", severity_raw: str = "info"):
    events, _, _ = classify_events([LogEvent(
        timestamp="2026-01-01T00:00:00", hostname="r1", appname=appname,
        severity_raw=severity_raw, message=message,
    )])
    return events[0]


# ── Cisco IOS / IOS-XE ───────────────────────────────────────────────────────

@pytest.mark.parametrize("msg,severity,description", [
    ("%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down",
     "high", "Interface link down"),
    ("%LINEPROTO-5-UPDOWN: Line protocol on Interface Gi0/1, changed state to down",
     "high", "Interface link down"),
    ("%LINEPROTO-5-UPDOWN: Line protocol on Interface Gi0/1, changed state to up",
     "medium", "Interface link up"),
    ("%DUAL-5-NBRCHANGE: EIGRP-IPv4 1: Neighbor 10.0.0.2 (Gi0/1) is down: holding time expired",
     "high", "EIGRP neighbor down (IOS)"),
    ("%SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: admin] [Source: 10.1.1.9]",
     "high", "Authentication failure"),
    ("%SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: ops] [Source: 10.1.1.9]",
     "low", "SSH login accepted"),
    ("%SYS-5-CONFIG_I: Configured from console by admin on vty0 (10.1.1.9)",
     "low", "Configuration change committed"),
    ("%HSRP-5-STATECHANGE: GigabitEthernet0/1 Grp 10 state Standby -> Active",
     "high", "VRRP/gateway failover"),
])
def test_ios_xe_patterns(msg, severity, description):
    e = _classify_one(msg)
    assert (e.severity, e.description) == (severity, description)


# ── Cisco NX-OS ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("msg,severity,description", [
    ("%ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/49 is down (Link failure)",
     "high", "Interface link down"),
    ("%SYSMGR-2-SERVICE_CRASHED: Service \"bgp\" (PID 1234) hasn't caught signal 11",
     "critical", "NX-OS service crash"),
    ("%VPC-2-VPC_SUSP: vPC 10 is down, suspending",
     "high", "vPC peer failure (NX-OS)"),
    ("%MODULE-2-MOD_FAIL: Module 3 reported failure",
     "critical", "Chassis alarm triggered"),
])
def test_nxos_patterns(msg, severity, description):
    e = _classify_one(msg)
    assert (e.severity, e.description) == (severity, description)


# ── Nokia SR Linux ───────────────────────────────────────────────────────────

def test_srlinux_bgp_session_down():
    e = _classify_one("Peer 10.0.0.1: session state changed from established to idle",
                      appname="sr_bgp_mgr")
    assert e.severity == "high"
    assert e.category == "routing"
    # matches the existing idle-state rule — same action path either way
    assert "BGP peer" in e.description


def test_srlinux_interface_oper_down():
    e = _classify_one("interface ethernet-1/3 oper state changed to down",
                      appname="sr_eth_mgr")
    assert e.severity == "high"
    assert e.description == "Interface link down"


# ── SONiC ────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("msg,app,severity,description", [
    ("orchagent dumped core after exception in routeOrch", "orchagent",
     "critical", "SONiC orchagent crash"),
    ("syncd segfault in sai_create_route_entry", "syncd",
     "critical", "SONiC syncd/ASIC crash"),
    ("swss failed to apply fdb update", "swss",
     "high", "SONiC SWSS failure"),
    ("teamd: slave Ethernet4 link down, failover", "teamd",
     "high", "SONiC teamd LAG member down"),
    ("ConfigDB update applied via sonic-cfggen", "configdb",
     "low", "SONiC ConfigDB change"),
])
def test_sonic_patterns(msg, app, severity, description):
    e = _classify_one(msg, appname=app)
    assert (e.severity, e.description) == (severity, description)


# ── Cumulus Linux / NVUE ─────────────────────────────────────────────────────

@pytest.mark.parametrize("msg,app,severity,description", [
    ("clagd: peer 10.0.0.2 down (heartbeat timeout)", "clagd",
     "high", "Cumulus clagd peer down"),
    ("switchd crashed, restarting", "switchd",
     "critical", "Cumulus switchd crash"),
    ("ifupdown2: unable to bring up swp1", "ifupdown2",
     "high", "Cumulus ifupdown2 failure"),
    ("ptmd: link swp1 down (BFD timeout)", "ptmd",
     "high", "Cumulus PTMD link/BFD down"),
    ("nvue commit applied by ops", "nvue",
     "low", "Cumulus NVUE/NCLU config commit"),
])
def test_cumulus_patterns(msg, app, severity, description):
    e = _classify_one(msg, appname=app)
    assert (e.severity, e.description) == (severity, description)


# ── Confidence scores ────────────────────────────────────────────────────────

def test_confidence_kb_match():
    e = _classify_one("bgp peer 10.0.0.1 down hold timer expired")
    assert e.confidence == 0.9


def test_confidence_unmatched_snippet():
    e = _classify_one("quantum flux discombobulated unexpectedly")
    assert e.confidence == 0.3
    assert e.severity == "info"


def test_confidence_severity_promoted():
    e = _classify_one("quantum flux discombobulated unexpectedly", severity_raw="crit")
    assert e.confidence == 0.6
    assert e.severity == "high"


def test_confidence_custom_rule(monkeypatch):
    from ai_log_analyzer import classifier
    saved = list(classifier._CUSTOM_RULES)
    classifier._CUSTOM_RULES.clear()
    try:
        classifier.add_custom_rules([{"pattern": "flux", "severity": "high",
                                      "category": "custom", "description": "flux"}])
        e = _classify_one("quantum flux discombobulated")
        assert e.confidence == 1.0
    finally:
        classifier._CUSTOM_RULES[:] = saved


def test_confidence_in_to_dict():
    e = _classify_one("bgp peer 10.0.0.1 down")
    assert e.to_dict()["confidence"] == 0.9
