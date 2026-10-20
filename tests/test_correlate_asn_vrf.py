"""Cross-device correlation on shared ASN and VRF, and the noise guardrails
that keep default routing tables, iBGP and placeholder ASNs from joining
unrelated failures."""
from __future__ import annotations

import dataclasses

import pytest

from ai_log_analyzer.adapters.file import parse_lines
from ai_log_analyzer.classifier import classify_events
from ai_log_analyzer.correlate import DEFAULT_VRF_NAMES, correlate_entities, normalize_asn, normalize_vrf

# Peer addresses sit in different /30s so no shared_ip / p2p_subnet join can
# hide what the ASN and VRF keys do.
JUNOS_TRANSIT = ("Oct 20 10:00:00 edge-01 rpd[2210]: RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 203.0.113.1 "
                 "(External AS {asn}) changed state from Established to Idle (event HoldTime) (instance master)")
EOS_TRANSIT = ("Oct 20 10:00:20 edge-02 Bgp: %BGP-5-ADJCHANGE: peer 198.51.100.9 (VRF default AS {asn}) "
               "old state Established event HoldTimerExpired new state Idle")
PANOS_TRANSIT = ('<14>1,2026/10/20 10:00:37,0123,SYSTEM,routing,0,2026/10/20 10:00:37,,routing-bgp-peer-down,,0,0,'
                 'general,high,"BGP peer 203.0.113.41 (VR default, remote-as {asn}) went down: hold timer expired",'
                 '1,0x0,0,0,0,0,,PA-10')
FRR_DEFAULT = ("Oct 20 10:00:30 edge-03 bgpd[900]: %ADJCHANGE: neighbor 192.0.2.77(Lumen) in vrf default Down "
               "BGP Notification received")
FGT_VRF0 = ('<185>date=2026-10-20 time=10:00:36 devname="FGT-09" devid="FG1" logid="0103020300" type="event" '
            'subtype="router" level="critical" vd="root" logdesc="BGP neighbor status changed" '
            'msg="BGP: %BGP-5-ADJCHANGE: VRF 0 neighbor 203.0.113.33 Down Hold Timer Expired"')

IOS_TENANT = "Oct 20 10:00:33 rtr-06 %BGP-5-ADJCHANGE: neighbor 10.20.0.1 vpn vrf TENANT-A Down BGP Notification sent"
EOS_TENANT = ("Oct 20 10:00:34 eos-07 Bgp: %BGP-5-ADJCHANGE: peer 10.30.0.1 (VRF TENANT-A AS 65200) old state "
              "Established event HoldTimerExpired new state Idle")
JUNOS_TENANT = ("Oct 20 10:00:35 mx-08 rpd[2210]: RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 10.40.0.1 "
                "(External AS 65200) changed state from Established to Idle (event HoldTime) (instance TENANT-A)")

JUNOS_IBGP = ("Oct 20 10:00:38 mx-11 rpd[2210]: RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 10.5.5.5 "
              "(Internal AS 65000) changed state from Established to Idle (event HoldTime) (instance master)")


def _events(lines):
    return classify_events(list(parse_lines(lines)))[0]


def _correlate(lines, **kw):
    return correlate_entities(_events(lines), **kw)["incidents"]


def _keys(inc):
    return {(e["type"], e["key"]) for e in inc["evidence"]}


# ── cross-device, multi-vendor joins ────────────────────────────────────────

def test_ebgp_drops_to_one_transit_as_join_across_vendors():
    lines = [JUNOS_TRANSIT.format(asn=3356), EOS_TRANSIT.format(asn=3356), PANOS_TRANSIT.format(asn=3356)]
    incidents = _correlate(lines)
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc["devices"] == ["edge-01", "edge-02", "pa-10"]
    assert inc["vendors"] == ["arista", "juniper", "paloalto"]
    assert ("shared_asn", "3356") in _keys(inc)
    assert not {"shared_ip", "p2p_subnet"} & {t for t, _ in _keys(inc)}
    assert inc["shared"]["asn"] == ["3356"]
    assert "shared peer AS AS3356" in inc["summary"]
    # Sharing a transit AS is a reason to look together, not proof of a common cause.
    assert inc["confidence"] == "medium"


def test_asn_spellings_normalise_to_one_key():
    lines = [JUNOS_TRANSIT.format(asn=65546), EOS_TRANSIT.format(asn=65546)]
    spelling = {"edge-01": "AS65546", "edge-02": "1.10"}           # asplain with prefix vs asdot
    events = [dataclasses.replace(e, asn=spelling[e.hostname]) for e in _events(lines)]
    incidents = correlate_entities(events)["incidents"]
    assert len(incidents) == 1 and ("shared_asn", "65546") in _keys(incidents[0])


def test_tenant_vrf_failure_joins_across_vendors_case_insensitively():
    incidents = _correlate([IOS_TENANT, EOS_TENANT, JUNOS_TENANT])
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc["devices"] == ["eos-07", "mx-08", "rtr-06"]
    assert inc["vendors"] == ["arista", "cisco_ios", "juniper"]
    assert ("same_vrf", "tenant-a") in _keys(inc)
    assert inc["shared"]["vrf"] == ["tenant-a"]
    assert "VRF tenant-a" in inc["summary"]


def test_default_vrf_joins_only_when_paired_with_the_same_external_as():
    inc = _correlate([JUNOS_TRANSIT.format(asn=3356), EOS_TRANSIT.format(asn=3356)])[0]
    # Junos "master" and EOS "default" are the same default table.
    assert ("same_vrf", "default|AS3356") in _keys(inc)


def test_existing_strong_evidence_still_drives_confidence():
    # Same transit AS and one end of the same /30: the p2p join keeps "high".
    lines = [JUNOS_TRANSIT.format(asn=3356),
             "Oct 20 10:00:10 edge-02 Bgp: %BGP-5-ADJCHANGE: peer 203.0.113.2 (VRF default AS 3356) "
             "old state Established event HoldTimerExpired new state Idle"]
    inc = _correlate(lines)[0]
    assert ("shared_asn", "3356") in _keys(inc) and ("p2p_subnet", "203.0.113.0/30") in _keys(inc)
    assert inc["confidence"] == "high"


# ── noise guardrails ────────────────────────────────────────────────────────

def test_default_vrf_alone_never_joins_unrelated_sessions():
    lines = [JUNOS_TRANSIT.format(asn=3356), EOS_TRANSIT.format(asn=174), FRR_DEFAULT, FGT_VRF0,
             PANOS_TRANSIT.format(asn=1299)]
    assert _correlate(lines) == []


@pytest.mark.parametrize("vrf", sorted({"default", "global", "main", "0", "root", "mgmt", "MGMT", " Default "}))
def test_default_like_vrf_names_do_not_group_tunnel_failures(vrf):
    """Two unrelated IPsec tunnels dropping in each site's default table stay apart."""
    lines = [
        '<189>date=2026-10-20 time=10:00:05 devname="FGT-BR-01" devid="FG1" vd="root" logid="0101037138" '
        'type="event" subtype="vpn" level="error" logdesc="IPsec connection status changed" action="tunnel-down" '
        'remip=203.0.113.10 locip=198.51.100.2 vpntunnel="BR1-DC1" tunnelid=1 tunneltype="ipsec"',
        '<189>date=2026-10-20 time=10:00:09 devname="FGT-BR-02" devid="FG2" vd="root" logid="0101037138" '
        'type="event" subtype="vpn" level="error" logdesc="IPsec connection status changed" action="tunnel-down" '
        'remip=192.0.2.20 locip=198.51.100.66 vpntunnel="BR2-DC2" tunnelid=1 tunneltype="ipsec"',
    ]
    events = [dataclasses.replace(e, vrf=vrf) for e in _events(lines)]
    assert all(e.event_type in ("ipsec_tunnel", "ike_phase1", "ike_phase2") for e in events)
    assert correlate_entities(events)["incidents"] == []
    # The same failures in a shared tenant VRF are one incident.
    tenant = [dataclasses.replace(e, vrf="Blue") for e in events]
    incidents = correlate_entities(tenant)["incidents"]
    assert len(incidents) == 1 and ("same_vrf", "blue") in _keys(incidents[0])


def test_ibgp_and_the_local_as_never_join():
    eos_ibgp = [f"Oct 20 10:00:{s:02d} {h} Bgp: %BGP-5-ADJCHANGE: peer 10.255.{n}.1 (VRF default AS 65000) "
                "old state Established event HoldTimerExpired new state Idle"
                for s, h, n in ((10, "core-01", 1), (20, "core-02", 2))]
    junos_ibgp_2 = JUNOS_IBGP.replace("mx-11", "mx-12").replace("10.5.5.5", "10.6.6.6")
    # Junos marks iBGP itself; EOS does not, so its AS is learned from the Junos line.
    assert _correlate([JUNOS_IBGP, junos_ibgp_2]) == []
    assert _correlate([JUNOS_IBGP, *eos_ibgp]) == []


@pytest.mark.parametrize("asn", [0, 23456, 65535, 4294967295])
def test_reserved_asns_are_ignored(asn):
    assert _correlate([JUNOS_TRANSIT.format(asn=asn), EOS_TRANSIT.format(asn=asn)]) == []


def test_missing_asn_and_vrf_add_no_keys():
    lines = ["Oct 20 10:00:31 rtr-04 %BGP-5-ADJCHANGE: neighbor 192.0.2.81 Down BGP Notification sent",
             "Oct 20 10:00:32 nx-05 %BGP-5-ADJCHANGE: bgp-65000 [1234] (default) neighbor 192.0.2.85 Down - "
             "holdtimer expired error"]
    assert _correlate(lines) == []


def test_recoveries_do_not_join_on_asn():
    up = ("Oct 20 10:00:20 edge-02 Bgp: %BGP-5-ADJCHANGE: peer 198.51.100.9 (VRF default AS 3356) "
          "old state OpenConfirm event RecvKeepAlive new state Established")
    events = _events([JUNOS_TRANSIT.format(asn=3356), up])
    assert any(e.state == "up" for e in events)
    assert correlate_entities(events)["incidents"] == []


def test_asn_join_respects_the_correlation_window():
    late = EOS_TRANSIT.format(asn=3356).replace("10:00:20", "10:09:00")
    assert _correlate([JUNOS_TRANSIT.format(asn=3356), late], window_s=300) == []
    assert len(_correlate([JUNOS_TRANSIT.format(asn=3356), late], window_s=900)) == 1


# ── normalisation helpers ───────────────────────────────────────────────────

@pytest.mark.parametrize(("raw", "expected"), [
    ("65010", "65010"), ("AS65010", "65010"), ("as 65010", "65010"), (65010, "65010"),
    ("1.10", "65546"), ("4200000001", "4200000001"),
    ("0", ""), ("23456", ""), ("65535", ""), ("4294967295", ""), ("4294967296", ""),
    ("", ""), (None, ""), ("AS", ""), ("abc", ""), ("-5", ""),
])
def test_normalize_asn(raw, expected):
    assert normalize_asn(raw) == expected


def test_normalize_vrf_and_default_names():
    assert normalize_vrf("  TENANT-A ") == "tenant-a" and normalize_vrf(None) == ""
    assert {"default", "global", "main", "0", "root", "mgmt"} <= DEFAULT_VRF_NAMES
