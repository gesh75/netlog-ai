"""Parser plugin registry + canonical structured schema (FortiOS, PAN-OS,
Cisco SD-WAN, DC NOS) and backward compatibility of the legacy fields."""
from __future__ import annotations

from pathlib import Path

import pytest

from ai_log_analyzer.adapters.file import _parse_line, parse_file, parse_lines
from ai_log_analyzer.classifier import STRUCTURED_FIELDS, LogEvent, classify_events
from ai_log_analyzer.parsers import SKIP, ensure_structured, parse_line, registry
from ai_log_analyzer.parsers.timeutil import normalize_ts

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).parent / "fixtures" / "multivendor"


def _lines(name: str) -> list[str]:
    return (FIXTURES / name).read_text(encoding="utf-8").splitlines()


# ── Schema backward compatibility ───────────────────────────────────────────

def test_logevent_positional_constructor_still_works_and_is_hashable():
    ev = LogEvent("2026-10-20T07:00:00", "r1", "rpd", "err", "bgp peer 10.0.0.1 down")
    assert ev.vendor == "" and ev.state == "" and dict(ev.attrs) == {}
    assert hash(ev) == hash(LogEvent("2026-10-20T07:00:00", "r1", "rpd", "err", "bgp peer 10.0.0.1 down"))
    # attrs never participate in equality / hashing
    import dataclasses
    assert dataclasses.replace(ev, attrs={"x": "1"}) == ev


def test_structured_fields_cover_the_canonical_schema():
    assert set(STRUCTURED_FIELDS) >= {"vendor", "event_type", "interface", "peer_ip", "asn", "vrf",
                                      "vni", "tunnel_id", "action", "normalized_utc_ts"}


@pytest.mark.parametrize("line,expected", [
    ("<13>Oct 13 10:00:01 sw1 mib2d[1234]: SNMP_TRAP_LINK_DOWN: ifIndex 545, ifName xe-0/0/1",
     ("Oct 13 10:00:01", "sw1", "mib2d", "notice", "SNMP_TRAP_LINK_DOWN: ifIndex 545, ifName xe-0/0/1")),
    ("<165>1 2026-10-20T07:00:00Z leaf1 bgpd 123 - - %ADJCHANGE: neighbor 10.0.0.1 Down",
     ("2026-10-20T07:00:00Z", "leaf1", "bgpd", "notice", "%ADJCHANGE: neighbor 10.0.0.1 Down")),
    ("Oct 13 10:00:01 spine1 rpd: BGP peer 10.0.0.1 reset (Hold Timer expired)",
     ("Oct 13 10:00:01", "spine1", "rpd", "info", "BGP peer 10.0.0.1 reset (Hold Timer expired)")),
    ("free text with no header", ("", "dflt", "syslog", "info", "free text with no header")),
])
def test_legacy_base_fields_unchanged(line, expected):
    ev = _parse_line(line, "dflt")
    assert (ev.timestamp, ev.hostname, ev.appname, ev.severity_raw, ev.message) == expected


def test_securecrt_padding_line_is_skipped_and_text_line_kept():
    assert _parse_line("20:30:01.01 §", "fw-1") is None
    ev = _parse_line("20:30:01.01 §bgp peer 10.0.0.1 down (hold timer expired)", "fw-1")
    assert ev.appname == "scrt-session" and ev.peer_ip == "10.0.0.1" and ev.state == "down"


def test_registry_order_and_custom_plugin():
    assert registry.names[:3] == ["fortios", "panos", "cisco_sdwan"]
    assert registry.names[-1] == "fallback"

    class Acme:
        name = "acme"
        priority = 5

        def parse(self, line, env, default_host):
            if line.startswith("ACME|"):
                return LogEvent("", "acme-1", "acme", "info", line[5:], vendor="acme")
            if line == "ACME-NOISE":
                return SKIP
            return None

    registry.register(Acme())
    try:
        assert parse_line("ACME|hello").vendor == "acme"
        assert parse_line("ACME-NOISE") is None
        assert parse_line("plain").appname == "syslog"
    finally:
        assert registry.unregister("acme")
    assert "acme" not in registry.names


# ── FortiOS ─────────────────────────────────────────────────────────────────

def test_fortios_ipsec_phase1_error():
    ev = parse_line(_lines("fortigate_sdwan_ipsec_bgp_cascade.log")[1])
    assert ev.hostname == "FGT-HQ-01"
    assert ev.appname == "fortios-vpn"
    assert ev.severity_raw == "err"
    assert ev.vendor == "fortinet"
    assert ev.event_type == "ike_phase1"
    assert ev.tunnel_id == "HQ-DC1"
    assert ev.peer_ip == "203.0.113.10"
    assert ev.interface == "wan1"
    assert ev.action == "negotiate"
    assert ev.state == "down"
    assert ev.normalized_utc_ts == "2026-10-20T07:01:02Z"
    assert ev.attrs["locip"] == "198.51.100.2" and ev.attrs["vdom"] == "root"
    # identity fields and the device serial never reach the message
    assert "jsmith" not in ev.message and "FG100FTK" not in ev.message


def test_fortios_sdwan_sla_and_recovery():
    lines = _lines("fortigate_sdwan_ipsec_bgp_cascade.log")
    down, up = parse_line(lines[0]), parse_line(lines[9])
    for ev in (down, up):
        assert ev.event_type == "sdwan_sla" and ev.interface == "wan1"
        assert ev.attrs["healthcheck"] == "HC-DC1"
    assert down.state == "down" and up.state == "up"


def test_fortios_router_bgp_and_conserve_mode():
    lines = _lines("fortigate_sdwan_ipsec_bgp_cascade.log")
    bgp = parse_line(lines[6])
    assert bgp.event_type == "bgp_session" and bgp.peer_ip == "169.254.10.1" and bgp.state == "down"
    conserve = parse_line(lines[8])
    assert conserve.hostname == "FGT-BR-07" and conserve.event_type == "conserve_mode"
    assert conserve.severity_raw == "crit" and conserve.state == "down"


def test_fortios_behind_relay_header_and_tz_offset():
    line = ('Oct 20 07:01:02 10.10.0.1 date=2026-10-20 time=09:01:02 devname="FGT-X" logid="1" '
            'type="event" subtype="vpn" level="notice" tz="+0200" logdesc="IPsec connection status changed" '
            'action="tunnel-up" vpntunnel="T1" remip=192.0.2.1')
    ev = parse_line(line)
    assert ev.hostname == "FGT-X" and ev.state == "up"
    assert ev.normalized_utc_ts == "2026-10-20T07:01:02Z"


# ── PAN-OS ──────────────────────────────────────────────────────────────────

def test_panos_system_vpn_phase1():
    ev = parse_line(_lines("panos_ha_vpn_routing.log")[2])
    assert ev.hostname == "PA-DC2-02" and ev.appname == "panos-vpn" and ev.vendor == "paloalto"
    assert ev.event_type == "ike_phase1" and ev.state == "down"
    assert ev.tunnel_id == "GW-AWS-TGW1" and ev.peer_ip == "198.51.100.77"
    assert ev.attrs["local_ip"] == "192.0.2.10" and ev.attrs["eventid"] == "ike-nego-p1-fail"
    assert ev.timestamp == "2026-10-20T08:15:40"


def test_panos_ha_routing_and_globalprotect():
    lines = _lines("panos_ha_vpn_routing.log")
    ha = parse_line(lines[0])
    assert ha.event_type == "ha_state" and ha.severity_raw == "crit" and ha.hostname == "PA-DC2-01"
    bgp = parse_line(lines[4])
    assert bgp.event_type == "bgp_session" and bgp.peer_ip == "169.254.20.1" and bgp.state == "down"
    assert parse_line(lines[11]).state == "up"
    gp = parse_line(lines[6])
    assert gp.event_type == "vpn_auth"
    assert "jdoe" not in gp.message  # usernames scrubbed at parse time


def test_panos_traffic_and_threat_csv():
    lines = _lines("panos_ha_vpn_routing.log")
    drop = parse_line(lines[7])
    assert drop.appname == "panos-traffic" and drop.action == "drop" and drop.event_type == "traffic"
    assert drop.interface == "ethernet1/1" and drop.attrs["rule"] == "deny-untrust"
    threat = parse_line(lines[10])
    assert threat.event_type == "threat" and threat.action == "reset-both"
    assert threat.attrs["threat_severity"] == "critical" and threat.severity_raw == "crit"
    assert "Log4j" in threat.message


# ── Cisco Catalyst SD-WAN ───────────────────────────────────────────────────

def test_viptela_notification_bfd_omp_control():
    lines = _lines("cisco_sdwan_bfd_omp_flaps.log")
    bfd = parse_line(lines[0])
    assert (bfd.vendor, bfd.event_type, bfd.state) == ("cisco_sdwan", "bfd_session", "down")
    assert bfd.peer_ip == "10.255.0.11"
    assert bfd.tunnel_id == "biz-internet->mpls@10.255.0.11"
    assert bfd.attrs["flap_reason"] == "timeout" and bfd.attrs["system_ip"] == "10.255.1.2"
    # base fields identical to what the generic syslog parser yields
    assert (bfd.hostname, bfd.appname, bfd.timestamp) == ("vedge-br02", "FTMD", "Oct 20 09:00:01")
    omp = parse_line(lines[2])
    assert (omp.event_type, omp.peer_ip, omp.state) == ("omp_peer", "10.255.0.3", "down")
    ctrl = parse_line(lines[3])
    assert (ctrl.event_type, ctrl.tunnel_id, ctrl.state) == ("control_connection", "vsmart@10.255.0.3", "down")


def test_cedge_ftmd_bfd_session():
    ev = parse_line(_lines("cisco_sdwan_bfd_omp_flaps.log")[-1])
    assert ev.hostname == "cedge-br01" and ev.event_type == "bfd_session" and ev.state == "down"
    assert ev.tunnel_id == "biz-internet->biz-internet@10.255.0.12"


# ── Data-center NOS enrichment ──────────────────────────────────────────────

@pytest.mark.parametrize("line,vendor,etype,field,value,state", [
    ("Oct 20 07:02:36 dc1-edge-01 rpd[2210]: RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 169.254.10.2 "
     "(External AS 65010) changed state from Established to Idle (event HoldTime) (instance master)",
     "juniper", "bgp_session", "peer_ip", "169.254.10.2", "down"),
    ("Oct 20 07:04:15 dc1-core-01 Bgp: %BGP-5-ADJCHANGE: peer 10.255.0.1 (VRF default AS 65000) "
     "old state Established event Stop new state Idle", "arista", "bgp_session", "asn", "65000", "down"),
    ("Oct 20 10:00:01 leaf1 Ebra: %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet12, "
     "changed state to up", "arista", "interface_link", "interface", "Ethernet12", "up"),
    ("Oct 20 10:08:00 nx-01 %BGP-5-ADJCHANGE: bgp-65001 [12345] (default) neighbor 10.0.3.1 Down - holdtimer "
     "expired error", "cisco_nxos", "bgp_session", "peer_ip", "10.0.3.1", "down"),
    ("Oct 20 10:00:01 r1 123: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down",
     "cisco_ios", "interface_link", "interface", "GigabitEthernet0/1", "down"),
    ("Oct 20 10:00:01 leaf5 bgpd[900]: %ADJCHANGE: neighbor 10.0.5.1(spine1) in vrf default Up",
     "frr", "bgp_session", "vrf", "default", "up"),
    ("Oct 20 10:00:01 sonic1 bgp#bgpd[51]: %ADJCHANGE: neighbor 10.0.0.57 in vrf default Down",
     "sonic", "bgp_session", "peer_ip", "10.0.0.57", "down"),
    ("Oct 20 10:00:01 vtep1 bgpd: EVPN route update VNI 10010 withdraw",
     "frr", "evpn", "vni", "10010", ""),
])
def test_nos_enrichment(line, vendor, etype, field, value, state):
    ev = parse_line(line)
    assert ev.vendor == vendor and ev.event_type == etype
    assert getattr(ev, field) == value
    assert ev.state == state


def test_junos_master_instance_normalized_to_default_vrf():
    ev = parse_line(_lines("fortigate_sdwan_ipsec_bgp_cascade.log")[5])
    assert ev.vrf == "default"


# ── Connectors (events built outside the registry) ──────────────────────────

def test_ensure_structured_parses_raw_vendor_line_from_connector():
    raw = _lines("fortigate_sdwan_ipsec_bgp_cascade.log")[2]
    ev = LogEvent("2026-10-20T07:01:05Z", "fgt-hq-01.example.net", "", "info", raw)
    out = ensure_structured(ev)
    assert out.vendor == "fortinet" and out.event_type == "ipsec_tunnel" and out.state == "down"
    assert out.hostname == "fgt-hq-01.example.net"   # connector's own identity wins
    assert out.attrs["parser"] == "enrich:fortios"
    assert ensure_structured(out) is out              # idempotent


def test_classifier_enriches_plain_logevents():
    ev = LogEvent("", "r1", "rpd", "err", "bgp peer 10.0.0.1 down (hold timer expired)")
    ce = classify_events([ev])[0][0]
    assert ce.peer_ip == "10.0.0.1" and ce.state == "down"
    assert ce.to_dict()["entities"]["peer_ip"] == "10.0.0.1"


def test_whole_fixture_files_parse_without_fallback():
    for name in ("fortigate_sdwan_ipsec_bgp_cascade.log", "panos_ha_vpn_routing.log",
                 "cisco_sdwan_bfd_omp_flaps.log", "bgp_anomalies.log"):
        events = list(parse_file(FIXTURES / name))
        assert events, name
        assert all(e.attrs.get("parser") != "fallback" for e in events), name
        # every device line gets a vendor; the BGP route monitor is not a network vendor
        assert all(e.vendor or e.appname == "bgp-monitor" for e in events), name


def test_parse_lines_bytes_path_uses_registry():
    ev = next(iter(parse_lines([_lines("panos_ha_vpn_routing.log")[0].encode()])))
    assert ev.vendor == "paloalto"


# ── Time normalization ──────────────────────────────────────────────────────

@pytest.mark.parametrize("stamp,tz,expected,assumed", [
    ("2026-10-20T09:01:02+02:00", None, "2026-10-20T07:01:02Z", False),
    ("2026-10-20T07:01:02", "+0200", "2026-10-20T05:01:02Z", False),
    ("2026/10/20 07:01:02", None, "2026-10-20T07:01:02Z", True),
    ("1792479662", None, "2026-10-20T07:01:02Z", False),
    ("not a time", None, "", False),
])
def test_normalize_ts(stamp, tz, expected, assumed):
    assert normalize_ts(stamp, tz) == (expected, assumed)


def test_normalize_rfc3164_year_rollover(monkeypatch):
    from datetime import datetime, timezone

    from ai_log_analyzer.parsers import timeutil
    monkeypatch.setattr(timeutil, "_now", lambda: datetime(2027, 1, 1, 0, 5, tzinfo=timezone.utc))
    assert normalize_ts("Dec 31 23:59:00") == ("2026-12-31T23:59:00Z", True)
    assert normalize_ts("Jan  1 00:01:00") == ("2027-01-01T00:01:00Z", True)
