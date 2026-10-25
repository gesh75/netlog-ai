"""Syslog framings beyond the plain RFC 3164 / Junos shapes: rsyslog ISO stamps,
SONiC microseconds + severity word, <PRI>-prefixed IOS / NX-OS, IOS year stamps,
timezone abbreviations and IOS-XR location tags."""
from __future__ import annotations

import pytest

from ai_log_analyzer.parsers import parse_line, split_envelope

pytestmark = pytest.mark.unit

BGP = "%ADJCHANGE: neighbor 10.1.1.2 in vrf default Down"


@pytest.mark.parametrize("line,ts,host,app,vendor,sev,norm", [
    # (a) rsyslog ISO stamp, with and without <PRI>
    (f"2026-10-22T10:15:01.123456+00:00 leaf1 bgpd[12]: {BGP}",
     "2026-10-22T10:15:01.123456+00:00", "leaf1", "bgpd", "frr", "info", "2026-10-22T10:15:01Z"),
    (f"<189>2026-10-22T10:15:01.123456+00:00 leaf1 bgpd[12]: {BGP}",
     "2026-10-22T10:15:01.123456+00:00", "leaf1", "bgpd", "frr", "notice", "2026-10-22T10:15:01Z"),
    (f"<189>2026-10-22T12:15:01+02:00 leaf1 bgpd[12]: {BGP}",
     "2026-10-22T12:15:01+02:00", "leaf1", "bgpd", "frr", "notice", "2026-10-22T10:15:01Z"),
    # (b) SONiC native: microseconds, severity word, '#' in the tag
    (f"Oct 22 10:15:01.123456 leaf1 NOTICE bgp#bgpd[12]: {BGP}",
     "Oct 22 10:15:01", "leaf1", "bgp#bgpd", "sonic", "notice", ""),
    (f"Oct 22 10:15:01.123456 leaf1 ERR bgp#bgpd[12]: {BGP}",
     "Oct 22 10:15:01", "leaf1", "bgp#bgpd", "sonic", "err", ""),
    # (c) IOS / NX-OS with PRI, %FAC-SEV-MNEM as the tag
    ("<186>Oct 22 10:15:01 r1 %SYS-2-MALLOCFAIL: Memory allocation of 1000 bytes failed",
     "Oct 22 10:15:01", "r1", "%SYS-2-MALLOCFAIL", "cisco_ios", "crit", ""),
    # (d) IOS year stamp, "host:" form
    ("<187>Oct 22 2026 10:15:01 r1: %BGP-5-ADJCHANGE: neighbor 10.1.1.2 Down",
     "2026-10-22T10:15:01", "r1", "%BGP-5-ADJCHANGE", "cisco_ios", "err", "2026-10-22T10:15:01Z"),
    # (e) timezone abbreviation between stamp and host
    (f"<187>Oct 22 10:15:01 UTC leaf1 bgpd[12]: {BGP}",
     "Oct 22 10:15:01", "leaf1", "bgpd", "frr", "err", ""),
])
def test_envelope_framings(line, ts, host, app, vendor, sev, norm):
    ev = parse_line(line, "dflt")
    assert (ev.timestamp, ev.hostname, ev.appname, ev.vendor, ev.severity_raw) == (ts, host, app, vendor, sev)
    assert ev.attrs["parser"] == "syslog"
    if norm:
        assert ev.normalized_utc_ts == norm
    else:
        assert ev.normalized_utc_ts   # yearless stamp: dated against the clock, never empty


def test_framed_bgp_lines_keep_their_entities():
    ev = parse_line(f"<189>2026-10-22T10:15:01.123456+00:00 leaf1 bgpd[12]: {BGP}")
    assert (ev.event_type, ev.peer_ip, ev.vrf, ev.state) == ("bgp_session", "10.1.1.2", "default", "down")
    ev = parse_line("<186>Oct 22 10:15:01 nx1 %BGP-5-ADJCHANGE: bgp-65001 [123] (default) neighbor 10.1.1.2 Down")
    assert (ev.vendor, ev.event_type, ev.vrf, ev.state) == ("cisco_nxos", "bgp_session", "default", "down")


def test_unknown_timezone_abbreviation_is_never_misdated():
    # "EST" (UTC-5) is not guessed: the stamp keeps its text and gets no UTC time.
    ev = parse_line("Oct 22 2026 10:15:01 EST leaf1 bgpd[12]: " + BGP)
    assert ev.hostname == "leaf1" and ev.normalized_utc_ts == ""


def test_iosxr_location_tag_is_unwrapped():
    line = ("Oct 22 10:15:01 xr1 RP/0/RP0/CPU0:Oct 22 10:15:01.123 UTC: bgp[1052]: "
            "%ROUTING-BGP-5-ADJCHANGE : neighbor 10.1.1.2 - Down - BGP Notification received")
    ev = parse_line(line)
    assert (ev.hostname, ev.appname, ev.vendor) == ("xr1", "bgp", "cisco_ios")
    assert (ev.event_type, ev.peer_ip, ev.state) == ("bgp_session", "10.1.1.2", "down")
    # sequence-number form
    ev = parse_line("<189>Oct 22 10:15:01 xr1 123: RP/0/RSP0/CPU0:Oct 22 10:15:01.1 UTC: bgp[1052]: "
                    "%ROUTING-BGP-5-ADJCHANGE : neighbor 10.1.1.2 Up (VRF: default) (AS: 65000)")
    assert (ev.appname, ev.vendor, ev.state, ev.asn) == ("bgp", "cisco_ios", "up", "65000")


def test_rfc5424_nilvalue_timestamp_is_empty():
    env = split_envelope("<165>1 - leaf1 bgpd 123 - - hello")
    assert env.fmt == "rfc5424" and env.timestamp == ""
    ev = parse_line("<165>1 - leaf1 bgpd 123 - - hello")
    assert ev.timestamp == "" and ev.normalized_utc_ts == "" and ev.hostname == "leaf1"


@pytest.mark.parametrize("line,expected", [
    # plain framings keep their exact legacy fields
    ("Oct 13 10:00:01 sw1 mib2d[1234]: SNMP_TRAP_LINK_DOWN: ifIndex 545",
     ("Oct 13 10:00:01", "sw1", "mib2d", "info")),
    ("<13>Oct 13 10:00:01 sw1 mib2d[1234]: SNMP_TRAP_LINK_DOWN: ifIndex 545",
     ("Oct 13 10:00:01", "sw1", "mib2d", "notice")),
    ("Oct  3 10:00:01 sw1 sshd[9]: hello", ("Oct  3 10:00:01", "sw1", "sshd", "info")),
    ("a hostname EDGE-like line: Oct 22 10:15:01 x y z", ("", "dflt", "syslog", "info")),
])
def test_plain_framings_unchanged(line, expected):
    ev = parse_line(line, "dflt")
    assert (ev.timestamp, ev.hostname, ev.appname, ev.severity_raw) == expected


def test_loose_relay_header_without_tag_uses_syslog_parser():
    ev = parse_line("<13>Oct 22 10:15:01 fw-edge some free text without a colon tag")
    assert (ev.timestamp, ev.hostname, ev.appname, ev.severity_raw) == ("Oct 22 10:15:01", "fw-edge",
                                                                       "syslog", "notice")
    assert ev.attrs["parser"] == "syslog"
