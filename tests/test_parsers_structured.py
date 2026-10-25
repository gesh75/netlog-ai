"""JSON / CEF / LEEF line parsers: fields are lifted out of the blob, entity
enrichment still runs on the message, and unknown shapes fall back as before."""
from __future__ import annotations

import json

import pytest

from ai_log_analyzer.parsers import parse_line

pytestmark = pytest.mark.unit


def test_json_line_fields_and_entities():
    line = json.dumps({"@timestamp": "2026-10-22T10:15:01.123Z", "host": {"name": "leaf1"}, "level": "ERROR",
                       "program": "bgpd",
                       "message": "%ADJCHANGE: neighbor 10.1.1.2 in vrf default Down"})
    ev = parse_line(line, "dflt")
    assert (ev.timestamp, ev.hostname, ev.appname, ev.severity_raw) == (
        "2026-10-22T10:15:01.123Z", "leaf1", "bgpd", "err")
    assert ev.message == "%ADJCHANGE: neighbor 10.1.1.2 in vrf default Down"
    assert (ev.vendor, ev.event_type, ev.peer_ip, ev.state, ev.vrf) == (
        "frr", "bgp_session", "10.1.1.2", "down", "default")
    assert ev.normalized_utc_ts == "2026-10-22T10:15:01Z" and ev.attrs["parser"] == "json"


def test_json_alternate_keys_epoch_and_numeric_severity():
    ev = parse_line('{"msg": "link down on Ethernet12", "hostname": "sw9", "time": 1792664101, "severity": 3}',
                    "dflt")
    assert (ev.hostname, ev.severity_raw, ev.timestamp) == ("sw9", "err", "2026-10-22T10:15:01Z")
    assert ev.appname == "json"
    ev = parse_line('{"log": "hello", "devname": "fgt1", "ts": "1792664101123"}')
    assert (ev.hostname, ev.timestamp) == ("fgt1", "2026-10-22T10:15:01Z")


def test_json_behind_a_syslog_header():
    ev = parse_line('<189>Oct 22 10:15:01 collector fluentd[1]: {"message": "peer 10.1.1.2 down", '
                    '"host": "leaf1"}')
    assert (ev.hostname, ev.timestamp, ev.attrs["parser"]) == ("leaf1", "Oct 22 10:15:01", "json")


@pytest.mark.parametrize("line", [
    '{"foo": "bar", "count": 3}',                    # no message-like key
    '{"message": "truncated json", "host":',         # invalid
    '["message", "list not object"]',
    '{"message": {"nested": "object"}}',
])
def test_unrecognised_json_falls_back_as_before(line):
    ev = parse_line(line, "dflt")
    assert ev.attrs["parser"] == "fallback" and ev.message == line and ev.hostname == "dflt"


def test_cef_with_syslog_header_and_extension():
    line = ("<134>Oct 22 10:15:01 siem-fwd CEF:0|Acme|NetGuard|2.1|1001|BGP session down|7|"
            "rt=1792664101000 dvchost=edge-fw1 src=10.1.1.2 msg=BGP peer 10.1.1.2 changed state "
            "from Established to Idle cs1Label=x")
    ev = parse_line(line, "dflt")
    assert ev.attrs["parser"] == "cef"
    assert (ev.hostname, ev.appname, ev.severity_raw) == ("edge-fw1", "NetGuard", "err")
    assert ev.timestamp == "2026-10-22T10:15:01Z"
    assert ev.message == "BGP session down: BGP peer 10.1.1.2 changed state from Established to Idle"
    assert (ev.event_type, ev.peer_ip, ev.state) == ("bgp_session", "10.1.1.2", "down")
    assert ev.attrs["cef_vendor"] == "Acme" and ev.attrs["cef_signature"] == "1001"


def test_cef_bare_line_uses_header_name_and_escaped_pipe():
    ev = parse_line(r"CEF:0|Acme|Net\|Guard|1|7|Link flap|9|dvchost=sw1", "dflt")
    assert (ev.hostname, ev.appname, ev.severity_raw, ev.message) == ("sw1", "Net|Guard", "crit", "Link flap")


def test_cef_truncated_header_falls_back():
    ev = parse_line("CEF:0|Acme|NetGuard|2.1", "dflt")
    assert ev.attrs["parser"] == "fallback"


def test_leef_1_and_2():
    ev = parse_line("Oct 22 10:15:01 qr-fwd LEEF:1.0|Acme|NetGuard|2.1|PEER_DOWN|"
                    "devTime=2026-10-22T10:15:01Z\tdevName=edge1\tmsg=BGP peer 10.1.1.2 down\tsev=7", "dflt")
    assert ev.attrs["parser"] == "leef"
    assert (ev.hostname, ev.timestamp, ev.appname, ev.severity_raw) == (
        "edge1", "2026-10-22T10:15:01Z", "NetGuard", "err")
    assert (ev.event_type, ev.peer_ip, ev.state) == ("bgp_session", "10.1.1.2", "down")
    ev = parse_line("LEEF:2.0|Acme|NetGuard|2.1|PEER_DOWN|^|devName=edge2^msg=link down Ethernet1", "dflt")
    assert (ev.hostname, ev.message) == ("edge2", "PEER_DOWN: link down Ethernet1")
    assert (ev.event_type, ev.interface, ev.state) == ("interface_link", "Ethernet1", "down")


def test_existing_vendor_parsers_still_win_over_json():
    # a FortiOS key=value line is not mistaken for JSON, CEF or LEEF
    line = ('<189>date=2026-10-20 time=07:01:02 devname="FGT-HQ-01" devid="FG100F" logid="0101037129" '
            'type="event" subtype="vpn" level="error" msg="IPsec phase 1 error"')
    assert parse_line(line).attrs["parser"] == "fortios"
