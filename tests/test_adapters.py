"""Tests for log adapters (FRR + generic file)."""
import pytest

from ai_log_analyzer.adapters.file import parse_lines
from ai_log_analyzer.adapters.frr import parse_frr_line


@pytest.mark.unit
def test_frr_line_with_id():
    ev = parse_frr_line(
        "2026/05/03 23:21:06 WATCHFRR: [QDG3Y-BY5TN] zebra state -> up : connect succeeded",
        hostname="de-fra-core-01",
    )
    assert ev is not None
    assert ev.timestamp == "2026-05-03T23:21:06"
    assert ev.appname == "watchfrr"
    assert ev.hostname == "de-fra-core-01"
    assert "zebra state" in ev.message


@pytest.mark.unit
def test_frr_line_severity_hint_down_means_err():
    ev = parse_frr_line(
        "2026/04/30 19:14:38 WATCHFRR: [ZCJ3S-SPH5S] bgpd state -> down : initial connection attempt failed",
        hostname="de-fra-core-01",
    )
    assert ev is not None
    assert ev.severity_raw == "err"


@pytest.mark.unit
def test_frr_line_freeform_no_timestamp():
    ev = parse_frr_line("Please, use 'ip ospf passive' on an interface instead.", hostname="rt-01")
    assert ev is not None
    assert ev.timestamp == ""
    assert ev.severity_raw == "info"
    assert "ip ospf passive" in ev.message


@pytest.mark.unit
def test_frr_empty_line_returns_none():
    assert parse_frr_line("", hostname="h") is None


@pytest.mark.unit
def test_file_parse_rfc3164():
    line = "Mar  3 12:00:01 router1 rpd[1234]: bgp peer 10.0.0.1 down"
    events = list(parse_lines([line]))
    assert len(events) == 1
    ev = events[0]
    assert ev.hostname == "router1"
    assert ev.appname == "rpd"
    assert "bgp peer" in ev.message


@pytest.mark.unit
def test_file_parse_rfc5424():
    line = "<134>1 2026-05-09T10:00:00Z router1 rpd 1234 ID47 - bgp peer 10.0.0.1 down"
    events = list(parse_lines([line]))
    assert len(events) == 1
    ev = events[0]
    assert ev.hostname == "router1"
    assert ev.appname == "rpd"
    assert ev.severity_raw == "info"  # PRI 134 -> facility 16 + severity 6 = info


@pytest.mark.unit
def test_file_parse_pri_to_severity_critical():
    # PRI 130 = facility 16 + severity 2 (crit)
    line = "<130>1 2026-05-09T10:00:00Z h1 app 1 ID - parity error at 0xABCD"
    events = list(parse_lines([line]))
    assert events[0].severity_raw == "crit"


@pytest.mark.unit
def test_file_parse_freeform_fallback():
    events = list(parse_lines(["just some random text with no structure"], default_host="h1"))
    assert len(events) == 1
    assert events[0].hostname == "h1"
    assert events[0].appname == "syslog"
    assert events[0].severity_raw == "info"


@pytest.mark.unit
def test_file_parse_skips_blank_lines():
    events = list(parse_lines(["", "  ", "\n"]))
    assert events == []
