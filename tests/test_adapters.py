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


# ──────────────────────────────────────────────────────────────────────────────
# SecureCRT terminal-recording parser
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_scrt_basic_line_parsed():
    """HH:MM:SS.ss § <text> is the SecureCRT recording format."""
    events = list(parse_lines(
        ["20:24:08.08 §Enter passphrase for PKCS#11: "],
        default_host="ach1-fw-20a",
    ))
    assert len(events) == 1
    assert events[0].timestamp == "20:24:08.08"
    assert events[0].appname == "scrt-session"
    assert events[0].hostname == "ach1-fw-20a"
    assert "PKCS#11" in events[0].message


@pytest.mark.unit
def test_scrt_classifier_still_fires_on_captured_output():
    """If a user pasted `show bgp summary` output into a terminal session,
    the SCRT parser strips the timestamp/§ and the classifier sees the inner
    text — so BGP-down events in captured terminal output are still detected."""
    from ai_log_analyzer.analyzer import analyze
    lines = [
        "20:30:01.01 §admin@ach1-fw-20a> show log messages | last 200",
        "20:30:02.02 §Feb 25 18:29:01 ach1-fw-20a rpd: bgp peer 10.0.0.1 down (hold timer expired)",
        "20:30:02.02 §Feb 25 18:29:02 ach1-fw-20a alarmd: LICENSE_EXPIRED feature bgp(47) expired",
        "20:30:02.02 §Feb 25 18:29:03 ach1-fw-20a kernel: fpc0 Unit 0: ASIC parity error",
    ]
    events = list(parse_lines(lines, default_host="ach1-fw-20a"))
    assert len(events) == 4
    # Run through the analyzer (KB only — no LLM needed)
    result = analyze(events, use_llm=False)
    payload = result.to_dict() if hasattr(result, "to_dict") else result
    items = payload.get("action_items") or []
    severities = {ai.get("severity") for ai in items}
    # We should pick up at least the critical (ASIC parity) and high
    # (BGP down, license expiry) findings even though they were captured
    # inside a SecureCRT session recording.
    assert "critical" in severities
    assert "high" in severities


@pytest.mark.unit
def test_scrt_empty_section_skipped():
    """Lines that are just a timestamp + § with no payload are ignored."""
    events = list(parse_lines(
        ["20:24:11.11 §", "20:24:12.12 §  "],
        default_host="x",
    ))
    assert events == []


@pytest.mark.unit
def test_parse_file_extracts_hostname_from_scrt_filename(tmp_path):
    """The SecureCRT filename pattern is `host (ip) -- date_time.log` — we
    should use just `host` so the dashboard groups events correctly."""
    from ai_log_analyzer.adapters.file import parse_file

    log = tmp_path / "ach1-fw-20a (10.1.15.1) -- 2026-02-25_18-29.log"
    log.write_text(
        "﻿20:30:01.01 §Start recording ach1-fw-20a\n"
        "20:30:02.02 §bgp peer 10.0.0.1 down (hold timer expired)\n",
        encoding="utf-8",
    )
    events = list(parse_file(log))
    assert len(events) == 2
    # Filename hostname stripping
    assert all(e.hostname == "ach1-fw-20a" for e in events)
    # BOM at the start of the file must not corrupt the first line
    assert "Start recording" in events[0].message


@pytest.mark.unit
def test_scrt_strips_leading_bom():
    """SecureCRT writes files as UTF-8 BOM. The first line must still parse."""
    events = list(parse_lines(
        ["﻿20:24:05.05 §Start recording session"],
        default_host="device1",
    ))
    assert len(events) == 1
    assert events[0].timestamp == "20:24:05.05"
    assert "Start recording session" in events[0].message
