"""Unit tests for per-device deep triage (ai_log_analyzer.device_triage)."""
from __future__ import annotations

import pytest

from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.device_triage import normalize_pattern, triage_device


# ── helpers ──────────────────────────────────────────────────────────────────

def _make_event(
    hostname: str = "h1",
    appname: str = "rpd",
    severity_raw: str = "err",
    message: str = "bgp peer 10.0.0.1 down",
) -> LogEvent:
    """Convenience constructor for a LogEvent."""
    return LogEvent("2026-05-09T10:00:00", hostname, appname, severity_raw, message)


# ── normalize_pattern tests ───────────────────────────────────────────────────

@pytest.mark.unit
def test_normalize_strips_hex_pid_ip():
    """normalize_pattern must replace hex addresses, PIDs, and IPs with tokens."""
    raw = "rpd[1234]: peer 10.0.0.1 at 0xdeadbeef reset"
    key = normalize_pattern(raw)

    assert "[N]" in key
    assert "IP" in key
    assert "0xADDR" in key

    # Originals must be gone.
    assert "1234" not in key
    assert "10.0.0.1" not in key
    assert "0xdeadbeef" not in key


@pytest.mark.unit
def test_normalize_truncates_to_120_chars():
    """normalize_pattern must truncate output to 120 characters."""
    long_msg = "x" * 300
    assert len(normalize_pattern(long_msg)) <= 120


@pytest.mark.unit
def test_normalize_empty_string():
    """normalize_pattern must handle empty input gracefully."""
    assert normalize_pattern("") == ""


# ── triage_device tests ───────────────────────────────────────────────────────

@pytest.mark.unit
def test_pattern_frequency_dedup():
    """Events that differ only by IP/PID must collapse to ONE pattern with count == 3."""
    events = [
        _make_event(message="rpd[100]: peer 10.0.0.1 at 0xaaaa reset"),
        _make_event(message="rpd[200]: peer 10.0.0.2 at 0xbbbb reset"),
        _make_event(message="rpd[300]: peer 10.0.0.3 at 0xcccc reset"),
    ]
    result = triage_device("h1", events)

    assert len(result.patterns) == 1
    assert result.patterns[0]["count"] == 3


@pytest.mark.unit
def test_non_error_severity_excluded_from_patterns():
    """An 'info' event must produce no pattern entry."""
    events = [
        _make_event(severity_raw="info", message="rpd[1]: bgp peer up"),
    ]
    result = triage_device("h1", events)

    assert result.patterns == []


@pytest.mark.unit
def test_verdict_hardware_from_fpc_process():
    """Events from fpc0 with err severity must yield a HARDWARE FAILURE verdict."""
    events = [
        _make_event(appname="fpc0", severity_raw="err",
                    message="fpc0 parity error at slot 0"),
    ]
    result = triage_device("h1", events)

    assert result.issue_type == "hardware"
    assert result.verdict.startswith("HARDWARE FAILURE")


@pytest.mark.unit
def test_verdict_routing_from_rpd():
    """Events from rpd with err severity must yield a ROUTING ISSUE verdict."""
    events = [
        _make_event(appname="rpd", severity_raw="err",
                    message="bgp peer 10.0.0.1 down hold timer expired"),
    ]
    result = triage_device("h1", events)

    assert result.issue_type == "routing"
    assert result.verdict.startswith("ROUTING ISSUE")


@pytest.mark.unit
def test_verdict_security_from_sshd():
    """sshd with error-grade events (e.g. auth failures) yields 'security'."""
    events = [
        _make_event(appname="sshd", severity_raw="err",
                    message="error: maximum authentication attempts exceeded for admin"),
    ]
    result = triage_device("h1", events)

    assert result.issue_type == "security"
    assert "SSH" in result.verdict


@pytest.mark.unit
def test_sshd_info_only_is_not_security():
    """Pure sshd info logins (no errors anywhere) must NOT be flagged 'security' —
    that would mislabel a healthy device. Expect a clean/info verdict."""
    events = [
        _make_event(appname="sshd", severity_raw="info",
                    message="accepted publickey for admin from 192.168.1.1"),
    ]
    result = triage_device("h1", events)

    assert result.issue_type == "info"


@pytest.mark.unit
def test_verdict_info_when_clean():
    """Clean info events must yield an INFORMATIONAL verdict with health_score == 100."""
    events = [
        _make_event(appname="mgd", severity_raw="info",
                    message="UI_COMMIT: User 'admin' done"),
        _make_event(appname="snmpd", severity_raw="info",
                    message="snmp trap sent"),
    ]
    result = triage_device("h1", events)

    assert result.issue_type == "info"
    assert result.verdict.startswith("INFORMATIONAL")
    assert result.health_score == 100


@pytest.mark.unit
def test_score_drops_with_criticals():
    """Many crit events must lower health_score below 100, capped by the formula."""
    n = 10  # 10 crit events -> 10*5=50 penalty -> score = 50
    events = [
        _make_event(severity_raw="crit", message=f"critical failure {i}")
        for i in range(n)
    ]
    result = triage_device("h1", events)

    expected_max = 100 - min(n * 5, 50)
    assert result.health_score < 100
    assert result.health_score <= expected_max


@pytest.mark.unit
def test_processes_sorted_desc_with_pct():
    """processes must be sorted descending by count; pct values must sum ~100."""
    events = [
        _make_event(appname="rpd", severity_raw="err"),
        _make_event(appname="rpd", severity_raw="err"),
        _make_event(appname="rpd", severity_raw="err"),
        _make_event(appname="mib2d", severity_raw="info"),
        _make_event(appname="mib2d", severity_raw="info"),
        _make_event(appname="sshd", severity_raw="info"),
    ]
    result = triage_device("h1", events)

    # First process must be the most frequent one.
    assert result.processes[0]["process"] == "rpd"
    assert result.processes[0]["count"] == 3

    # Pct values must sum approximately to 100.
    total_pct = sum(p["pct"] for p in result.processes)
    assert abs(total_pct - 100.0) <= 0.5


@pytest.mark.unit
def test_empty_events_clean_verdict():
    """Empty event list must yield total_events==0, 'No events found', score 100."""
    result = triage_device("h1", [])

    assert result.total_events == 0
    assert result.verdict == "No events found"
    assert result.health_score == 100
    assert result.issue_type == "info"
    assert result.processes == []
    assert result.patterns == []


@pytest.mark.unit
def test_input_not_mutated():
    """triage_device must not mutate the caller's events list."""
    original_event = _make_event()
    original_list = [original_event]

    triage_device("h1", original_list)

    assert original_list == [original_event]
    assert len(original_list) == 1
