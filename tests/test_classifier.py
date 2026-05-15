"""Unit tests for the regex-based classifier."""
import pytest

from ai_log_analyzer.classifier import LogEvent, classify_events, SEV_ORDER


@pytest.mark.unit
def test_bgp_down_classified_high():
    ev = LogEvent("2026-05-09T10:00:00", "rt-01", "rpd", "err", "bgp peer 10.0.0.1 down (hold timer expired)")
    out, sev_counts, _ = classify_events([ev])
    assert out[0].severity == "high"
    assert out[0].category == "routing"
    assert sev_counts["high"] == 1


@pytest.mark.unit
def test_kernel_panic_classified_critical():
    ev = LogEvent("2026-05-09T10:00:00", "sw-01", "kernel", "crit", "kernel panic - not syncing")
    out, sev_counts, _ = classify_events([ev])
    assert out[0].severity == "critical"
    assert out[0].category == "system"
    assert sev_counts["critical"] == 1


@pytest.mark.unit
def test_link_up_classified_medium_interface():
    ev = LogEvent("2026-05-09T10:00:00", "sw-01", "mib2d", "info", "ifIndex 538 link up")
    out, _, cat_counts = classify_events([ev])
    assert out[0].severity == "medium"
    assert out[0].category == "interface"
    assert cat_counts["interface"] == 1


@pytest.mark.unit
def test_unknown_message_falls_back_to_info_other():
    ev = LogEvent("", "", "", "info", "some random non-network message")
    out, sev_counts, _ = classify_events([ev])
    assert out[0].severity == "info"
    assert out[0].category == "other"
    assert sev_counts["info"] == 1


@pytest.mark.unit
def test_severity_promotion_when_raw_is_critical_but_no_pattern_match():
    # Raw severity "crit" should bump unmatched event to "high"
    ev = LogEvent("", "", "weirdd", "crit", "totally novel message with no regex match here")
    out, _, _ = classify_events([ev])
    assert out[0].severity == "high"


@pytest.mark.unit
def test_sort_order_critical_first():
    events = [
        LogEvent("2026-05-09T10:00:00", "h1", "sshd", "info", "accepted publickey for user"),
        LogEvent("2026-05-09T10:00:00", "h2", "kernel", "crit", "kernel panic"),
        LogEvent("2026-05-09T10:00:00", "h3", "rpd", "err", "bgp peer down"),
    ]
    out, _, _ = classify_events(events)
    severities = [e.severity for e in out]
    assert severities.index("critical") < severities.index("high") < severities.index("low")


@pytest.mark.unit
def test_hostname_strips_fqdn():
    ev = LogEvent("", "rt-01.net.example.com", "rpd", "info", "starting")
    out, _, _ = classify_events([ev])
    assert out[0].hostname == "rt-01"


@pytest.mark.unit
def test_severity_order_constants():
    assert SEV_ORDER["critical"] < SEV_ORDER["high"] < SEV_ORDER["medium"] < SEV_ORDER["low"] < SEV_ORDER["info"]


@pytest.mark.unit
def test_lacp_timeout_high_lag():
    ev = LogEvent("", "sw-01", "lacpd", "err", "ae0 lacp timeout expired on member ge-0/0/1")
    out, _, _ = classify_events([ev])
    assert out[0].category == "lag"
    assert out[0].severity == "high"


@pytest.mark.unit
def test_license_expiration_compliance():
    ev = LogEvent("", "sw-01", "license", "warning", "license will expire in 14 days")
    out, _, _ = classify_events([ev])
    assert out[0].category == "compliance"
    assert out[0].severity == "high"


@pytest.mark.unit
def test_bulk_classification_counts():
    events = [
        LogEvent("", "h1", "rpd", "err", "bgp peer 1.1.1.1 down"),
        LogEvent("", "h1", "rpd", "err", "bgp peer 2.2.2.2 down"),
        LogEvent("", "h2", "kernel", "crit", "kernel panic"),
        LogEvent("", "h3", "sshd", "info", "accepted publickey"),
    ]
    out, sev_counts, _ = classify_events(events)
    assert len(out) == 4
    assert sev_counts["critical"] == 1
    assert sev_counts["high"] == 2
    assert sev_counts["low"] == 1
