"""Shared short-host helper: IP-addressed devices must not collapse."""
from __future__ import annotations

import pytest

from ai_log_analyzer.adapters.file import parse_lines
from ai_log_analyzer.classifier import classify_events
from ai_log_analyzer.hostnames import is_ip_literal, short_host


@pytest.mark.parametrize(("raw", "expected"), [
    ("10.0.0.1", "10.0.0.1"), ("10.0.0.2", "10.0.0.2"), ("2001:db8::1", "2001:db8::1"), ("[2001:DB8::1]", "[2001:db8::1]"),
    ("Edge1.DC1.example.com", "edge1"), ("R1", "r1"), ("  fgt-01 ", "fgt-01"), ("", ""), (None, ""),
])
def test_short_host(raw, expected):
    assert short_host(raw) == expected


def test_fold_false_keeps_case():
    assert short_host("FGT-HQ-01.corp.example", fold=False) == "FGT-HQ-01"


def test_is_ip_literal():
    assert is_ip_literal("10.1.2.3") and is_ip_literal("[::1]") and not is_ip_literal("edge1.example.com")


def test_ip_named_devices_stay_distinct_through_classification():
    lines = [f"Oct 22 10:00:0{i} 10.0.0.{i} %LINK-3-UPDOWN: Interface Ethernet1, changed state to down" for i in (1, 2)]
    hosts = sorted({e.hostname for e in classify_events(list(parse_lines(lines)))[0]})
    assert hosts == ["10.0.0.1", "10.0.0.2"]
