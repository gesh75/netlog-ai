"""Tests for the tfsm_fire auto-parsing adapter.

These tests are skipped if `tfsm-fire` isn't installed (optional `parse` extra).
They use real upstream templates against canned device output — no mocking — to
prove the integration actually works end-to-end against scottpeterman's DB.
"""
from __future__ import annotations

import pytest

from ai_log_analyzer.adapters import tfsm_auto
from ai_log_analyzer.adapters.network_tool import CommandResult, parse_output

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Skip if the optional extra isn't installed. The unit suite must stay green
# in environments that haven't installed the `parse` extra.
# ---------------------------------------------------------------------------
if not tfsm_auto.is_available():
    pytest.skip("tfsm-fire not installed (install with: pip install netlog-ai[parse])",
                allow_module_level=True)


# ---------------------------------------------------------------------------
# Canned device output fixtures. These are intentionally short and well-formed
# so the template-scorer has something obvious to lock onto.
# ---------------------------------------------------------------------------

CISCO_LLDP_NEIGHBORS = """\
Capability codes:
    (R) Router, (B) Bridge, (T) Telephone, (C) DOCSIS Cable Device
    (W) WLAN Access Point, (P) Repeater, (S) Station, (O) Other

Device ID           Local Intf     Hold-time  Capability      Port ID
switch1             Gi0/1          120        R               Gi1/0/1
switch2             Gi0/2          120        R               Gi1/0/2
switch3             Gi0/3          120        R               Gi1/0/3

Total entries displayed: 3
"""


def test_is_available_returns_true_after_install():
    """If we got past the module-level skip, this must hold."""
    assert tfsm_auto.is_available() is True


def test_auto_parse_empty_input_returns_no_match():
    """Empty input must short-circuit before touching the engine."""
    result = tfsm_auto.auto_parse("")
    assert result.matched is False
    assert result.records == []
    assert result.template is None


def test_auto_parse_whitespace_only_returns_no_match():
    """Whitespace-only input is equivalent to empty."""
    result = tfsm_auto.auto_parse("   \n\n  \t  ")
    assert result.matched is False
    assert result.records == []


def test_auto_parse_lldp_finds_template_with_filter_hint():
    """With a filter_hint the scan is fast and should pick an LLDP template."""
    result = tfsm_auto.auto_parse(CISCO_LLDP_NEIGHBORS, filter_hint="lldp_neighbor")
    assert result.matched is True, f"expected a match; got candidates: {result.candidates[:5]}"
    assert "lldp" in result.template.lower()
    assert len(result.records) == 3
    # Every record must have at least a neighbor identifier
    for record in result.records:
        assert any(record.values()), "record should have at least one populated field"


def test_auto_parse_returns_immutable_result():
    """ParseResult is a frozen dataclass — mutation must raise."""
    result = tfsm_auto.auto_parse(CISCO_LLDP_NEIGHBORS, filter_hint="lldp_neighbor")
    with pytest.raises((AttributeError, TypeError)):
        result.template = "tampered"  # type: ignore[misc]


def test_min_score_threshold_rejects_low_confidence():
    """A min_score of 999 should reject every match — nothing scores that high."""
    result = tfsm_auto.auto_parse(CISCO_LLDP_NEIGHBORS,
                                   filter_hint="lldp_neighbor",
                                   min_score=999.0)
    assert result.matched is False
    assert result.records == []
    # But the candidate list still records what would have matched
    assert result.score > 0 or len(result.candidates) > 0


def test_parse_output_helper_with_failed_command():
    """parse_output() must return [] for a failed CommandResult without touching the engine."""
    bad = CommandResult(ok=False, hostname="r1", command="show lldp", output="", error="auth fail")
    assert parse_output(bad) == []


def test_parse_output_helper_with_empty_output():
    """parse_output() must return [] when the command succeeded but produced nothing."""
    empty = CommandResult(ok=True, hostname="r1", command="show lldp", output="", error="")
    assert parse_output(empty) == []


def test_parse_output_helper_with_lldp_data():
    """parse_output() returns parsed records when given good output and a hint."""
    good = CommandResult(
        ok=True, hostname="r1", command="show lldp neighbors",
        output=CISCO_LLDP_NEIGHBORS, error="",
    )
    records = parse_output(good, filter_hint="lldp_neighbor", min_score=10.0)
    assert len(records) == 3
    assert all(isinstance(r, dict) for r in records)


def test_engine_cache_reuse():
    """Calling auto_parse twice should reuse the cached engine (no second DB download)."""
    r1 = tfsm_auto.auto_parse(CISCO_LLDP_NEIGHBORS, filter_hint="lldp_neighbor")
    r2 = tfsm_auto.auto_parse(CISCO_LLDP_NEIGHBORS, filter_hint="lldp_neighbor")
    assert r1.template == r2.template
    assert r1.score == r2.score


def test_reset_engine_cache_clears_singleton():
    """reset_engine_cache lets tests swap DB paths cleanly."""
    tfsm_auto.auto_parse(CISCO_LLDP_NEIGHBORS, filter_hint="lldp_neighbor")
    tfsm_auto.reset_engine_cache()
    assert tfsm_auto._engine is None
    assert tfsm_auto._engine_db_path is None
