"""Literal-gate soundness: the keyword fast path must never change results.

The gate skips the ordered 75-pattern loop for lines that provably cannot
match any guarded pattern. These tests pin the equivalence and the gate's
structural invariants so KB additions can't silently break either.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from ai_log_analyzer import classifier
from ai_log_analyzer.adapters.file import parse_file
from ai_log_analyzer.classifier import LogEvent, classify_events

SAMPLES = Path(__file__).resolve().parents[1] / "src" / "ai_log_analyzer" / "data" / "samples"


@pytest.mark.unit
def test_gate_equivalent_to_full_loop_on_sample_corpus(monkeypatch):
    events = []
    for f in SAMPLES.glob("*.txt"):
        events.extend(parse_file(f))
    assert events, "sample corpus is empty"

    gated = classify_events(events)

    # Disable the gate: empty keyword set routes every line through the
    # "unguarded" path, which we point at the full ordered pattern table.
    monkeypatch.setattr(classifier, "_KEYWORDS", ())
    monkeypatch.setattr(classifier, "_UNGUARDED", classifier._COMPILED)
    reference = classify_events(events)

    assert gated == reference


@pytest.mark.unit
def test_gate_invariants():
    assert all(len(k) >= 3 for k in classifier._KEYWORDS), \
        "short keyword would fire on every line and neuter the gate"
    assert len(classifier._UNGUARDED) <= 5, \
        "too many unguarded patterns — extraction regressed"
    assert len(classifier._KEYWORDS) >= 30, "suspiciously few keywords extracted"


@pytest.mark.unit
def test_guarded_pattern_still_matches():
    events = [LogEvent(timestamp="2026-01-01T00:00:00", hostname="r1",
                       appname="rpd", severity_raw="err",
                       message="BGP peer 192.0.2.1 (External AS 64900) down")]
    classified, sev_counts, _ = classify_events(events)
    assert classified[0].severity == "high"
    assert classified[0].category == "routing"


@pytest.mark.unit
def test_non_ascii_ignorecase_match_bypasses_literal_gate():
    events = [LogEvent(timestamp="2026-01-01T00:00:00", hostname="r1",
                       appname="authd", severity_raw="err",
                       message="authentıcation faıl")]

    classified, _, _ = classify_events(events)

    assert classified[0].severity == "high"
    assert classified[0].category == "security"
    assert classified[0].description == "Authentication failure"


@pytest.mark.unit
def test_unmatched_line_stays_info():
    events = [LogEvent(timestamp="2026-01-01T00:00:00", hostname="r1",
                       appname="cron", severity_raw="info",
                       message="job 42 completed normally")]
    classified, sev_counts, _ = classify_events(events)
    assert classified[0].severity == "info"
    assert sev_counts["info"] == 1
