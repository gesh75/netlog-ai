"""The compiled-alternation literal gate must equal a scan of every literal,
and classify_events must order mixed timestamp formats by real time."""
from __future__ import annotations

import itertools
import random

import pytest

from ai_log_analyzer import classifier
from ai_log_analyzer.classifier import LogEvent, classify_events


def _naive_present(text: str) -> tuple[str, ...]:
    return tuple(k for k in classifier._GATE_LITERALS if k in text)


@pytest.mark.unit
def test_keywords_are_substring_free():
    # The exactness argument for the alternation rests on this invariant.
    kws = classifier._KEYWORDS
    assert not [(a, b) for a in kws for b in kws if a != b and a in b]


@pytest.mark.unit
def test_present_literals_equals_naive_scan_for_each_literal_alone_and_padded():
    for lit in classifier._GATE_LITERALS:
        for text in (lit, f"zz {lit} zz", f"{lit}{lit}", lit.upper().lower()):
            assert classifier._present_literals(text) == _naive_present(text), (lit, text)


@pytest.mark.unit
def test_present_literals_equals_naive_scan_for_overlapping_literals():
    """Non-overlapping scanning would drop a literal that overlaps its neighbour."""
    lits = classifier._GATE_LITERALS
    checked = 0
    for a, b in itertools.permutations(lits, 2):
        for k in range(1, min(len(a), len(b))):
            if a.endswith(b[:k]):
                text = a + b[k:]
                assert classifier._present_literals(text) == _naive_present(text), (a, b)
                checked += 1
    assert checked > 0


@pytest.mark.unit
def test_present_literals_equals_naive_scan_on_random_concatenations():
    rng = random.Random(11)
    lits = list(classifier._GATE_LITERALS)
    for _ in range(400):
        parts = [rng.choice(lits) for _ in range(rng.randint(1, 5))]
        text = rng.choice(["", " ", "-"]).join(parts)
        assert classifier._present_literals(text) == _naive_present(text), text


@pytest.mark.unit
def test_gated_first_match_equals_ungated_first_match_on_fragment_lines():
    rng = random.Random(5)
    frags = list(classifier._GATE_LITERALS) + ["down", "up", "peer", "10.0.0.1", "established", "to"]
    for _ in range(600):
        text = " ".join(rng.choice(frags) for _ in range(rng.randint(1, 6)))
        gated = next((p for p in classifier._gated_candidates(text) if p[0].search(text)), None)
        full = next((p for p in classifier._COMPILED if p[0].search(text)), None)
        assert gated == full, text


@pytest.mark.unit
def test_mixed_timestamp_formats_sort_by_real_time_newest_first():
    def ev(host, ts):
        return LogEvent(ts, host, "rpd", "err", "bgp peer 10.0.0.1 down")

    events = [
        ev("a", "2026-10-22T11:00:00+02:00"),   # 09:00Z, but lexically the largest ISO string
        ev("b", "2026-10-22T09:30:00Z"),
        ev("c", "2026/10/22 09:45:00"),         # PAN-OS style, 09:45Z
    ]
    out, _, _ = classify_events(events)
    assert [e.hostname for e in out] == ["c", "b", "a"]


@pytest.mark.unit
def test_unparseable_timestamps_sort_oldest_and_do_not_crash():
    events = [
        LogEvent("garbage", "x", "rpd", "err", "bgp peer 10.0.0.1 down"),
        LogEvent("2026-10-22T09:30:00Z", "y", "rpd", "err", "bgp peer 10.0.0.1 down"),
    ]
    out, _, _ = classify_events(events)
    assert [e.hostname for e in out] == ["y", "x"]
