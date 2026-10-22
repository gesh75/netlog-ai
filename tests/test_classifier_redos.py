"""Built-in KB regexes must not let one oversized syslog line pin a worker.

Ingest caps a line at 64 KB and the sender controls the text. Before the bound,
``vdaemon.*(?:connection.*is up|...)`` and the fortios-vpn phase rules were
polynomial: 11.6 KB took 13.6 s and 64 KB over 100 s.
"""
from __future__ import annotations

import random
import re
import time

import pytest

from ai_log_analyzer import classifier
from ai_log_analyzer.classifier import LogEvent, classify_events

_UNIT = "control-connection-state-change new-state vdaemon connection "


def _classify_seconds(message: str, appname: str = "vdaemon") -> tuple[float, list]:
    ev = LogEvent("2026-05-09T10:00:00", "edge1", appname, "info", message)
    t0 = time.perf_counter()
    out, _, _ = classify_events([ev])
    return time.perf_counter() - t0, out


@pytest.mark.unit
@pytest.mark.parametrize("size", [11_600, 64_000])
def test_adversarial_sdwan_line_classifies_fast(size):
    elapsed, out = _classify_seconds(_UNIT * (size // len(_UNIT)))
    assert elapsed < 1.0, f"{size} byte adversarial line took {elapsed:.2f}s"
    assert len(out) == 1


@pytest.mark.unit
@pytest.mark.parametrize("unit, appname", [
    ("fortios-vpn phase1 ike sa kmd ", "fortios-vpn"),
    ("fortios-ha heartbeat hbdev ha1 link ", "fortios-ha"),
    ("panos-routing bgp established to ", "panos-routing"),
    ("ptmd link bfd teamd slave clagd peer ", "ptmd"),
])
def test_adversarial_vendor_lines_classify_fast(unit, appname):
    elapsed, _ = _classify_seconds(unit * (64_000 // len(unit)), appname)
    assert elapsed < 1.0, f"{appname} adversarial line took {elapsed:.2f}s"


@pytest.mark.unit
def test_every_builtin_pattern_is_bounded_on_adversarial_shapes():
    """Scan the whole table with each pattern's own tokens repeated to the match cap."""
    rng = random.Random(7)
    size = classifier._MAX_MATCH_CHARS
    slow: list[tuple[float, str]] = []
    for (src, *_), (compiled, *_rest) in zip(classifier._KB_PATTERNS, classifier._COMPILED):
        toks = list(dict.fromkeys(re.findall(r"[a-z][a-z0-9_%\-]{2,}", src)))[:12] or ["x"]
        shuffled = toks[:]
        rng.shuffle(shuffled)
        worst = 0.0
        for shape in (" ".join(toks), " ".join(reversed(toks)), " ".join(shuffled), toks[0] + " "):
            text = ((shape + " ") * (size // (len(shape) + 1) + 1))[:size]
            t0 = time.perf_counter()
            compiled.search(text)
            worst = max(worst, time.perf_counter() - t0)
        if worst > 0.5:
            slow.append((worst, src))
    assert not slow, slow


@pytest.mark.unit
def test_overlong_line_keeps_head_and_tail_for_matching():
    # The state word sits at the very end of an over-cap line: truncation must keep it.
    msg = "x" * 20_000 + " bgp peer 10.0.0.1 down"
    _, out = _classify_seconds(msg, "rpd")
    assert out[0].category == "routing" and out[0].severity == "high"
    # ...and a keyword in the head survives too.
    msg = "bgp peer 10.0.0.1 down " + "y" * 20_000
    _, out = _classify_seconds(msg, "rpd")
    assert out[0].category == "routing"


@pytest.mark.unit
def test_bound_for_kb_is_identity_below_cap_and_capped_above():
    assert classifier._bound_for_kb("abc") == "abc"
    long = "a" * 5000 + "TAIL"
    bounded = classifier._bound_for_kb(long)
    assert len(bounded) <= classifier._MAX_MATCH_CHARS and bounded.endswith("TAIL")


@pytest.mark.unit
def test_bound_gaps_rewrites_wildcards_but_not_escapes_or_classes():
    assert classifier._bound_gaps("a.*b") == "a.{0,300}b"
    assert classifier._bound_gaps(r"a\.*b") == r"a\.*b"
    assert classifier._bound_gaps("[.*]x.*") == "[.*]x.{0,300}"
    assert classifier._bound_gaps("a.*?b") == "a.{0,300}?b"
