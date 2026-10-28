"""Snapshot diff is bounded: difflib is quadratic in what it aligns, and the input size was the caller's."""
from __future__ import annotations

import difflib
import random
import time

import pytest

from ai_log_analyzer import diff as diff_mod
from ai_log_analyzer import llm
from ai_log_analyzer.diff import ConfigDiff, explain_diff, structured_diff, text_diff

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _no_llm(monkeypatch):
    """explain_diff would otherwise try to reach a model."""
    monkeypatch.setattr(llm, "get_state", lambda: {"enabled": False})


def _old_changes(before: str, after: str):
    out = []
    for line in difflib.ndiff(before.splitlines(), after.splitlines()):
        if line.startswith("+ ") or line.startswith("- "):
            out.append(line[2:])
    return out


def _old_structured(before: str, after: str):
    adds, dels = [], []
    for line in difflib.Differ().compare(before.splitlines(), after.splitlines()):
        if line.startswith("+ "):
            adds.append(line[2:])
        elif line.startswith("- "):
            dels.append(line[2:])
    return adds, dels


def _two_texts(n: int) -> tuple[str, str]:
    return ("\n".join(f"line-{i:06d}" for i in range(n)), "\n".join(f"other-{i:06d}" for i in range(n)))


def _anagram_texts(n: int) -> tuple[str, str]:
    """No common lines, but every cross pair passes Differ's cheap filters and gets a full ratio()."""
    return ("\n".join(f"abcdefghijklmnop{i:04d}" for i in range(n)),
            "\n".join(f"ponmlkjihgfedcba{i:04d}" for i in range(n)))


def test_structured_diff_is_bounded_for_disjoint_texts():
    before, after = _anagram_texts(800)   # one big replace block: 640k line pairs for Differ
    t0 = time.perf_counter()
    out = structured_diff(before, after)
    elapsed = time.perf_counter() - t0
    assert elapsed < 2.0, f"800 x 800 disjoint lines took {elapsed:.1f}s"
    assert (out["lines_added"], out["lines_removed"]) == (800, 800)
    assert out["approximate"] is True


def test_changed_lines_is_bounded_for_disjoint_texts():
    before, after = _anagram_texts(800)
    cfg = ConfigDiff(before=before, after=after)
    t0 = time.perf_counter()
    lines = cfg.changed_lines()
    elapsed = time.perf_counter() - t0
    assert elapsed < 2.0, f"800 x 800 disjoint lines took {elapsed:.1f}s"
    assert len(lines) == 1_600
    assert cfg.diff_lines()[1] is True


def test_hundred_thousand_line_diff_returns_a_bounded_answer():
    """The finding's request: two ~100,000-line texts with no common lines through /api/diff."""
    before, after = _two_texts(100_000)
    t0 = time.perf_counter()
    out = explain_diff(before, after)
    elapsed = time.perf_counter() - t0
    assert elapsed < 20.0, f"100k x 100k lines took {elapsed:.1f}s"
    assert out["structured"]["lines_added"] == 100_000
    assert out["structured"]["approximate"] is True
    assert "approximate" in out["warning"]
    assert len(out["raw_diff"]) <= 16_000
    assert len(ConfigDiff(before=before, after=after).changed_lines()) == 200_000


def test_text_diff_above_the_line_cap_is_bounded():
    before, after = _two_texts(diff_mod.MAX_DIFF_LINES + 1)
    t0 = time.perf_counter()
    out = text_diff(before, after)
    assert time.perf_counter() - t0 < 5.0
    assert "approximate" in out.splitlines()[0]


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_diff_results_below_the_caps_are_unchanged(seed):
    rng = random.Random(seed)
    pool = ["!", " exit", "interface Ethernet{n}", " mtu {n}", "router bgp 650{n}", " neighbor 192.0.2.{n}",
            "vlan {n}", " description uplink-{n}", "ntp server 198.51.100.{n}", "no shutdown"]

    def cfg(n_lines: int) -> str:
        return "\n".join(rng.choice(pool).format(n=rng.randint(0, 9)) for _ in range(n_lines))

    for size in (30, 250, 400):   # >= 200 lines exercises SequenceMatcher's popular-line handling
        before = cfg(size)
        after = "\n".join(rng.choice([line, line, line, rng.choice(pool).format(n=rng.randint(0, 9))])
                          for line in before.split("\n"))
        got = structured_diff(before, after)
        adds, dels = _old_structured(before, after)
        assert got["lines_added"] == len(adds) and got["lines_removed"] == len(dels)
        assert got["sample_additions"] == adds[:10] and got["sample_removals"] == dels[:10]
        assert "approximate" not in got
        assert "warning" not in explain_diff(before, after)
        assert ConfigDiff(before=before, after=after).changed_lines() == _old_changes(before, after)
