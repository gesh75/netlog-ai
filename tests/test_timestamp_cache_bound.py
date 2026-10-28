"""Timestamp parse caches must not retain attacker-sized keys.

``normalize_ts`` and ``causal.event_time`` memoize per timestamp string (8192 slots each).
JSON/CEF/LEEF parsers keep any ISO-looking prefix verbatim, so one 64 KiB "timestamp" per slot
would pin ~500 MB. A stamp longer than any real one is parsed but never cached.
"""
from __future__ import annotations

from types import SimpleNamespace

from ai_log_analyzer import causal
from ai_log_analyzer.parsers import timeutil

_BIG = "2026-10-27T10:00:00" + "9" * 65_000


def test_normalize_ts_does_not_cache_oversized_stamps():
    timeutil._normalize_cached.cache_clear()
    for i in range(50):
        timeutil.normalize_ts(f"{_BIG}{i}")
    assert timeutil._normalize_cached.cache_info().currsize == 0


def test_normalize_ts_still_caches_real_stamps():
    timeutil._normalize_cached.cache_clear()
    for _ in range(3):
        out = timeutil.normalize_ts("2026-10-27T10:00:00Z")
    info = timeutil._normalize_cached.cache_info()
    assert out[0].startswith("2026-10-27T10:00:00")
    assert info.currsize == 1 and info.hits == 2


def test_event_time_does_not_cache_oversized_stamps():
    causal._parse_event_ts.cache_clear()
    for i in range(50):
        ev = SimpleNamespace(timestamp=f"{_BIG}{i}")
        causal.event_time(ev)
    assert causal._parse_event_ts.cache_info().currsize == 0


def test_event_time_still_caches_real_stamps():
    causal._parse_event_ts.cache_clear()
    ev = SimpleNamespace(timestamp="2026-10-27T10:00:00Z")
    first = causal.event_time(ev)
    again = causal.event_time(ev)
    assert first is not None and first == again
    assert causal._parse_event_ts.cache_info().currsize == 1
