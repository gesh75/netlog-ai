"""Yearless RFC 3164 stamps: 29 Feb in a common year and New Year clock skew."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ai_log_analyzer.parsers import timeutil
from ai_log_analyzer.parsers.timeutil import normalize_ts

pytestmark = pytest.mark.unit


def _at(monkeypatch, *args):
    monkeypatch.setattr(timeutil, "_now", lambda: datetime(*args, tzinfo=timezone.utc))


@pytest.mark.parametrize("now,stamp,expected", [
    # device 7 s ahead of us at New Year's Eve: the coming year, not last year
    ((2026, 12, 31, 23, 59, 55), "Jan  1 00:00:02", "2027-01-01T00:00:02Z"),
    ((2026, 12, 31, 23, 30, 0), "Jan 1 00:10:00", "2027-01-01T00:10:00Z"),
    # device a few seconds behind just after midnight: still last year
    ((2027, 1, 1, 0, 0, 3), "Dec 31 23:59:56", "2026-12-31T23:59:56Z"),
    # ordinary placement is unchanged
    ((2026, 10, 22, 10, 20, 0), "Oct 22 10:15:01", "2026-10-22T10:15:01Z"),
    ((2026, 10, 22, 10, 20, 0), "Dec 31 23:00:00", "2025-12-31T23:00:00Z"),
    ((2026, 12, 30, 12, 0, 0), "Jan  1 00:00:02", "2026-01-01T00:00:02Z"),   # a year-old replay
])
def test_yearless_rollover(monkeypatch, now, stamp, expected):
    _at(monkeypatch, *now)
    assert normalize_ts(stamp) == (expected, True)


@pytest.mark.parametrize("now,expected", [
    ((2026, 10, 22, 10, 0, 0), "2024-02-29T12:00:00Z"),   # common year: nearest earlier leap year
    ((2028, 3, 5, 10, 0, 0), "2028-02-29T12:00:00Z"),      # leap year: this year
    ((2028, 2, 29, 11, 0, 0), "2028-02-29T12:00:00Z"),     # a little ahead on the day itself
])
def test_feb_29_is_dated_in_a_leap_year(monkeypatch, now, expected):
    _at(monkeypatch, *now)
    assert normalize_ts("Feb 29 12:00:00") == (expected, True)


def test_impossible_dates_stay_empty(monkeypatch):
    _at(monkeypatch, 2026, 10, 22, 10, 0, 0)
    assert normalize_ts("Feb 30 12:00:00") == ("", False)
    assert normalize_ts("Foo 1 12:00:00") == ("", False)
