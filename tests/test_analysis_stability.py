"""Stability tracking per entity and time-ordered buckets; template miner totals."""
from __future__ import annotations

import pytest

from ai_log_analyzer.classifier import ClassifiedEvent
from ai_log_analyzer.patterns import TemplateMiner
from ai_log_analyzer.stability import StabilityTracker

pytestmark = pytest.mark.unit


def _ev(ts: str, desc: str, iface: str = "", host: str = "sw1") -> ClassifiedEvent:
    down = "down" in desc
    return ClassifiedEvent(
        timestamp=ts, hostname=host, appname="x", severity="high" if down else "medium", severity_raw="",
        category="interface", description=desc, action="", message="m", event_type="interface_link",
        interface=iface, state="down" if down else "up")


def _device(tracker: StabilityTracker, host: str = "sw1") -> dict:
    return next(d for d in tracker.report()["devices"] if d["hostname"] == host)


def test_many_ports_each_going_down_and_up_once_are_not_one_flapping_port():
    tracker = StabilityTracker()
    for i in range(24):
        tracker.add(_ev(f"2026-10-20T10:{i:02d}:00", "Interface link down", f"et-0/0/{i}"))
        tracker.add(_ev(f"2026-10-20T10:{i:02d}:30", "Interface link up", f"et-0/0/{i}"))
    dev = _device(tracker)
    assert dev["flaps"] == 0 and dev["flapping_entity_id"] == ""


def test_one_port_flapping_is_still_counted_and_named():
    tracker = StabilityTracker()
    for i in range(5):
        tracker.add(_ev(f"2026-10-20T10:00:{i * 10:02d}", "Interface link down", "et-0/0/7"))
        tracker.add(_ev(f"2026-10-20T10:00:{i * 10 + 5:02d}", "Interface link up", "et-0/0/7"))
    tracker.add(_ev("2026-10-20T10:05:00", "Interface link down", "et-0/0/9"))   # one clean failure elsewhere
    dev = _device(tracker)
    assert dev["flaps"] == 4 and dev["flapping_entity"] == "interface"
    assert dev["flapping_entity_id"] == "et-0/0/7"


def test_events_without_an_entity_fall_back_to_the_class():
    tracker = StabilityTracker()
    for i in range(3):
        tracker.add(_ev(f"2026-10-20T10:00:{i * 10:02d}", "Interface link down"))
        tracker.add(_ev(f"2026-10-20T10:00:{i * 10 + 5:02d}", "Interface link up"))
    assert _device(tracker)["flaps"] == 2


def test_trend_follows_time_not_arrival_order_on_multi_file_input():
    tracker = StabilityTracker()
    late = [f"2026-10-20T10:{m:02d}:00" for m in range(5, 9)]
    early = [f"2026-10-20T10:{m:02d}:00" for m in range(1, 5)]
    for ts in late:                      # the later file is read first: quiet
        tracker.add(_ev(ts, "Interface link down", "e1"))
    for ts in early:                     # the earlier file is busy
        for _ in range(4):
            tracker.add(_ev(ts, "Interface link down", "e1"))
    assert _device(tracker)["trend"] == "falling"


def test_old_minutes_are_evicted_first_when_buckets_overflow():
    tracker = StabilityTracker()
    for m in range(600):
        tracker.add(_ev(f"2026-10-20T{m // 60 + 1:02d}:{m % 60:02d}:00", "Interface link down", "e1"))
    tracker.add(_ev("2026-10-20T00:00:00", "Interface link down", "e1"))   # older than everything kept
    st = tracker._devices["sw1"]
    assert len(st.buckets) == 512 and "2026-10-20T00:00" not in st.buckets
    assert "2026-10-20T10:59" in st.buckets


def test_template_miner_total_survives_lru_eviction():
    miner = TemplateMiner(max_clusters=20)
    for i in range(500):
        miner.add(f"zz{i}x alpha beta gamma", "h1")
    out = miner.to_dict()
    assert miner.cluster_count <= 20 and out["total_unclassified"] == 500
