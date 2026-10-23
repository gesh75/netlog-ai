"""Flap dynamics and EVPN causal timestamps take their year from the batch;
articulation points survive long chains."""
from __future__ import annotations

from datetime import datetime

import pytest

from ai_log_analyzer import analytics, causal
from ai_log_analyzer.evpn_causal import EVPNBipartiteCausalEngine

pytestmark = pytest.mark.unit


def _row(stamp: str, state: str, device: str = "sw1") -> dict:
    return {"device": device, "message": f"Ethernet1 link {state}", "timestamp": stamp}


def test_yearless_stamps_take_the_year_of_the_dated_events_in_the_batch():
    report = analytics.analyze_flap_dynamics([_row("2025-06-10T10:00:00Z", "down"), _row("Jun 10 10:00:05", "up")])
    (entity,) = report.entities
    assert entity.intervals_sec == [5.0]


def test_year_rollover_between_yearless_stamps_stays_chronological():
    report = analytics.analyze_flap_dynamics([_row("2026-12-31T23:59:50Z", "down"), _row("Jan  1 00:00:05", "up")])
    (entity,) = report.entities
    assert entity.intervals_sec == [15.0]


def test_untimed_events_are_not_read_as_a_flap_storm():
    events = [_row("", "down" if i % 2 == 0 else "up") for i in range(12)]
    report = analytics.analyze_flap_dynamics(events)
    (entity,) = report.entities
    assert entity.state != "DAMPENED_STORM" and report.dampened_count == 0


def test_rapid_timed_flaps_are_still_a_storm():
    events = [_row(f"2026-10-20T10:00:{i:02d}Z", "down" if i % 2 == 0 else "up") for i in range(12)]
    assert analytics.analyze_flap_dynamics(events).dampened_count == 1


def test_articulation_points_on_a_chain_longer_than_the_recursion_limit():
    n = 3000
    adj = {f"n{i:04d}": set() for i in range(n)}
    for i in range(n - 1):
        adj[f"n{i:04d}"].add(f"n{i + 1:04d}")
        adj[f"n{i + 1:04d}"].add(f"n{i:04d}")
    cuts = analytics._articulation_points(adj)
    assert cuts == {f"n{i:04d}" for i in range(1, n - 1)}


def test_articulation_points_small_graph_matches_the_known_answer():
    # triangle a-b-c with a tail c-d-e: c and d are cut vertices
    edges = [("a", "b"), ("b", "c"), ("a", "c"), ("c", "d"), ("d", "e")]
    adj: dict[str, set[str]] = {}
    for u, v in edges:
        adj.setdefault(u, set()).add(v)
        adj.setdefault(v, set()).add(u)
    assert analytics._articulation_points(adj) == {"c", "d"}


class _E:
    def __init__(self, ts: str, host: str, msg: str) -> None:
        self.timestamp, self.hostname, self.message = ts, host, msg


def test_evpn_rfc3164_year_comes_from_the_batch_then_from_now(monkeypatch):
    engine = EVPNBipartiteCausalEngine()
    dated = engine.ingest([_E("2025-06-10T10:00:00Z", "leaf1", "Interface Ethernet1 link down"),
                           _E("Jun 10 10:00:05", "leaf1", "Interface Ethernet2 link down")])
    assert [e.timestamp.year for e in dated] == [2025, 2025]
    monkeypatch.setattr(causal, "_now", lambda: datetime(2031, 3, 1, 12, 0, 0))
    undated = engine.ingest([_E("Feb 20 10:00:05", "leaf1", "Interface Ethernet2 link down")])
    assert undated[0].timestamp.year == 2031
