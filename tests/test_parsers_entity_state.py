"""EntityStateTracker eviction is least-recently-updated and observable."""
from __future__ import annotations

import pytest

from ai_log_analyzer.entity_state import EntityStateTracker, summarize
from ai_log_analyzer.parsers import parse_line

pytestmark = pytest.mark.unit


def _bgp(host: str, peer: str, state: str = "Down", sec: int = 0):
    return parse_line(f"Oct 22 10:00:{sec:02d} {host} bgpd[1]: %ADJCHANGE: neighbor {peer} in vrf default {state}")


def test_eviction_is_lru_not_insertion_order():
    t = EntityStateTracker(max_entities=2)
    t.add(_bgp("r1", "10.0.0.1"), 0)      # oldest-inserted ...
    t.add(_bgp("r1", "10.0.0.2"), 1)
    t.add(_bgp("r1", "10.0.0.1", "Up", 5), 2)   # ... but touched again: now the most recent
    t.add(_bgp("r1", "10.0.0.3"), 3)      # forces one eviction
    peers = {k[2].split("|")[1] for k in t.report()}
    assert peers == {"10.0.0.1", "10.0.0.3"}
    assert t.dropped_entities == 1


def test_dropped_entities_is_surfaced():
    t = EntityStateTracker(max_entities=1)
    for i in range(3):
        t.add(_bgp("r1", f"10.0.0.{i + 1}"), i)
    assert t.status() == {"tracked": 1, "max_entities": 1, "dropped_entities": 2}
    summary = t.summary()
    assert summary["dropped_entities"] == 2 and summary["total"] == 1
    # unchanged shape when nothing was evicted
    assert "dropped_entities" not in summarize(t.report().values())
    assert "dropped_entities" not in EntityStateTracker().summary()
