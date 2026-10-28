"""One crafted upload must not pin an API worker in the EVPN causal engine.

``EVPNBipartiteCausalEngine.analyze`` compared every event with every later one, and the per-host
config reserve that feeds it grew with the number of distinct hostnames. Both are now bounded, a capped
answer says so, and results below the caps are unchanged.
"""
from __future__ import annotations

import random
import time
from datetime import datetime, timedelta, timezone

import pytest

from ai_log_analyzer import evpn_causal
from ai_log_analyzer.analyzer import _aggregate_stream, analyze
from ai_log_analyzer.causal import evpn_causal_hypotheses
from ai_log_analyzer.classifier import LogEvent, iter_classify
from ai_log_analyzer.evpn_causal import (
    CausalHypothesis,
    EVPNBipartiteCausalEngine,
    FabricEvent,
    ProtocolLayer,
    fabric_event_from_raw,
)

pytestmark = pytest.mark.unit

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
FLOOD_LINE = "UI_CMDLINE_READ_LINE: OPTICAL_PWR_LOW"


def _flood(n: int) -> list[FabricEvent]:
    """n single-layer L1 events, one per distinct host, all inside one propagation window."""
    return [fabric_event_from_raw(FLOOD_LINE, timestamp=T0.isoformat(), device=f"h{i}") for i in range(n)]


def test_evpn_engine_caps_events_and_reports_what_it_dropped():
    n = 6_000
    engine = EVPNBipartiteCausalEngine()
    t0 = time.perf_counter()
    hyps = engine.analyze(_flood(n))
    elapsed = time.perf_counter() - t0
    assert len(hyps) < n, f"{len(hyps)} hypotheses for {n} events: the input was not capped"
    assert elapsed < 3.0, f"{n} events took {elapsed:.1f}s"
    assert engine.dropped_events == n - len(hyps)
    assert len(hyps) == evpn_causal.MAX_FABRIC_EVENTS


class _Counting(FabricEvent):
    """Counts how often the scan looks at an event."""

    reads = 0

    def __getattribute__(self, name):
        if name == "event_id":
            _Counting.reads += 1
        return super().__getattribute__(name)


def test_evpn_scan_stops_at_the_first_event_past_the_window():
    n = 600
    events = []
    for i in range(n):   # one event every 300 s: nothing falls inside the 120 s window
        ev = fabric_event_from_raw(
            "OPTICAL_PWR_LOW", timestamp=(T0 + timedelta(seconds=300 * i)).isoformat(), device=f"h{i}")
        events.append(_Counting(**{f: getattr(ev, f) for f in ev.__dataclass_fields__}))
    _Counting.reads = 0
    hyps = EVPNBipartiteCausalEngine().analyze(events)
    assert len(hyps) == n
    assert _Counting.reads < 20 * n, f"{_Counting.reads} event reads for {n} events: scan did not stop"


def _reference_analyze(engine: EVPNBipartiteCausalEngine, events: list[FabricEvent]) -> list[CausalHypothesis]:
    """The pre-fix analyze() loop: every later event is examined, out-of-window ones just skipped."""
    fabric = [e for e in engine.ingest(events) if e.layer != ProtocolLayer.UNKNOWN]
    ordered = sorted(fabric, key=lambda e: (e.timestamp, int(e.layer)))
    claimed: set[str] = set()
    out: list[CausalHypothesis] = []
    for idx, cand in enumerate(ordered):
        if cand.event_id in claimed:
            continue
        symptoms: list[FabricEvent] = []
        devs = {cand.device}
        vnis = {cand.vni} if cand.vni else set()
        for later in ordered[idx + 1:]:
            if later.event_id in claimed:
                continue
            delta = (later.timestamp - cand.timestamp).total_seconds()
            if delta < 0 or delta > engine.max_window:
                continue
            higher = later.layer > cand.layer
            peer = (later.layer == cand.layer and later.device in engine.adjacency_map.get(cand.device, set())
                    and delta <= 5.0)
            if (higher or peer) and engine._is_topologically_coupled(cand.device, later.device, later.layer):
                symptoms.append(later)
                claimed.add(later.event_id)
                devs.add(later.device)
                if later.vni:
                    vnis.add(later.vni)
        out.append(CausalHypothesis(root_cause=cand, suppressed_symptoms=symptoms, affected_devices=devs,
                                    affected_vnis=vnis))
    return out


_MESSAGES = (
    "LINEPROTO-5-UPDOWN: Interface Ethernet1/1 changed state to down",
    "OPTICAL_PWR_LOW on Ethernet2",
    "LACP: Port-Channel10 member suspended",
    "BFD session to neighbor 10.0.0.2 Down",
    "VXLAN_TUNNEL_DOWN: VTEP unreachable VNI 10010",
    "BGP-EVPN: Type-2 route withdraw VNI 10020",
    "unrelated chatter",
)


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_evpn_results_below_the_cap_are_unchanged(seed):
    rng = random.Random(seed)
    devices = [f"d{i}" for i in range(8)]
    adjacency = {d: {devices[(i + 1) % 8], devices[(i - 1) % 8]} for i, d in enumerate(devices)}
    events = [   # the index keeps every event_id unique, so hypotheses can be matched by root
        fabric_event_from_raw(f"{rng.choice(_MESSAGES)} #{i}", device=rng.choice(devices),
                              timestamp=(T0 + timedelta(seconds=rng.randint(0, 900))).isoformat())
        for i in range(400)
    ]
    for adj in (None, adjacency):
        engine = EVPNBipartiteCausalEngine(adj)
        new = engine.analyze(events)
        old = _reference_analyze(EVPNBipartiteCausalEngine(adj), events)
        assert engine.dropped_events == 0
        assert new and len(new) == len(old)
        by_root = {h.root_cause.event_id: h for h in new}
        for ref in old:
            got = by_root[ref.root_cause.event_id]
            assert [s.event_id for s in got.suppressed_symptoms] == [s.event_id for s in ref.suppressed_symptoms]
            assert got.affected_devices == ref.affected_devices
            assert got.affected_vnis == ref.affected_vnis


def test_evpn_payload_says_when_events_were_dropped_and_is_unchanged_otherwise():
    small = evpn_causal_hypotheses(_flood(50))
    assert set(small) == {"enabled", "hypotheses", "cytoscape_elements"}   # no new keys below the cap
    n = 2_500
    big = evpn_causal_hypotheses(_flood(n))
    assert big.get("truncated") is True
    assert big["dropped"] > 0
    assert len(big["hypotheses"]) + big["dropped"] == n
    assert "dropped" in big["warning"]


def test_config_reserve_has_a_fixed_bound_however_many_hosts_commit():
    def synth(n):
        for i in range(n):
            yield LogEvent(
                timestamp=f"2026-01-01T{(i // 3600) % 24:02d}:{(i // 60) % 60:02d}:{i % 60:02d}",
                hostname=f"h{i:05d}", appname="mgd", severity_raw="info", message="commit complete confirmed")

    hosts = 3_000
    *_head, config_events = _aggregate_stream(iter_classify(synth(hosts)))
    assert len(config_events) <= 1_100, f"{len(config_events)} reserved config events for {hosts} hosts"
    names = {e.hostname for e in config_events}
    assert "h00000" in names   # the earliest commit host is what change_window names: it must survive
    res = analyze(synth(hosts), use_llm=False)
    assert res.change_window["devices"][0] == "h00000"
    assert res.change_window.get("truncated") is True
    assert res.change_window["dropped_hosts"] > 0


def test_flood_of_config_hosts_gives_bounded_evpn_input():
    """The finding's request: every host sends one config-category line that is also an L1 event."""
    events = [
        LogEvent(timestamp=f"2026-01-01T{(i // 3600) % 24:02d}:{(i // 60) % 60:02d}:{i % 60:02d}",
                 hostname=f"h{i:05d}", appname="mgd", severity_raw="info", message=FLOOD_LINE)
        for i in range(5_000)
    ]
    res = analyze(iter(events), use_llm=False, evpn_causal=True)
    assert len(res.evpn_causal["hypotheses"]) <= 1_500
