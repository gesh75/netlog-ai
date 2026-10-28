"""Deep-report topology inference is bounded: hosts x messages used to be quadratic in the input."""
from __future__ import annotations

import random
import time

import pytest

from ai_log_analyzer import analytics, deep_report

pytestmark = pytest.mark.unit


def _old_infer_topology(rows):
    hosts, messages = [], []
    for device, message, _stamp in analytics._iter_rows(rows):
        if device and device not in hosts:
            hosts.append(device)
        messages.append((device, message))
    edges, seen = [], set()
    for device, message in messages:
        for other in hosts:
            if not device or other == device or other not in message:
                continue
            pair = tuple(sorted((device, other)))
            if pair not in seen:
                seen.add(pair)
                edges.append((device, other))
    return {"nodes": [{"id": host} for host in hosts], "edges": edges}


def test_infer_topology_is_bounded_for_unique_hostnames():
    n = 6_000
    rows = [f"Jan  1 00:00:00 host{i:06d} x" for i in range(n)]
    t0 = time.perf_counter()
    graph = deep_report._infer_topology(rows)
    elapsed = time.perf_counter() - t0
    assert elapsed < 2.0, f"{n} unique hosts took {elapsed:.1f}s"
    assert len(graph["nodes"]) < n
    assert graph["truncated"]["hosts_dropped"] == n - len(graph["nodes"])


def test_infer_topology_results_are_unchanged_below_the_caps():
    rng = random.Random(5)
    hosts = [f"leaf{i}" for i in range(1, 25)] + ["spine1", "spine2", "r1", "r10"]
    rows = []
    for _ in range(500):
        src = rng.choice(hosts)
        mention = " ".join(rng.sample(hosts, rng.randint(0, 3)))
        rows.append(f"Jan  1 00:00:{rng.randint(0, 59):02d} {src} bgp neighbor {mention} down")
    rows += ["not a syslog line", "", "Jan  1 00:00:00 solo x"]
    new = deep_report._infer_topology(rows)
    assert new == _old_infer_topology(rows)
    assert "truncated" not in new


def test_deep_report_says_when_topology_inference_was_bounded():
    log_text = "\n".join(f"Jan  1 00:00:00 host{i:06d} link down" for i in range(5_000))
    bundle = deep_report.run_deep_report(log_text=log_text)
    assert bundle.payload["truncated"]["topology"]["hosts_dropped"] > 0
    small = deep_report.run_deep_report(log_text="Jan  1 00:00:00 a link down\nJan  1 00:00:01 b link down")
    assert "truncated" not in small.payload
