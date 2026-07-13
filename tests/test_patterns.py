"""Tests for the unknown-pattern template miner (patterns.py)."""
from __future__ import annotations

import pytest

from ai_log_analyzer.patterns import TemplateMiner, mask_message


pytestmark = pytest.mark.unit


# ── masking ──────────────────────────────────────────────────────────────────

def test_mask_ipv4_and_numbers():
    assert mask_message("peer 10.0.0.1 reset after 42 tries") == "peer <ip> reset after <n> tries"


def test_mask_ip_with_port_and_prefix():
    assert mask_message("connect 192.168.1.1:179 failed") == "connect <ip> failed"
    assert mask_message("route 10.20.0.0/16 withdrawn") == "route <ip> withdrawn"


def test_mask_mac_and_hex():
    assert mask_message("mac aa:bb:cc:dd:ee:ff moved") == "mac <mac> moved"
    assert mask_message("addr 0xdeadbeef fault") == "addr <hex> fault"


def test_mask_interfaces():
    assert mask_message("ge-0/0/1 flapped") == "<if> flapped"
    assert mask_message("Ethernet49/1 errdisabled") == "<if> errdisabled"


def test_mask_preserves_words():
    assert mask_message("kernel module loaded") == "kernel module loaded"


# ── clustering ───────────────────────────────────────────────────────────────

def test_same_shape_clusters_together():
    m = TemplateMiner()
    for i in range(50):
        m.add(f"session {i} torn down for peer 10.0.0.{i % 9}", hostname=f"h{i % 3}")
    assert m.cluster_count == 1
    top = m.top(1)[0]
    assert top.count == 50
    assert top.template == "session <n> torn down for peer <ip>"
    assert len(top.hosts) == 3


def test_different_shapes_stay_separate():
    m = TemplateMiner()
    m.add("power rail B undervoltage detected")
    m.add("optical transceiver removed from slot 3")
    assert m.cluster_count == 2


def test_similar_shapes_merge_with_wildcard():
    m = TemplateMiner(sim_threshold=0.55)
    m.add("service restart requested by operator alice")
    m.add("service restart requested by operator bob")
    assert m.cluster_count == 1
    assert m.top(1)[0].template == "service restart requested by operator <*>"


def test_errorish_hint_promoted():
    m = TemplateMiner()
    m.add("cache rebuild failed on shard 4")
    m.add("heartbeat received from controller")
    by_template = {c.template: c for c in m.top(10)}
    assert by_template["cache rebuild failed on shard <n>"].severity_hint == "warning"
    assert by_template["heartbeat received from controller"].severity_hint == "info"


def test_top_ranks_errorish_first():
    m = TemplateMiner()
    for _ in range(100):
        m.add("routine heartbeat tick")
    m.add("disk write failure on volume 2")
    top = m.top(2)
    assert "failure" in top[0].template  # errorish beats higher-volume benign


def test_lru_eviction_bounds_memory():
    m = TemplateMiner(max_clusters=10)
    for i in range(50):
        m.add(f"unique{i} shape{i} alpha beta gamma delta")
    assert m.cluster_count <= 10
    # groups index must not leak evicted ids
    live = set(m._clusters)
    for ids in m._groups.values():
        assert set(ids) <= live


def test_to_dict_shape():
    m = TemplateMiner()
    m.add("widget 7 exploded", hostname="r1")
    d = m.to_dict()
    assert d["total_unclassified"] == 1
    assert d["template_count"] == 1
    t = d["top_templates"][0]
    assert set(t) == {"template", "count", "hosts", "host_count", "sample", "severity_hint"}
    assert t["hosts"] == ["r1"]


# ── analyzer integration ─────────────────────────────────────────────────────

def test_analyze_surfaces_unknown_patterns():
    from ai_log_analyzer.analyzer import analyze
    from ai_log_analyzer.classifier import LogEvent

    events = [
        LogEvent(timestamp=f"2026-01-01T00:00:{i:02d}", hostname="r1",
                 appname="fooagent", severity_raw="info",
                 message=f"quantum flux capacitor recalibrated {i} times")
        for i in range(20)
    ]
    result = analyze(iter(events), use_llm=False)
    up = result.to_dict()["unknown_patterns"]
    assert up["total_unclassified"] == 20
    assert up["template_count"] == 1
    assert "<n>" in up["top_templates"][0]["template"]


def test_analyze_kb_matched_events_not_mined():
    from ai_log_analyzer.analyzer import analyze
    from ai_log_analyzer.classifier import LogEvent

    events = [
        LogEvent(timestamp="2026-01-01T00:00:00", hostname="r1",
                 appname="rpd", severity_raw="err",
                 message="bgp peer 10.0.0.1 down hold timer expired"),
    ]
    result = analyze(iter(events), use_llm=False)
    assert result.unknown_patterns["total_unclassified"] == 0
