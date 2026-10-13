"""Drain-style NetworkLogDeduplicator: flaps, BGP, masking, ratios."""
from __future__ import annotations

import hashlib

import pytest

from ai_log_analyzer.analyzer import analyze
from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.dedup import (
    DedupResult,
    NetworkLogDeduplicator,
    deduplicate_logs,
    is_dedup_enabled,
    reset_dedup_enabled,
    set_dedup_enabled,
)
from ai_log_analyzer.llm import prepare_log_samples


def _flap_burst() -> list[str]:
    return [
        "Oct 13 10:00:01 leaf1 kernel: Interface Ethernet1/1, changed state to down",
        "Oct 13 10:00:02 leaf1 kernel: Interface Ethernet1/1, changed state to down",
        "Oct 13 10:00:03 leaf1 kernel: Interface Ethernet2/1, changed state to down",
        "Oct 13 10:00:04 leaf2 kernel: Interface Ethernet1/1, changed state to down",
        "Oct 13 10:00:05 leaf2 kernel: Interface Ethernet3/1, changed state to down",
    ]


def _bgp_burst() -> list[str]:
    return [
        "Oct 13 10:00:01 spine1 rpd: BGP peer 10.0.0.1 reset (Hold Timer expired)",
        "Oct 13 10:00:02 spine1 rpd: BGP peer 10.0.0.2 reset (Hold Timer expired)",
        "Oct 13 10:00:03 spine2 rpd: BGP peer 192.0.2.1 reset (Hold Timer expired)",
        "Oct 13 10:00:04 spine2 rpd: BGP peer 192.0.2.8 reset (Hold Timer expired)",
    ]


@pytest.mark.unit
def test_interface_flaps_collapse_to_one_template():
    result = deduplicate_logs(_flap_burst())
    assert result.total_lines == 5
    assert result.unique_templates == 1
    cluster = result.clusters[0]
    assert cluster.count == 5
    assert "<INTF>" in cluster.template
    assert "Ethernet1/1" not in cluster.template
    assert cluster.hosts == {"leaf1", "leaf2"}
    assert cluster.variable_counts["INTF"]["Ethernet1/1"] == 3
    compact = cluster.to_compact_line()
    assert compact.startswith("[DEDUP x5 |")
    assert "INTF=" in compact
    assert "window=" in compact


@pytest.mark.unit
def test_bgp_resets_collapse_and_mask_ipv4():
    result = deduplicate_logs(_bgp_burst())
    assert result.unique_templates == 1
    cluster = result.clusters[0]
    assert cluster.count == 4
    assert "<IPV4>" in cluster.template
    assert "10.0.0.1" not in cluster.template
    assert cluster.variable_counts["IPV4"]["10.0.0.1"] == 1
    assert "IPV4=[10.0.0.1(1)" in cluster.to_compact_line() or "IPV4=[" in cluster.to_compact_line()
    assert cluster.hosts == {"spine1", "spine2"}


@pytest.mark.unit
def test_masks_ipv4_ipv6_mac_intf_asn():
    line = (
        "2026-10-13T10:00:01Z leaf1 rpd: peer 2001:db8:1:2:3:4:5:6 "
        "via Ethernet1/1 mac aa:bb:cc:dd:ee:ff "
        "backup 10.1.2.3/32 cisco aabb.ccdd.eeff dash aa-bb-cc-dd-ee-ff "
        "ge-0/0/1 xe-1/0/0 irb.10 lo0.0 Port-Channel10 AS65000 AS 65001"
    )
    result = deduplicate_logs([line])
    template = result.clusters[0].template
    assert "<IPV6>" in template
    assert "<IPV4>" in template
    assert "<MAC>" in template
    assert "<INTF>" in template
    assert "<ASN>" in template
    assert "2001:db8:1:2:3:4:5:6" not in template
    assert "10.1.2.3" not in template
    assert "aa:bb:cc:dd:ee:ff" not in template
    assert "Ethernet1/1" not in template
    assert "AS65000" not in template
    vars_ = result.clusters[0].variable_counts
    assert vars_["IPV6"]["2001:db8:1:2:3:4:5:6"] == 1
    assert vars_["IPV4"]["10.1.2.3/32"] == 1
    assert vars_["MAC"]["aa:bb:cc:dd:ee:ff"] == 1
    assert vars_["MAC"]["aabb.ccdd.eeff"] == 1
    assert vars_["MAC"]["aa-bb-cc-dd-ee-ff"] == 1
    assert vars_["INTF"]["Ethernet1/1"] == 1
    assert vars_["INTF"]["ge-0/0/1"] == 1
    assert vars_["ASN"]["AS65000"] == 1


@pytest.mark.unit
def test_pid_placeholder_value_not_recorded():
    result = deduplicate_logs([
        "Oct 13 10:00:01 rt1 rpd[4321]: BGP peer 10.0.0.1 reset",
        "Oct 13 10:00:02 rt1 rpd[9999]: BGP peer 10.0.0.2 reset",
    ])
    template = result.clusters[0].template
    assert "[<PID>]" in template
    assert "4321" not in template
    assert "PID" not in result.clusters[0].variable_counts


@pytest.mark.unit
def test_hex_and_num_masked():
    result = deduplicate_logs([
        "Oct 13 10:00:01 sw1 kernel: asic error 0xDEAD retry 3",
        "Oct 13 10:00:02 sw1 kernel: asic error 0xBEEF retry 9",
    ])
    template = result.clusters[0].template
    assert "<HEX>" in template
    assert "<NUM>" in template
    assert "0xDEAD" not in template


@pytest.mark.unit
def test_singleton_passthrough():
    raw = "Oct 13 10:00:01 leaf1 kernel: unique widget failure on box"
    result = deduplicate_logs([raw])
    assert result.unique_templates == 1
    assert result.clusters[0].count == 1
    assert result.clusters[0].to_compact_line() == raw
    assert result.format_for_llm() == raw


@pytest.mark.unit
def test_preserve_singletons_false_drops_uniques():
    lines = _bgp_burst() + ["Oct 13 11:00:00 leaf9 kernel: one-off noise"]
    result = deduplicate_logs(lines, preserve_singletons=False)
    assert result.total_lines == 5
    assert result.unique_templates == 2
    assert all(c.count > 1 for c in result.clusters)
    assert "one-off noise" not in result.format_for_llm()


@pytest.mark.unit
def test_reduction_ratios_floor_at_zero():
    burst = deduplicate_logs(_flap_burst())
    assert burst.line_reduction_ratio == pytest.approx(0.8)
    assert burst.char_reduction_ratio > 0
    assert 0.0 <= burst.char_reduction_ratio <= 1.0

    singles = deduplicate_logs([
        "Oct 13 10:00:01 a kernel: alpha",
        "Oct 13 10:00:02 b kernel: bravo",
    ])
    assert singles.line_reduction_ratio == 0.0
    assert singles.char_reduction_ratio == 0.0

    empty = DedupResult(clusters=[], total_lines=0, unique_templates=0, raw_chars=0, compressed_chars=10)
    assert empty.line_reduction_ratio == 0.0
    assert empty.char_reduction_ratio == 0.0


@pytest.mark.unit
def test_format_for_llm_joins_compact_lines():
    result = deduplicate_logs(_flap_burst() + [
        "Oct 13 12:00:00 core1 kernel: unique widget failure",
    ])
    text = result.format_for_llm()
    assert "[DEDUP x5 |" in text
    assert "unique widget failure" in text
    assert text.count("\n") == 1


@pytest.mark.unit
def test_cluster_id_is_sha1_prefix_and_order_is_first_seen():
    lines = [
        "Oct 13 10:00:01 a kernel: unique-aaa",
        "Oct 13 10:00:02 b kernel: Interface Ethernet1, changed state to down",
        "Oct 13 10:00:03 c kernel: unique-ccc",
        "Oct 13 10:00:04 d kernel: Interface Ethernet2, changed state to down",
    ]
    result = deduplicate_logs(lines)
    assert [c.sample_raw for c in result.clusters][:2] == lines[:2]
    first = result.clusters[0]
    assert first.cluster_id == hashlib.sha1(first.template.encode("utf-8")).hexdigest()[:10]
    assert len(first.cluster_id) == 10


@pytest.mark.unit
def test_skips_blank_lines_and_accepts_string_input():
    blob = "\n\n" + "\n".join(_bgp_burst()) + "\n   \n"
    result = NetworkLogDeduplicator().deduplicate(blob)
    assert result.total_lines == 4
    assert result.unique_templates == 1


@pytest.mark.unit
def test_hosts_overflow_suffix():
    lines = [
        f"Oct 13 10:00:0{i} leaf{i} kernel: Interface Ethernet1, changed state to down"
        for i in range(1, 6)
    ]
    compact = deduplicate_logs(lines).clusters[0].to_compact_line()
    assert "(+2_more)" in compact


@pytest.mark.unit
def test_deduplicate_logs_is_wrapper():
    a = deduplicate_logs(_bgp_burst())
    b = NetworkLogDeduplicator().deduplicate(_bgp_burst())
    assert a.unique_templates == b.unique_templates
    assert a.clusters[0].cluster_id == b.clusters[0].cluster_id


@pytest.mark.unit
def test_analyze_default_keeps_burst_counts():
    events = [
        LogEvent("Oct 13 10:00:01", "spine1", "rpd", "err",
                 "bgp peer 10.0.0.1 down hold timer expired")
        for _ in range(8)
    ]
    result = analyze(events, use_llm=False)
    assert result.severity_counts["high"] == 8
    assert result.netbox == {}


@pytest.mark.unit
def test_analyze_dedup_flag_compresses_before_classify():
    events = [
        LogEvent("Oct 13 10:00:01", "spine1", "rpd", "err",
                 "bgp peer 10.0.0.1 down hold timer expired")
        for _ in range(8)
    ]
    result = analyze(events, use_llm=False, dedup=True)
    assert result.severity_counts["high"] == 1


@pytest.mark.unit
def test_prepare_log_samples_passthrough_by_default():
    assert prepare_log_samples(["a", "b"]) == "  - a\n  - b"
    assert prepare_log_samples([]) == "  (no samples)"


@pytest.mark.unit
def test_prepare_log_samples_compresses_when_dedup_on():
    token = set_dedup_enabled(True)
    try:
        assert is_dedup_enabled() is True
        text = prepare_log_samples(_bgp_burst())
        assert "DEDUP" in text
        assert "<IPV4>" in text
    finally:
        reset_dedup_enabled(token)
    assert is_dedup_enabled() is False
