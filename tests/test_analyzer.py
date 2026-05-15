"""Tests for the analyzer pipeline (action items, health, summary, optimize)."""
from unittest.mock import patch

import pytest

from ai_log_analyzer import llm
from ai_log_analyzer.analyzer import (
    AnalysisResult,
    analyze,
    build_action_items,
    deep_analyze,
    health_score,
    optimize_config,
)
from ai_log_analyzer.classifier import LogEvent, classify_events


@pytest.fixture(autouse=True)
def disable_llm():
    """Force LLM off for every test so behavior is deterministic."""
    prior = llm.get_state()["enabled"]
    llm.set_enabled(False)
    yield
    llm.set_enabled(bool(prior))


@pytest.mark.unit
def test_health_score_perfect_when_no_events():
    score, grade, label = health_score({"critical": 0, "high": 0, "medium": 0})
    assert score == 100 and grade == "A" and label == "Healthy"


@pytest.mark.unit
def test_health_score_critical_drops_grade():
    score, grade, _ = health_score({"critical": 8, "high": 0, "medium": 0})
    assert score == 60 and grade == "C"


@pytest.mark.unit
def test_health_score_capped_at_zero():
    score, grade, _ = health_score(
        {"critical": 1000, "high": 1000, "medium": 1000}, external_alerts=1000,
    )
    assert score == 0 and grade == "F"


@pytest.mark.unit
def test_build_action_items_dedupes_by_severity_and_description():
    classified, _, _ = classify_events([
        LogEvent("", "h1", "rpd", "err", "bgp peer 10.0.0.1 down"),
        LogEvent("", "h2", "rpd", "err", "bgp peer 10.0.0.2 down"),
        LogEvent("", "h1", "rpd", "err", "bgp peer 10.0.0.3 down"),
    ])
    items = build_action_items(classified, llm_top_n=0)
    assert len(items) == 1
    item = items[0]
    assert item.count == 3
    assert sorted(item.devices) == ["h1", "h2"]


@pytest.mark.unit
def test_build_action_items_skips_low_and_info():
    classified, _, _ = classify_events([
        LogEvent("", "h1", "sshd", "info", "accepted publickey for user"),
    ])
    assert build_action_items(classified, llm_top_n=0) == []


@pytest.mark.unit
def test_deep_analyze_returns_phased_structure():
    result = deep_analyze(
        category="routing",
        description="BGP peer down / connect failure",
        devices=["rt-01"],
        count=42,
        sample_messages=["bgp 10.0.0.1 down"],
        skip_llm=True,
    )
    assert result["llm_powered"] is False
    assert isinstance(result["phases"], list) and len(result["phases"]) == 5
    phase_names = [p["name"] for p in result["phases"]]
    assert phase_names == ["Diagnose", "Mitigate", "Remediate", "Verify", "Optimize"]


@pytest.mark.unit
def test_deep_analyze_optimize_phase_has_actions():
    result = deep_analyze(
        category="routing", description="BGP peer down / connect failure",
        devices=["rt-01"], count=10, sample_messages=[], skip_llm=True,
    )
    optimize = next(p for p in result["phases"] if p["name"] == "Optimize")
    assert len(optimize["actions"]) > 0


@pytest.mark.unit
def test_deep_analyze_preventive_config_populated():
    result = deep_analyze(
        category="routing", description="BGP peer down",
        devices=["rt-01"], count=10, sample_messages=[], skip_llm=True,
    )
    assert isinstance(result["preventive_config"], list)
    assert len(result["preventive_config"]) > 0


@pytest.mark.unit
def test_deep_analyze_each_action_has_cli_dict():
    result = deep_analyze(
        category="interface", description="Interface link down",
        devices=["sw-01"], count=5, sample_messages=[], skip_llm=True,
    )
    for phase in result["phases"]:
        for action in phase["actions"]:
            assert isinstance(action["cli"], dict)


@pytest.mark.unit
def test_analyze_end_to_end_produces_full_result():
    events = [
        LogEvent("2026-05-09T10:00:00", "rt-01", "rpd", "err", "bgp peer 10.0.0.1 down"),
        LogEvent("2026-05-09T10:01:00", "rt-01", "kernel", "crit", "kernel panic - not syncing"),
    ]
    result = analyze(events, use_llm=False)
    assert isinstance(result, AnalysisResult)
    assert result.severity_counts["critical"] == 1
    assert result.severity_counts["high"] == 1
    assert len(result.action_items) >= 1
    # Each action item has phased deep analysis
    for item in result.action_items:
        assert "phases" in item.deep_analysis
        assert len(item.deep_analysis["phases"]) == 5


@pytest.mark.unit
def test_analyze_empty_input_safe():
    result = analyze([], use_llm=False)
    assert result.score == 100 and result.grade == "A"
    assert result.action_items == []


@pytest.mark.unit
def test_optimize_config_returns_unavailable_when_llm_disabled():
    # LLM is force-disabled by the fixture
    out = optimize_config(
        hostname="rt-01", platform="frr",
        running_config="router bgp 65001\n neighbor 1.1.1.1 remote-as 65002\n",
    )
    assert out["llm_powered"] is False
    assert out["findings"] == []


@pytest.mark.unit
def test_optimize_config_with_mocked_llm_parses_json():
    fake_json = (
        '{"summary":"good","findings":[{"severity":"high","title":"missing BFD",'
        '"category":"convergence","evidence":"no bfd line",'
        '"rationale":"slower failover","patch":["neighbor x bfd"],'
        '"verify_cli":["show bfd peer"]}],'
        '"monitoring_gaps":["bgp keepalive"],"score":72}'
    )
    llm.set_enabled(True)
    with patch.object(llm, "query", return_value=fake_json):
        out = optimize_config(
            hostname="rt-01", platform="frr",
            running_config="router bgp 65001\n",
        )
    assert out["llm_powered"]
    assert out["score"] == 72
    assert len(out["findings"]) == 1
    assert out["findings"][0]["title"] == "missing BFD"


@pytest.mark.unit
def test_optimize_config_handles_non_json_llm_response():
    llm.set_enabled(True)
    with patch.object(llm, "query", return_value="This config looks fine, no issues."):
        out = optimize_config(
            hostname="rt-01", platform="frr",
            running_config="router bgp 65001\n",
        )
    assert out["llm_powered"]
    assert out["findings"] == []
    assert "raw" in out
