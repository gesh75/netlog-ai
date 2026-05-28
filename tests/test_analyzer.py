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


# ── Executive summary hostname anchoring (LOGS tab) ───────────────────────

@pytest.mark.unit
def test_scrub_placeholders_replaces_generic_when_no_real_host():
    """Bullets with only placeholders (R1, SW2) get [hostname?] substituted."""
    from ai_log_analyzer.analyzer import _scrub_placeholders
    bullet = "BGP peer down on R1 and SW2"
    out = _scrub_placeholders(bullet, ["leaf1", "spine2"])
    assert "R1" not in out
    assert "SW2" not in out
    assert "[hostname?]" in out


@pytest.mark.unit
def test_scrub_placeholders_keeps_bullet_when_real_host_present():
    """If the bullet also names a real host, leave it alone — operator can still read it."""
    from ai_log_analyzer.analyzer import _scrub_placeholders
    bullet = "BGP peer down on leaf1 (also called R1 by docs)"
    out = _scrub_placeholders(bullet, ["leaf1", "spine2"])
    assert out == bullet  # untouched


@pytest.mark.unit
def test_scrub_placeholders_passthrough_when_no_placeholders():
    from ai_log_analyzer.analyzer import _scrub_placeholders
    bullet = "BGP peer down on leaf1 and spine2"
    assert _scrub_placeholders(bullet, ["leaf1", "spine2"]) == bullet


@pytest.mark.unit
def test_executive_summary_llm_prompt_anchors_hostnames(monkeypatch):
    """The LLM call must receive an ALLOWED_HOSTNAMES line and real device names."""
    from ai_log_analyzer import analyzer, llm
    from ai_log_analyzer.analyzer import ActionItem, _executive_summary

    captured = {}

    def fake_query(system: str, user: str, max_tokens: int = 400) -> str:
        captured["system"] = system
        captured["user"] = user
        return "• BGP down on leaf1\n• Memory pressure on spine2"

    llm.set_enabled(True)
    monkeypatch.setattr(llm, "query", fake_query)
    items = [
        ActionItem(severity="high", category="routing",
                   description="BGP peer down", count=3,
                   devices=["leaf1", "leaf4"], sample_messages=[]),
        ActionItem(severity="critical", category="system",
                   description="OOM kill", count=2,
                   devices=["spine2"], sample_messages=[]),
    ]
    bullets, used_llm = _executive_summary(
        sev_counts={"critical": 2, "high": 3, "medium": 0},
        cat_counts={"routing": 3, "system": 2},
        score=24, grade="F", grade_label="Critical",
        items=items, use_llm=True,
    )
    assert used_llm
    # Prompt anchoring
    assert "HOSTNAME ANCHORING" in captured["system"]
    assert "ALLOWED_HOSTNAMES" in captured["user"]
    # Real hostnames passed through (not collapsed to counts)
    assert "leaf1" in captured["user"]
    assert "leaf4" in captured["user"]
    assert "spine2" in captured["user"]


@pytest.mark.unit
def test_executive_summary_scrubs_placeholders_in_llm_output(monkeypatch):
    """LLM that still emits R1/SW2 → bullet gets [hostname?] substitution."""
    from ai_log_analyzer import llm
    from ai_log_analyzer.analyzer import ActionItem, _executive_summary

    monkeypatch.setattr(
        llm, "query",
        lambda s, u, max_tokens=400: "• BGP peer down on R1 to R3\n• OOM event on SW2",
    )
    llm.set_enabled(True)
    items = [
        ActionItem(severity="high", category="routing",
                   description="BGP peer down", count=3,
                   devices=["leaf1"], sample_messages=[]),
    ]
    bullets, used_llm = _executive_summary(
        sev_counts={"critical": 0, "high": 3, "medium": 0},
        cat_counts={"routing": 3},
        score=70, grade="C", grade_label="Degraded",
        items=items, use_llm=True,
    )
    assert used_llm
    joined = " ".join(bullets)
    # R1, R3, SW2 all stripped
    assert " R1" not in joined and "R3" not in joined and "SW2" not in joined
    assert "[hostname?]" in joined
