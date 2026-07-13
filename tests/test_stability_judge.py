"""Tests for the fabric stability engine (stability.py) and the
LLM-as-Judge playbook scorer (judge.py) + its CLI command."""
from __future__ import annotations

import json

import pytest

from ai_log_analyzer import judge
from ai_log_analyzer.classifier import LogEvent, iter_classify
from ai_log_analyzer.stability import StabilityTracker


pytestmark = pytest.mark.unit


def _events(lines: list[tuple[str, str, str]]):
    """(timestamp, host, message) → classified events."""
    return iter_classify(
        LogEvent(timestamp=ts, hostname=h, appname="rpd", severity_raw="info", message=m)
        for ts, h, m in lines
    )


# ── stability: flap detection ────────────────────────────────────────────────

def test_flapping_interface_detected_and_scored():
    lines = []
    for i in range(6):  # 3 full down→up→down… cycles on r1
        state = "snmp_trap_link_down" if i % 2 == 0 else "snmp_trap_link_up"
        lines.append((f"Jan  1 00:0{i}:00", "r1", f"{state} ifIndex 501 ge-0/0/1"))
    lines.append(("Jan  1 00:07:00", "r2", "bgp peer 10.0.0.1 down hold timer"))

    tracker = StabilityTracker()
    for e in _events(lines):
        tracker.add(e)
    report = tracker.report()

    r1 = next(d for d in report["devices"] if d["hostname"] == "r1")
    assert r1["flaps"] >= 2
    assert r1["flapping_entity"] == "interface"
    r2 = next(d for d in report["devices"] if d["hostname"] == "r2")
    assert r2["flaps"] == 0          # one clean failure is not a flap
    assert r1["score"] < r2["score"]  # flapping is worse than one incident
    assert any("flapped" in r for r in report["recommendations"])


def test_stable_device_scores_high_low_risk():
    lines = [(f"Jan  1 00:00:{i:02d}", "sw-1", f"sshd session opened for user ops{i}")
             for i in range(10)]
    tracker = StabilityTracker()
    for e in _events(lines):
        tracker.add(e)
    d = tracker.report()["devices"][0]
    assert d["score"] >= 90
    assert d["risk_24h"] == "low"
    assert d["trend"] == "stable"


def test_rising_trend_and_risk_band():
    # Quiet early minutes, busy late minutes → rising trend.
    lines = [(f"Jan  1 00:0{m}:00", "core-1", "bgp peer 10.0.0.9 down hold timer")
             for m in (1, 2, 3, 4)]
    lines += [(f"Jan  1 00:0{m}:{s:02d}", "core-1", "bgp peer 10.0.0.9 down hold timer")
              for m in (5, 6) for s in range(0, 50, 10)]
    tracker = StabilityTracker()
    for e in _events(lines):
        tracker.add(e)
    d = tracker.report()["devices"][0]
    assert d["trend"] == "rising"
    assert d["risk_24h"] in ("medium", "high")


def test_empty_input_reports_perfect_fabric():
    report = StabilityTracker().report()
    assert report == {"fabric_score": 100, "device_count": 0,
                      "devices": [], "recommendations": []}


def test_analyze_carries_stability_section():
    from ai_log_analyzer.analyzer import analyze
    events = [LogEvent(timestamp="Jan  1 00:00:01", hostname="r1", appname="rpd",
                       severity_raw="err", message="bgp peer 10.0.0.1 down")]
    result = analyze(iter(events), use_llm=False)
    stab = result.to_dict()["stability"]
    assert stab["device_count"] == 1
    assert stab["devices"][0]["hostname"] == "r1"


# ── judge: heuristic scoring ─────────────────────────────────────────────────

GOOD_PLAYBOOK = {
    "root_cause": "BGP hold timer expired due to intermittent L1 errors on the peering link.",
    "risk": "Peer flaps withdraw 40k prefixes each cycle, causing reconvergence spikes.",
    "phases": [
        {"name": n, "goal": "g", "actions": [
            {"cli": {"junos": "show bgp summary", "eos": "show ip bgp summary"},
             "expected": "peer Established > 1h", "note": "check both ends"},
        ]} for n in ("Diagnose", "Mitigate", "Remediate", "Verify", "Optimize")
    ],
    "preventive_config": ["set protocols bgp group isp bfd-liveness-detection minimum-interval 300"],
    "monitoring": ["Alert when BGP session state != Established for > 30 seconds"],
    "timeline": "P2",
}

EMPTY_PLAYBOOK = {"root_cause": "", "risk": "", "phases": [], "preventive_config": [], "monitoring": []}


def test_good_playbook_outscores_empty():
    good = judge.judge_playbook(GOOD_PLAYBOOK, devices=["core-1"])
    bad = judge.judge_playbook(EMPTY_PLAYBOOK)
    assert good["scores"]["overall"] >= 7
    assert bad["scores"]["overall"] <= 3
    assert "missing root_cause" in " ".join(bad["notes"])


def test_disruptive_command_without_context_penalized():
    risky = dict(GOOD_PLAYBOOK)
    risky["phases"] = [{"name": "Mitigate", "goal": "g", "actions": [
        {"cli": {"junos": "request system reboot"}, "expected": "", "note": ""},
    ]}]
    v = judge.judge_playbook(risky, devices=["core-1"])
    assert v["scores"]["safety"] <= 7
    assert any("disruptive" in n for n in v["notes"])


def test_placeholder_names_hurt_grounding():
    hallucinated = dict(GOOD_PLAYBOOK)
    hallucinated["root_cause"] = "R1 and SW2 have mismatched timers"
    v = judge.judge_playbook(hallucinated, devices=["core-1"])
    grounded = judge.judge_playbook(GOOD_PLAYBOOK, devices=["core-1"])
    assert v["scores"]["grounding"] < grounded["scores"]["grounding"]


def test_judge_kb_self_test_scores_every_actionable_rule():
    report = judge.judge_kb()
    assert report["playbooks_scored"] > 20
    assert 0 < report["overall"] <= 10
    # every verdict has the full score set
    for v in report["verdicts"]:
        assert set(v["scores"]) == {"actionability", "safety", "grounding",
                                    "completeness", "overall"}


def test_judge_llm_blend_falls_back_when_llm_dead(monkeypatch):
    from ai_log_analyzer import llm
    monkeypatch.setattr(llm, "is_enabled", lambda: True)
    monkeypatch.setattr(llm, "query", lambda *a, **k: None)  # provider dead
    v = judge.judge(GOOD_PLAYBOOK, use_llm=True)
    assert v["judge"] == "heuristic"


def test_judge_llm_blend_merges_scores(monkeypatch):
    from ai_log_analyzer import llm
    monkeypatch.setattr(llm, "is_enabled", lambda: True)
    monkeypatch.setattr(llm, "query", lambda *a, **k: json.dumps(
        {"actionability": 10, "safety": 10, "grounding": 10, "completeness": 10}))
    v = judge.judge(EMPTY_PLAYBOOK, use_llm=True)
    assert v["judge"] == "heuristic+llm"
    heuristic_only = judge.judge_playbook(EMPTY_PLAYBOOK)
    assert v["scores"]["overall"] > heuristic_only["scores"]["overall"]


# ── eval CLI ─────────────────────────────────────────────────────────────────

def test_cli_eval_kb_self_test(capsys):
    from ai_log_analyzer.cli import main
    import sys as _sys
    argv = _sys.argv
    _sys.argv = ["ai-log-analyzer", "eval", "--json"]
    try:
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
    finally:
        _sys.argv = argv
    report = json.loads(capsys.readouterr().out)
    assert report["playbooks_scored"] > 20


def test_cli_eval_min_score_gate(tmp_path, capsys):
    from ai_log_analyzer.cli import main
    import sys as _sys
    bad_result = {"action_items": [
        {"description": "x", "severity": "high", "devices": [],
         "deep_analysis": EMPTY_PLAYBOOK},
    ]}
    f = tmp_path / "result.json"
    f.write_text(json.dumps(bad_result))
    argv = _sys.argv
    _sys.argv = ["ai-log-analyzer", "eval", "--file", str(f), "--min-score", "9.9"]
    try:
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 1  # CI gate trips
    finally:
        _sys.argv = argv
