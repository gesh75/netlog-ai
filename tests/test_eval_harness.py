"""Golden-incident regression harness: the bundled labeled cases pass, each
scoring dimension actually detects the failure it is meant to catch, and a
run leaves global LLM state and the environment untouched."""
from __future__ import annotations

import copy
import os
import sys
from unittest.mock import patch

import pytest

from ai_log_analyzer import analyzer, judge, llm, sanitize_vault


@pytest.fixture(scope="module")
def cases():
    return {c["id"]: c for c in judge.load_cases()}


def test_bundled_cases_cover_the_target_scenarios(cases):
    tags = {t for c in cases.values() for t in c.get("tags", [])}
    assert {"evpn", "bgp", "leak", "flap", "fortinet", "sdwan", "ipsec", "paloalto", "ha"} <= tags
    assert all(c.get("expect", {}).get("root") for c in cases.values())


def test_every_golden_incident_passes(cases):
    report = judge.run_eval(list(cases.values()))
    assert report["failing"] == [], [(r["id"], r["notes"]) for r in report["results"] if r["id"] in report["failing"]]
    assert report["scores"] == {"rca": 1.0, "detokenize": 1.0, "guardrail": 1.0, "evidence": 1.0, "overall": 1.0}
    for r in report["results"]:
        assert r["playbook_quality"] >= 7.0, (r["id"], r["playbook_quality"])


def test_rca_dimension_catches_a_wrong_root_and_missed_alerts(cases):
    case = copy.deepcopy(cases["fortigate-sdwan-ipsec-cascade"])
    case["expect"]["root"]["description_any"] = ["BGP hold timer expired"]
    case["expect"]["must_detect"].append("Some alert the pipeline never raises")
    r = judge.run_case(case)
    assert r["scores"]["rca"] < 1.0
    assert any("root ranked" in n for n in r["notes"]) and any(n.startswith("missed:") for n in r["notes"])


def test_rca_dimension_catches_false_positives(cases):
    case = copy.deepcopy(cases["panos-ha-failover-vpn-bgp"])
    case["expect"]["must_not_detect"] = ["Firewall HA failover / state change"]
    r = judge.run_case(case)
    assert r["scores"]["rca"] < 1.0 and any(n.startswith("false positive") for n in r["notes"])


def test_guardrail_dimension_catches_a_disabled_guardrail(cases):
    case = cases["bgp-route-leak-and-flap"]
    with patch.object(analyzer, "screen_llm_cli", lambda v, b=None: v), \
            patch.object(analyzer, "screen_phases", lambda p, b=None: p):
        r = judge.run_case(case)
    assert r["scores"]["guardrail"] == 0.0
    assert any("survived the guardrail" in n for n in r["notes"])


def test_detokenize_dimension_catches_entity_leaks(cases):
    case = cases["fortigate-sdwan-ipsec-cascade"]
    with patch.object(sanitize_vault.SanitizeVault, "tokenize", lambda self, text, hosts=(): text):
        r = judge.run_case(case)
    assert r["scores"]["detokenize"] <= 0.5
    assert any("raw entities reached the provider" in n for n in r["notes"])


def test_evidence_dimension_requires_the_expected_config_evidence(cases):
    case = copy.deepcopy(cases["fortigate-sdwan-ipsec-cascade"])
    case["configs"] = []
    r = judge.run_case(case)
    assert r["scores"]["evidence"] == 0.0


def test_a_run_restores_llm_state_and_environment(cases, tmp_path, monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_STATE_DB", str(tmp_path / "live.db"))
    before = dict(llm._state)
    provider_fn = llm._PROVIDERS["claude"]
    judge.run_case(cases["panos-ha-failover-vpn-bgp"])
    assert llm._state == before and llm._PROVIDERS["claude"] is provider_fn
    assert os.environ["AI_LOG_ANALYZER_STATE_DB"] == str(tmp_path / "live.db")
    assert "AI_LOG_ANALYZER_RAG" not in os.environ
    assert not (tmp_path / "live.db").exists()       # the case never touched live state


def test_cli_golden_gate(monkeypatch, capsys):
    from ai_log_analyzer import cli
    monkeypatch.setattr(sys, "argv", ["ai-log-analyzer", "eval", "--golden", "--min-golden", "0.99"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "Golden incidents : 4" in out and "overall=1.00" in out
