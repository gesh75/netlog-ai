"""Incident memory: recurrence annotation across runs + similarity search."""
from __future__ import annotations

import pytest

from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.memory import IncidentStore


pytestmark = pytest.mark.unit


def _bgp_event(host: str = "spine-01") -> LogEvent:
    return LogEvent(timestamp="Jan  1 00:00:01", hostname=host, appname="rpd",
                    severity_raw="err", message="bgp peer 10.0.0.1 down hold timer expired")


def test_recurrence_annotated_on_second_run(tmp_path, monkeypatch):
    from ai_log_analyzer.analyzer import analyze
    monkeypatch.setenv("AI_LOG_ANALYZER_INCIDENT_STORE", str(tmp_path / "incidents.jsonl"))

    r1 = analyze(iter([_bgp_event()]), use_llm=False)
    first = r1.to_dict()["action_items"][0]
    assert "recurrence" not in first  # nothing before this run

    r2 = analyze(iter([_bgp_event()]), use_llm=False)
    second = r2.to_dict()["action_items"][0]
    assert second["recurrence"]["count"] == 1
    assert second["recurrence"]["devices"] == ["spine-01"]

    r3 = analyze(iter([_bgp_event("leaf-09")]), use_llm=False)
    third = r3.to_dict()["action_items"][0]
    # History covers runs 1+2 (both spine-01); leaf-09 is the current run.
    assert third["recurrence"]["count"] == 2
    assert third["recurrence"]["devices"] == ["spine-01"]

    r4 = analyze(iter([_bgp_event()]), use_llm=False)
    fourth = r4.to_dict()["action_items"][0]
    assert fourth["recurrence"]["count"] == 3
    assert set(fourth["recurrence"]["devices"]) == {"spine-01", "leaf-09"}


def test_no_env_var_means_no_journal(tmp_path, monkeypatch):
    from ai_log_analyzer.analyzer import analyze
    monkeypatch.delenv("AI_LOG_ANALYZER_INCIDENT_STORE", raising=False)
    r = analyze(iter([_bgp_event()]), use_llm=False)
    assert "recurrence" not in r.to_dict()["action_items"][0]
    assert not list(tmp_path.iterdir())


def test_find_similar_token_overlap(tmp_path):
    store = IncidentStore(tmp_path / "j.jsonl")
    store.record([
        {"description": "Power supply or fan failure", "severity": "critical",
         "category": "hardware", "devices": ["spine-02"], "count": 1,
         "sample_messages": ["%PLATFORM-2-PS_FAIL: Power supply 1 failed"]},
        {"description": "BGP peer down / connect failure", "severity": "high",
         "category": "routing", "devices": ["spine-01"], "count": 6,
         "sample_messages": []},
    ], generated_at="2026-07-13T10:00:00")

    fresh = IncidentStore(tmp_path / "j.jsonl")  # reload from disk
    matches = fresh.find_similar("fan failures on spine-02")
    assert matches
    assert matches[0]["description"] == "Power supply or fan failure"
    assert not fresh.find_similar("")


def test_corrupt_journal_tolerated(tmp_path):
    p = tmp_path / "bad.jsonl"
    p.write_text('{"description": "ok", "generated_at": "t"}\nnot-json\n{broken\n')
    store = IncidentStore(p)
    assert len(store) == 1


def test_api_incidents_similar(tmp_path, monkeypatch):
    from ai_log_analyzer.web.app import create_app
    monkeypatch.setenv("AI_LOG_ANALYZER_INCIDENT_STORE", str(tmp_path / "j.jsonl"))
    IncidentStore(tmp_path / "j.jsonl").record(
        [{"description": "Interface link down", "severity": "high",
          "category": "interface", "devices": ["leaf-11"], "count": 3,
          "sample_messages": []}], generated_at="2026-07-13T10:00:00")

    app = create_app()
    app.testing = True
    client = app.test_client()
    body = client.get("/api/incidents/similar?q=link down leaf-11").get_json()
    assert body["matches"][0]["description"] == "Interface link down"
    assert client.get("/api/incidents/similar").status_code == 400

    monkeypatch.delenv("AI_LOG_ANALYZER_INCIDENT_STORE")
    assert client.get("/api/incidents/similar?q=x").status_code == 400
