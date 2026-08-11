"""Tests for user-defined classification rules (classifier custom rules + API)."""
from __future__ import annotations

import json
import time

import pytest

from ai_log_analyzer import classifier
from ai_log_analyzer.classifier import LogEvent, classify_events


pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _clean_custom_rules():
    """Isolate each test from module-global custom-rule state."""
    saved = list(classifier._CUSTOM_RULES)
    classifier._CUSTOM_RULES.clear()
    yield
    classifier._CUSTOM_RULES[:] = saved


def _event(message: str, appname: str = "app") -> LogEvent:
    return LogEvent(timestamp="2026-01-01T00:00:00", hostname="r1",
                    appname=appname, severity_raw="info", message=message)


def test_add_custom_rule_and_classify():
    added, errors = classifier.add_custom_rules([{
        "pattern": r"widget.*meltdown",
        "severity": "critical",
        "category": "custom",
        "description": "Widget meltdown detected",
    }])
    assert added == 1 and not errors
    events, sev, _cat = classify_events([_event("widget core meltdown imminent")])
    assert events[0].severity == "critical"
    assert events[0].description == "Widget meltdown detected"
    assert sev["critical"] == 1


def test_custom_rule_overrides_builtin():
    # Built-in KB says "bgp peer down" is high/routing; operator overrides.
    classifier.add_custom_rules([{
        "pattern": r"bgp.*down",
        "severity": "low",
        "category": "known-noise",
        "description": "Lab BGP flap — ignore",
    }])
    events, _, _ = classify_events([_event("bgp peer 10.0.0.1 down")])
    assert events[0].severity == "low"
    assert events[0].category == "known-noise"


def test_invalid_rules_are_skipped_with_errors():
    added, errors = classifier.add_custom_rules([
        {"pattern": "(unclosed", "severity": "high"},
        {"pattern": "ok", "severity": "not-a-severity"},
        "not-a-dict",
        {"pattern": "fine", "severity": "medium"},
    ])
    assert added == 1
    assert len(errors) == 3


def test_custom_rule_catastrophic_backtracking_is_bounded():
    added, errors = classifier.add_custom_rules([{
        "pattern": r"(a+)+$", "severity": "high",
    }])
    assert added == 1 and not errors

    started = time.monotonic()
    events, _, _ = classify_events([_event("a" * 10_000 + "!")])
    assert time.monotonic() - started < 1
    assert events[0].severity == "info"


def test_custom_rule_count_and_pattern_length_are_limited():
    rules = [{"pattern": f"rule-{i}", "severity": "low"}
             for i in range(classifier._MAX_CUSTOM_RULES + 1)]
    added, errors = classifier.add_custom_rules(rules)
    assert added == classifier._MAX_CUSTOM_RULES
    assert errors == [
        f"rule {classifier._MAX_CUSTOM_RULES}: custom rule limit "
        f"({classifier._MAX_CUSTOM_RULES}) reached"
    ]

    classifier._CUSTOM_RULES.clear()
    added, errors = classifier.add_custom_rules([{
        "pattern": "x" * (classifier._MAX_CUSTOM_PATTERN_LENGTH + 1),
        "severity": "low",
    }])
    assert added == 0
    assert "exceeds" in errors[0]


def test_load_custom_rules_file(tmp_path):
    rules_file = tmp_path / "rules.json"
    rules_file.write_text(json.dumps([
        {"pattern": "gizmo.*offline", "severity": "high",
         "category": "gizmo", "description": "Gizmo went offline"},
    ]))
    added, errors = classifier.load_custom_rules_file(str(rules_file))
    assert added == 1 and not errors
    events, _, _ = classify_events([_event("gizmo controller offline")])
    assert events[0].category == "gizmo"


def test_load_custom_rules_file_missing():
    added, errors = classifier.load_custom_rules_file("/nonexistent/rules.json")
    assert added == 0 and errors


# ── API endpoints ────────────────────────────────────────────────────────────

@pytest.fixture()
def client():
    from ai_log_analyzer.web.app import create_app
    app = create_app()
    app.testing = True
    with app.test_client() as c:
        yield c


def test_api_rules_get(client):
    resp = client.get("/api/rules")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["builtin_count"] > 50
    assert body["custom"] == []


def test_api_rules_post_and_list(client):
    resp = client.post("/api/rules", json={"rules": [
        {"pattern": "foo.*bar", "severity": "medium",
         "category": "custom", "description": "foo-bar"},
    ]})
    assert resp.status_code == 200
    assert resp.get_json()["added"] == 1
    listed = client.get("/api/rules").get_json()
    assert any(r["description"] == "foo-bar" for r in listed["custom"])


def test_api_rules_post_rejects_bad_body(client):
    assert client.post("/api/rules", json={}).status_code == 400
    assert client.post("/api/rules", json={"rules": []}).status_code == 400
    resp = client.post("/api/rules", json={"rules": [{"pattern": "(", "severity": "high"}]})
    assert resp.status_code == 400
    assert resp.get_json()["added"] == 0
