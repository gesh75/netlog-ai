"""Regression: raw log samples must pass the sanitize gate before any LLM call.

The config paths (optimize_config / analyze_site / copilot) always sanitized;
the *log* path (deep_analyze sample_messages) did not — contradicting the
project's core "sanitize-before-LLM" guarantee.
"""
from __future__ import annotations

import pytest

from ai_log_analyzer import analyzer, llm


pytestmark = pytest.mark.unit

SECRET_LINE = "login attempt snmp-server community SuperSecret123 ro rejected"


def test_deep_analyze_sanitizes_sample_messages(monkeypatch):
    captured: dict = {}

    def fake_query(system_prompt, user_prompt, max_tokens=0, **kwargs):
        captured["prompt"] = user_prompt
        return None  # fall back to KB — we only care what went out

    monkeypatch.setattr(llm, "query", fake_query)
    analyzer.deep_analyze(
        category="security",
        description="Authentication failure",
        devices=["r1"],
        count=3,
        sample_messages=[SECRET_LINE],
        skip_llm=False,
    )
    assert "prompt" in captured, "LLM path was not exercised"
    assert "SuperSecret123" not in captured["prompt"]
    assert "<REDACTED>" in captured["prompt"]


def test_deep_analyze_sanitizes_description(monkeypatch):
    captured: dict = {}

    def fake_query(system_prompt, user_prompt, max_tokens=0, **kwargs):
        captured["prompt"] = user_prompt
        return None

    monkeypatch.setattr(llm, "query", fake_query)
    # Severity-promoted events with no KB match carry a raw message snippet
    # as their description.
    analyzer.deep_analyze(
        category="other",
        description=SECRET_LINE,
        devices=["r1"],
        count=1,
        sample_messages=[],
        skip_llm=False,
    )
    assert "SuperSecret123" not in captured["prompt"]
