"""Regression: analyze_site() must sanitize device configs before the LLM call.

The sanitize-before-LLM guarantee held for copilot.ask / optimize_config /
diff but analyze_site() shipped raw config_text into the prompt. This locks
the fix in place.
"""
from __future__ import annotations

import pytest

import ai_log_analyzer.analyzer as analyzer_mod
from ai_log_analyzer.analyzer import analyze_site

_SECRET_CONFIG = """\
system {
    root-authentication {
        encrypted-password "$6$rounds=5000$abcdef$VerySecretHash123";
    }
}
snmp {
    community topsecret-rw-community {
        authorization read-write;
    }
}
protocols {
    bgp {
        group ebgp-peers {
            neighbor 192.0.2.1;
        }
    }
}
"""


@pytest.mark.unit
def test_analyze_site_never_sends_raw_secrets_to_llm(monkeypatch):
    captured: dict = {}

    def fake_query(system_prompt, user_prompt, max_tokens=4096, **kw):
        captured["system"] = system_prompt
        captured["user"] = user_prompt
        return None  # LLM failure path is fine — we only need the prompt

    monkeypatch.setattr(analyzer_mod.llm, "query", fake_query)
    monkeypatch.setattr(analyzer_mod.llm, "get_state", lambda: {"enabled": True})

    analyze_site("test-site", [{
        "hostname": "fw-01",
        "function": "firewall",
        "platform": "junos",
        "config_text": _SECRET_CONFIG,
    }])

    assert "user" in captured, "analyze_site never reached llm.query"
    prompt = captured["user"]
    # secrets scrubbed
    assert "VerySecretHash123" not in prompt
    assert "topsecret-rw-community" not in prompt
    # but the config structure still reaches the LLM
    assert "fw-01" in prompt
    assert "root-authentication" in prompt
