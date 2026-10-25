"""End to end through ``llm.query()``: no provider ever receives a secret from
the regression table in test_sanitize_secret_formats.py."""
from __future__ import annotations

import copy

import pytest

from ai_log_analyzer import llm
from tests.test_sanitize_secret_formats import FORMATS

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    snap = copy.deepcopy(llm._state)
    llm._state.update({"enabled": True, "provider": "ollama", "allow_cloud_fallback": True,
                       "anthropic_api_key": "sk-test-never-real", "tokenize_hostnames": "auto"})
    monkeypatch.setattr(llm, "_sync_shared_state", lambda force=False: None)
    monkeypatch.setattr(llm, "_audit_call", lambda *a, **k: None)
    llm.reset_circuit_breakers()
    yield
    llm._state.clear()
    llm._state.update(snap)


@pytest.mark.parametrize("fid,text,secret", FORMATS, ids=[f[0] for f in FORMATS])
def test_provider_never_sees_the_secret(monkeypatch, fid, text, secret):
    seen: list[str] = []

    def provider(system, user, max_tokens):
        seen.append(user)
        return "ok"

    for name in ("ollama", "local", "claude", "grok"):
        monkeypatch.setitem(llm._PROVIDERS, name, provider)
    prompt = f"Analyze this device config:\n{text}\nrouter-id 10.0.0.1\n"
    assert llm.query("sys", prompt) == "ok"
    assert len(seen) == 1 and secret not in seen[0], seen[0]
