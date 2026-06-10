"""LLM transport + fallback-chain tests (previously 0% on every transport).

The chain routes to the PAID Anthropic API — these tests pin error recording,
fallback order, the claude-only no-fallback contract, the prompt-caching
payload, and <think>-block cleaning, all with the network fully mocked.
"""
from __future__ import annotations

import copy

import pytest
import requests

from ai_log_analyzer import llm


class _NetworkTripwire:
    """Any unmocked transport call fails loudly instead of hitting the real
    network (and the real, PAID Anthropic API)."""

    def post(self, url, **kwargs):
        pytest.fail(f"unmocked network call to {url}")

    def get(self, url, **kwargs):
        pytest.fail(f"unmocked network call to {url}")


@pytest.fixture(autouse=True)
def _isolated_llm_state(monkeypatch):
    """Deep-copy restore — last_errors is nested and a shallow snapshot
    would leak mutations between tests. Also kills the real API key and
    arms the network tripwire for every test in this module."""
    snap = copy.deepcopy(llm._state)
    llm._state["anthropic_api_key"] = "sk-test-never-real"
    monkeypatch.setattr(llm, "_SESSION", _NetworkTripwire())
    yield
    llm._state.clear()
    llm._state.update(snap)


class _Resp:
    def __init__(self, status_code: int, payload: dict | None = None, text: str = ""):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text

    def json(self) -> dict:
        return self._payload


class _Session:
    """Scripted fake for llm._SESSION — returns/raises per call."""

    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.calls: list[dict] = []

    def post(self, url, **kwargs):
        self.calls.append({"url": url, **kwargs})
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


# ── _clean ───────────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_clean_strips_think_blocks():
    assert llm._clean("<think>secret reasoning</think>{\"a\": 1}") == '{"a": 1}'


@pytest.mark.unit
def test_clean_strips_reasoning_preamble():
    out = llm._clean("Okay, let me look at this.\n{\"a\": 1}")
    assert out == '{"a": 1}'


@pytest.mark.unit
def test_clean_keeps_normal_text():
    assert llm._clean("BGP peer down on rt-01") == "BGP peer down on rt-01"


# ── ollama transport ─────────────────────────────────────────────────────────

@pytest.mark.unit
def test_ollama_success_cleans_and_clears_error(monkeypatch):
    llm._state["last_errors"] = {"ollama": "old error"}
    sess = _Session(_Resp(200, {"message": {"content": "<think>x</think>answer"}}))
    monkeypatch.setattr(llm, "_SESSION", sess)
    assert llm._query_ollama("sys", "user", 100) == "answer"
    assert "ollama" not in llm._state["last_errors"]


@pytest.mark.unit
def test_ollama_http_error_recorded(monkeypatch):
    monkeypatch.setattr(llm, "_SESSION", _Session(_Resp(500, text="boom")))
    assert llm._query_ollama("sys", "user", 100) is None
    assert "HTTP 500" in llm._state["last_errors"]["ollama"]


@pytest.mark.unit
def test_ollama_timeout_and_connection_errors_recorded(monkeypatch):
    monkeypatch.setattr(llm, "_SESSION", _Session(requests.Timeout()))
    assert llm._query_ollama("sys", "user", 100) is None
    assert "Timeout" in llm._state["last_errors"]["ollama"]

    monkeypatch.setattr(llm, "_SESSION", _Session(requests.ConnectionError("refused")))
    assert llm._query_ollama("sys", "user", 100) is None
    assert "Connection error" in llm._state["last_errors"]["ollama"]


@pytest.mark.unit
def test_ollama_empty_response_recorded(monkeypatch):
    monkeypatch.setattr(llm, "_SESSION", _Session(_Resp(200, {"message": {"content": ""}})))
    assert llm._query_ollama("sys", "user", 100) is None
    assert "Empty" in llm._state["last_errors"]["ollama"]


# ── claude transport ─────────────────────────────────────────────────────────

@pytest.mark.unit
def test_claude_without_key_never_posts(monkeypatch):
    llm._state["anthropic_api_key"] = ""
    sess = _Session()
    monkeypatch.setattr(llm, "_SESSION", sess)
    assert llm._query_claude("sys", "user", 100) is None
    assert not sess.calls
    assert "not configured" in llm._state["last_errors"]["claude"]


@pytest.mark.unit
def test_claude_success_payload_uses_prompt_caching(monkeypatch):
    llm._state["anthropic_api_key"] = "sk-test"
    sess = _Session(_Resp(200, {"content": [{"text": "verdict"}]}))
    monkeypatch.setattr(llm, "_SESSION", sess)
    assert llm._query_claude("sys prompt", "user prompt", 100) == "verdict"
    body = sess.calls[0]["json"]
    assert body["system"][0]["text"] == "sys prompt"
    assert body["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert sess.calls[0]["headers"]["x-api-key"] == "sk-test"


@pytest.mark.unit
def test_claude_http_error_recorded(monkeypatch):
    llm._state["anthropic_api_key"] = "sk-test"
    monkeypatch.setattr(llm, "_SESSION", _Session(_Resp(401, text="invalid x-api-key")))
    assert llm._query_claude("sys", "user", 100) is None
    assert "HTTP 401" in llm._state["last_errors"]["claude"]


# ── fallback chain ───────────────────────────────────────────────────────────

@pytest.mark.unit
def test_query_disabled_short_circuits(monkeypatch):
    llm._state["enabled"] = False
    monkeypatch.setitem(llm._PROVIDERS, "ollama",
                        lambda *a: pytest.fail("provider called while disabled"))
    assert llm.query("sys", "user") is None


@pytest.mark.unit
def test_query_falls_back_in_order(monkeypatch):
    llm._state["enabled"] = True
    llm._state["provider"] = "ollama"
    called: list[str] = []
    monkeypatch.setitem(llm._PROVIDERS, "ollama", lambda *a: called.append("ollama"))
    monkeypatch.setitem(llm._PROVIDERS, "local", lambda *a: called.append("local"))
    monkeypatch.setitem(llm._PROVIDERS, "claude",
                        lambda *a: called.append("claude") or "claude says hi")
    assert llm.query("sys", "user") == "claude says hi"
    assert called == ["ollama", "local", "claude"]


@pytest.mark.unit
def test_query_claude_provider_tries_claude_first(monkeypatch):
    llm._state["enabled"] = True
    llm._state["provider"] = "claude"
    called: list[str] = []
    monkeypatch.setitem(llm._PROVIDERS, "claude",
                        lambda *a: called.append("claude") or "fast answer")
    monkeypatch.setitem(llm._PROVIDERS, "ollama",
                        lambda *a: pytest.fail("fallback ran despite success"))
    assert llm.query("sys", "user") == "fast answer"
    assert called == ["claude"]


@pytest.mark.unit
def test_query_claude_only_never_falls_back(monkeypatch):
    llm._state["enabled"] = True
    llm._state["provider"] = "claude-only"
    # claude-only short-circuits to _query_claude directly, NOT via the
    # _PROVIDERS table — patch the direct call.
    monkeypatch.setattr(llm, "_query_claude", lambda *a: None)
    monkeypatch.setitem(llm._PROVIDERS, "ollama",
                        lambda *a: pytest.fail("claude-only must not fall back"))
    monkeypatch.setitem(llm._PROVIDERS, "local",
                        lambda *a: pytest.fail("claude-only must not fall back"))
    assert llm.query("sys", "user") is None


@pytest.mark.unit
def test_query_all_providers_fail_returns_none(monkeypatch):
    llm._state["enabled"] = True
    llm._state["provider"] = "ollama"
    for name in ("ollama", "local", "claude"):
        monkeypatch.setitem(llm._PROVIDERS, name, lambda *a: None)
    assert llm.query("sys", "user") is None


# ── OpenAI-shape extraction (docker model runner) ────────────────────────────

@pytest.mark.unit
def test_extract_openai_text_variants():
    assert llm._extract_openai_text({}) is None
    assert llm._extract_openai_text({"choices": []}) is None
    assert llm._extract_openai_text(
        {"choices": [{"message": {"content": "hi"}}]}) == "hi"
    # reasoning_content fallback (qwen3-style)
    assert llm._extract_openai_text(
        {"choices": [{"message": {"content": "", "reasoning_content": "fallback"}}]}
    ) == "fallback"
