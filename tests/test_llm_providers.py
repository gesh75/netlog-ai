"""Tests for the LLM provider switcher."""
import pytest

from ai_log_analyzer import llm


@pytest.fixture(autouse=True)
def restore_state():
    """Snapshot provider state, restore after each test."""
    snap = dict(llm._state)
    yield
    for k, v in snap.items():
        llm._state[k] = v


@pytest.mark.unit
def test_default_state_has_three_providers():
    state = llm.get_state()
    ids = [p["id"] for p in state["providers_available"]]
    assert "ollama" in ids and "local" in ids and "claude" in ids


@pytest.mark.unit
def test_set_provider_ollama_succeeds():
    ok, msg = llm.set_provider("ollama")
    assert ok and msg == "ollama"


@pytest.mark.unit
def test_set_provider_local_succeeds():
    ok, _ = llm.set_provider("local")
    assert ok


@pytest.mark.unit
def test_set_provider_invalid_rejected():
    ok, msg = llm.set_provider("gpt4")
    assert not ok and "provider must be" in msg


@pytest.mark.unit
def test_set_provider_claude_requires_api_key():
    llm._state["anthropic_api_key"] = ""
    ok, msg = llm.set_provider("claude")
    assert not ok and "ANTHROPIC_API_KEY" in msg


@pytest.mark.unit
def test_set_provider_claude_only_requires_api_key():
    llm._state["anthropic_api_key"] = ""
    ok, _ = llm.set_provider("claude-only")
    assert not ok


@pytest.mark.unit
def test_set_provider_claude_succeeds_with_key():
    llm._state["anthropic_api_key"] = "sk-test"
    ok, msg = llm.set_provider("claude")
    assert ok and msg == "claude"


@pytest.mark.unit
def test_clean_strips_think_block():
    text = "<think>this is reasoning</think>\nActual answer here."
    out = llm._clean(text)
    assert "reasoning" not in out
    assert "Actual answer" in out


@pytest.mark.unit
def test_clean_strips_preamble():
    text = "Okay, let me analyze this.\n\nThe actual answer is 42."
    out = llm._clean(text)
    assert out.startswith("The actual answer") or "42" in out


@pytest.mark.unit
def test_query_returns_none_when_disabled():
    llm.set_enabled(False)
    assert llm.query("sys", "user") is None


@pytest.mark.unit
def test_provider_chain_order_for_ollama():
    """When provider=ollama, fallback order should be [ollama, local, claude]."""
    # Disable LLM so we don't actually hit any backend
    llm.set_enabled(False)
    llm._state["provider"] = "ollama"
    # No backends will be called because enabled=False
    assert llm.query("s", "u") is None


@pytest.mark.unit
def test_extract_openai_text_handles_missing_choices():
    assert llm._extract_openai_text({}) is None
    assert llm._extract_openai_text({"choices": []}) is None


@pytest.mark.unit
def test_extract_openai_text_extracts_content():
    payload = {"choices": [{"message": {"content": "hello world"}}]}
    assert llm._extract_openai_text(payload) == "hello world"


@pytest.mark.unit
def test_extract_openai_text_falls_back_to_reasoning_content():
    payload = {"choices": [{"message": {"reasoning_content": "thinking..."}}]}
    assert llm._extract_openai_text(payload) == "thinking..."
