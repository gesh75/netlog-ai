"""egress_policy must not call a local-provider URL "local-only" when that URL
points off-host (an OLLAMA_URL on a public address still sends prompts out)."""
from __future__ import annotations

import pytest

from ai_log_analyzer import llm

pytestmark = pytest.mark.unit


@pytest.fixture
def state(monkeypatch):
    monkeypatch.setattr(llm, "_sync_shared_state", lambda force=False: None)
    for key in ("provider", "enabled", "allow_cloud_fallback", "ollama_url", "local_url"):
        monkeypatch.setitem(llm._state, key, llm._state.get(key))
    monkeypatch.delenv("LLM_LOCAL_HOSTS", raising=False)
    llm._state.update(provider="ollama", enabled=True, allow_cloud_fallback=False,
                      ollama_url="http://localhost:11434", local_url="http://localhost:12434")
    return llm._state


@pytest.mark.parametrize("url", [
    "http://localhost:11434", "http://127.0.0.1:11434", "http://[::1]:11434", "http://10.1.2.3:11434",
    "http://192.168.1.5:11434", "http://172.16.0.9", "http://169.254.1.1:11434", "http://100.64.1.2:11434",
    "http://ollama:11434", "http://host.docker.internal:11434", "http://gpu-box.local:11434",
    "http://llm.corp.internal:11434", "192.168.0.7:11434", "http://[fd00::5]:11434",
])
def test_local_urls_stay_local_only(state, url):
    state["ollama_url"] = url
    assert llm.egress_policy()["mode"] == "local-only"


@pytest.mark.parametrize("url", [
    "http://8.8.8.8:11434", "https://52.20.30.40", "http://ollama.example.com:11434",
    "https://my-gpu.runpod.io", "http://[2001:4860:4860::8888]:11434",
])
def test_remote_ollama_url_is_not_local_only(state, url):
    state["ollama_url"] = url
    pol = llm.egress_policy()
    assert pol["mode"] == "remote-host"
    assert "ollama" in pol["remote_hosts"]
    assert pol["order"] == llm.provider_order("ollama")


def test_remote_model_runner_url_is_flagged(state):
    state.update(provider="local", local_url="http://52.9.8.7:12434")
    pol = llm.egress_policy()
    assert pol["mode"] == "remote-host" and "local" in pol["remote_hosts"]


def test_trusted_hosts_env_allows_internal_fqdn(state, monkeypatch):
    state["ollama_url"] = "http://ollama.corp.example.com:11434"
    assert llm.egress_policy()["mode"] == "remote-host"
    monkeypatch.setenv("LLM_LOCAL_HOSTS", "ollama.corp.example.com, other.example.com")
    assert llm.egress_policy()["mode"] == "local-only"


def test_cloud_modes_are_unchanged(state):
    state.update(provider="claude", ollama_url="http://8.8.8.8:11434")
    assert llm.egress_policy()["mode"] == "cloud"
    state.update(provider="ollama", allow_cloud_fallback=True)
    assert llm.egress_policy()["mode"] == "cloud-fallback"


def test_local_only_reports_no_remote_hosts(state):
    pol = llm.egress_policy()
    assert pol["mode"] == "local-only" and pol["remote_hosts"] == []
