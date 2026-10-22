"""Gateway resilience: query() never raises (malformed provider replies, buggy
providers), an overall per-query deadline bounds the worst case, and a
per-provider circuit breaker stops hammering a dead backend. No real network."""
from __future__ import annotations

import copy

import pytest
import requests

from ai_log_analyzer import llm

pytestmark = pytest.mark.unit


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds: float):
        self.now += seconds


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    snap = copy.deepcopy(llm._state)
    llm._state.update({
        "enabled": True, "provider": "ollama", "anthropic_api_key": "sk-test-never-real",
        "xai_api_key": "xai-test-never-real", "allow_cloud_fallback": False,
        "tokenize_hostnames": "auto", "last_errors": {}, "timeout": 120, "max_retries": 2,
    })
    monkeypatch.setattr(llm, "_sync_shared_state", lambda force=False: None)
    monkeypatch.setattr(llm, "_sleep", lambda _s: None)
    for var in ("LLM_TOTAL_TIMEOUT_S", "LLM_BREAKER_THRESHOLD", "LLM_BREAKER_COOLDOWN_S"):
        monkeypatch.delenv(var, raising=False)
    yield
    llm._state.clear()
    llm._state.update(snap)


class _Resp:
    def __init__(self, payload, status_code=200, headers=None):
        self._payload = payload
        self.status_code = status_code
        self.text = str(payload)[:200]
        self.headers = headers or {}

    def json(self):
        return self._payload


class _Session:
    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.calls: list[dict] = []

    def post(self, url, **kwargs):
        self.calls.append({"url": url, **kwargs})
        outcome = self.outcomes.pop(0) if len(self.outcomes) > 1 else self.outcomes[0]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def get(self, url, **kwargs):
        raise requests.ConnectionError("no network in tests")


# ── malformed provider replies never raise ───────────────────────────────────

MALFORMED = [
    pytest.param({"content": []}, id="empty-content-list"),
    pytest.param({"content": None}, id="null-content"),
    pytest.param({"content": [{"type": "tool_use"}]}, id="no-text-block"),
    pytest.param({"content": ["text"]}, id="non-dict-block"),
    pytest.param({"content": [{"type": "text", "text": 5}]}, id="non-str-text"),
    pytest.param(["not", "a", "dict"], id="list-body"),
    pytest.param("just a string", id="str-body"),
    pytest.param(None, id="null-body"),
    pytest.param({"choices": [None]}, id="null-choice"),
    pytest.param({"choices": [{"message": None}]}, id="null-message"),
    pytest.param({"choices": [{"message": {"content": ["x"]}}]}, id="list-content"),
    pytest.param({"message": ["x"]}, id="list-message"),
    pytest.param({"message": {"content": 7}}, id="int-content"),
]


@pytest.mark.parametrize("body", MALFORMED)
@pytest.mark.parametrize("provider", ["ollama", "claude", "grok", "local"])
def test_provider_returns_none_on_malformed_body(monkeypatch, provider, body):
    sess = _Session(_Resp(body))
    monkeypatch.setattr(llm, "_SESSION", sess)
    monkeypatch.setattr(llm, "_DOCKER_SOCKETS", [])
    fn = {"ollama": llm._query_ollama, "claude": llm._query_claude,
          "grok": llm._query_grok, "local": llm._query_docker_runner}[provider]
    assert fn("sys", "user", 50) is None


@pytest.mark.parametrize("body", MALFORMED)
def test_query_never_raises_on_malformed_claude_reply(monkeypatch, body):
    llm._state["provider"] = "claude-only"
    monkeypatch.setattr(llm, "_SESSION", _Session(_Resp(body)))
    assert llm.query("sys", "peer 10.0.0.1 down") is None


def test_unparseable_json_body_is_a_soft_failure(monkeypatch):
    class _BadJson(_Resp):
        def json(self):
            raise ValueError("Expecting value")
    monkeypatch.setattr(llm, "_SESSION", _Session(_BadJson(None)))
    assert llm._query_claude("sys", "user", 50) is None
    assert llm._query_ollama("sys", "user", 50) is None
    assert "ollama" in llm._state["last_errors"]


def test_claude_thinking_block_before_text_is_skipped(monkeypatch):
    body = {"content": [{"type": "thinking", "thinking": "hm"}, {"type": "text", "text": "the answer"}]}
    monkeypatch.setattr(llm, "_SESSION", _Session(_Resp(body)))
    assert llm._query_claude("sys", "user", 50) == "the answer"


def test_malformed_reply_falls_through_to_next_provider(monkeypatch):
    llm._state.update(provider="claude", allow_cloud_fallback=True)
    monkeypatch.setitem(llm._PROVIDERS, "claude", llm._query_claude)
    monkeypatch.setattr(llm, "_SESSION", _Session(_Resp({"content": []})))
    seen = []
    monkeypatch.setitem(llm._PROVIDERS, "ollama", lambda *a: seen.append("ollama") or "local answer")
    assert llm.query("sys", "user") == "local answer"
    assert seen == ["ollama"]


def test_provider_exception_never_escapes_query(monkeypatch):
    def boom(*a):
        raise RuntimeError("bug in provider")
    monkeypatch.setitem(llm._PROVIDERS, "ollama", boom)
    monkeypatch.setitem(llm._PROVIDERS, "local", lambda *a: "fallback ok")
    assert llm.query("sys", "user") == "fallback ok"
    assert "RuntimeError" in llm._state["last_errors"]["ollama"]


def test_query_returns_none_when_every_provider_raises(monkeypatch):
    def boom(*a):
        raise KeyError("x")
    for name in ("ollama", "local"):
        monkeypatch.setitem(llm._PROVIDERS, name, boom)
    assert llm.query("sys", "user") is None


def test_audit_failure_never_breaks_the_answer(monkeypatch):
    llm._state.update(provider="claude", allow_cloud_fallback=True)
    monkeypatch.setitem(llm._PROVIDERS, "claude", lambda *a: "cloud answer")
    monkeypatch.setattr(llm, "_audit_call", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
    assert llm.query("sys", "user") == "cloud answer"


# ── overall deadline ─────────────────────────────────────────────────────────

def test_total_deadline_skips_remaining_providers(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(llm, "_clock", clock)
    monkeypatch.setenv("LLM_TOTAL_TIMEOUT_S", "100")
    llm._state["allow_cloud_fallback"] = True
    called = []

    def slow_fail(name):
        def fn(*a):
            called.append(name)
            clock.advance(120)
        return fn
    for name in ("ollama", "local", "claude", "grok"):
        monkeypatch.setitem(llm._PROVIDERS, name, slow_fail(name))
    assert llm.query("sys", "user") is None
    assert called == ["ollama"]  # 120 s burned > 100 s budget: nothing else is tried
    assert "deadline" in llm._state["last_errors"]["local"]


def test_deadline_does_not_cut_a_fast_chain(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(llm, "_clock", clock)
    monkeypatch.setenv("LLM_TOTAL_TIMEOUT_S", "100")
    monkeypatch.setitem(llm._PROVIDERS, "ollama", lambda *a: clock.advance(30))
    monkeypatch.setitem(llm._PROVIDERS, "local", lambda *a: clock.advance(30) or "ok")
    assert llm.query("sys", "user") == "ok"


def test_deadline_zero_means_unlimited(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(llm, "_clock", clock)
    monkeypatch.setenv("LLM_TOTAL_TIMEOUT_S", "0")
    monkeypatch.setitem(llm._PROVIDERS, "ollama", lambda *a: clock.advance(10_000))
    monkeypatch.setitem(llm._PROVIDERS, "local", lambda *a: "late but fine")
    assert llm.query("sys", "user") == "late but fine"


def test_default_deadline_is_generous():
    assert llm._total_timeout() == 180.0


def test_http_timeout_shrinks_to_remaining_budget(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(llm, "_clock", clock)
    monkeypatch.setenv("LLM_TOTAL_TIMEOUT_S", "100")
    sess = _Session(_Resp({"message": {"content": "hi"}}))
    monkeypatch.setattr(llm, "_SESSION", sess)

    def first(*a):
        clock.advance(70)
    monkeypatch.setitem(llm._PROVIDERS, "local", first)
    llm._state["provider"] = "local"
    monkeypatch.setitem(llm._PROVIDERS, "ollama", llm._query_ollama)
    assert llm.query("sys", "user") == "hi"
    assert sess.calls[0]["timeout"] <= 30  # 120 s configured, ~30 s left


def test_retries_stop_at_the_deadline(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(llm, "_clock", clock)
    monkeypatch.setenv("LLM_TOTAL_TIMEOUT_S", "10")
    llm._state.update(backoff_base=30.0, backoff_max=60.0, max_retries=5)
    sess = _Session(_Resp({}, status_code=503))
    monkeypatch.setattr(llm, "_SESSION", sess)
    slept = []
    monkeypatch.setattr(llm, "_sleep", lambda s: (slept.append(s), clock.advance(s)))
    monkeypatch.setitem(llm._PROVIDERS, "ollama", llm._query_ollama)
    assert llm.query("sys", "user") is None
    assert len([c for c in sess.calls if "/api/chat" in c["url"]]) == 1 and not slept  # 30 s backoff > 10 s budget


# ── circuit breaker ──────────────────────────────────────────────────────────

def _counting(monkeypatch, name, results):
    calls = []

    def fn(*a):
        calls.append(1)
        return results[min(len(calls) - 1, len(results) - 1)]
    monkeypatch.setitem(llm._PROVIDERS, name, fn)
    return calls


def test_breaker_opens_after_three_consecutive_failures(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(llm, "_clock", clock)
    calls = _counting(monkeypatch, "ollama", [None])
    monkeypatch.setitem(llm._PROVIDERS, "local", lambda *a: None)
    for _ in range(3):
        assert llm.query("sys", "user") is None
    assert len(calls) == 3
    assert llm.query("sys", "user") is None
    assert len(calls) == 3  # skipped while the circuit is open
    assert "circuit open" in llm._state["last_errors"]["ollama"]


def test_breaker_half_opens_after_cooldown_and_recovers(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(llm, "_clock", clock)
    monkeypatch.setenv("LLM_BREAKER_COOLDOWN_S", "30")
    calls = _counting(monkeypatch, "ollama", [None, None, None, "recovered"])
    monkeypatch.setitem(llm._PROVIDERS, "local", lambda *a: None)
    for _ in range(3):
        llm.query("sys", "user")
    clock.advance(31)
    assert llm.query("sys", "user") == "recovered"
    assert len(calls) == 4
    assert llm.query("sys", "user") == "recovered"  # closed again


def test_failed_trial_after_cooldown_reopens_immediately(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(llm, "_clock", clock)
    monkeypatch.setenv("LLM_BREAKER_COOLDOWN_S", "30")
    calls = _counting(monkeypatch, "ollama", [None])
    monkeypatch.setitem(llm._PROVIDERS, "local", lambda *a: None)
    for _ in range(3):
        llm.query("sys", "user")
    clock.advance(31)
    llm.query("sys", "user")  # trial call fails
    llm.query("sys", "user")  # circuit open again
    assert len(calls) == 4


def test_success_resets_the_failure_streak(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(llm, "_clock", clock)
    calls = _counting(monkeypatch, "ollama", [None, None, "ok", None, None, None])
    monkeypatch.setitem(llm._PROVIDERS, "local", lambda *a: None)
    for _ in range(5):
        llm.query("sys", "user")
    assert len(calls) == 5  # fail, fail, ok, fail, fail: never three in a row


def test_breaker_is_per_provider_and_chain_continues(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(llm, "_clock", clock)
    bad = _counting(monkeypatch, "ollama", [None])
    monkeypatch.setitem(llm._PROVIDERS, "local", lambda *a: "docker runner answer")
    for _ in range(5):
        assert llm.query("sys", "user") == "docker runner answer"
    assert len(bad) == 3


def test_breaker_threshold_zero_disables_it(monkeypatch):
    monkeypatch.setenv("LLM_BREAKER_THRESHOLD", "0")
    calls = _counting(monkeypatch, "ollama", [None])
    monkeypatch.setitem(llm._PROVIDERS, "local", lambda *a: None)
    for _ in range(6):
        llm.query("sys", "user")
    assert len(calls) == 6


def test_breaker_threshold_is_env_tunable(monkeypatch):
    monkeypatch.setenv("LLM_BREAKER_THRESHOLD", "1")
    calls = _counting(monkeypatch, "ollama", [None])
    monkeypatch.setitem(llm._PROVIDERS, "local", lambda *a: None)
    for _ in range(4):
        llm.query("sys", "user")
    assert len(calls) == 1


def test_reset_circuit_breakers(monkeypatch):
    calls = _counting(monkeypatch, "ollama", [None])
    monkeypatch.setitem(llm._PROVIDERS, "local", lambda *a: None)
    for _ in range(3):
        llm.query("sys", "user")
    llm.reset_circuit_breakers()
    llm.query("sys", "user")
    assert len(calls) == 4
