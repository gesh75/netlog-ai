"""Pluggable LLM client with three providers:

  - "ollama"      : Ollama native API (gemma3 / qwen2.5-coder / llama3.2) — preferred local
  - "local"       : Docker Model Runner (OpenAI-compatible) via TCP or Unix socket
  - "claude"      : Anthropic Claude direct API
  - "claude-only" : Claude only (never call local)

Provider is selectable at runtime via set_provider() — used by /api/llm/provider.
Always returns either a cleaned string or None (caller falls back to rule-based KB).
"""
from __future__ import annotations

import json
import os
import re
import socket
import time
from collections.abc import Callable
from typing import Optional

import requests

# Single shared HTTP session — connection pooling reduces per-call overhead
_SESSION = requests.Session()

# Probe cache — provider availability rarely changes within a second; reuse
# results so /api/llm/status doesn't probe Ollama/DMR/Claude every poll.
_PROBE_TTL: float = 10.0
_probe_cache: dict[str, tuple[float, bool]] = {}


def _cached_probe(name: str, fn: Callable[[], bool]) -> bool:
    now = time.monotonic()
    cached = _probe_cache.get(name)
    if cached and now - cached[0] < _PROBE_TTL:
        return cached[1]
    ok = bool(fn())
    _probe_cache[name] = (now, ok)
    return ok

# ── Config (env-driven, mutable at runtime via set_provider) ──────────────────
_state: dict[str, object] = {
    # ollama | local | claude | claude-only
    "provider":           os.environ.get("LLM_PROVIDER", "ollama").lower(),
    "enabled":            os.environ.get("LLM_ENABLED", "true").lower() == "true",
    # Ollama (native API)
    "ollama_url":         os.environ.get("OLLAMA_URL", "http://localhost:11434"),
    "ollama_model":       os.environ.get("OLLAMA_MODEL", "gemma4:latest"),
    # Docker Model Runner (OpenAI-compatible)
    "local_url":          os.environ.get("MODEL_RUNNER_URL", "http://localhost:12434"),
    "local_model":        os.environ.get("LLM_MODEL", "ai/qwen3:latest"),
    # Anthropic
    "anthropic_api_key":  os.environ.get("ANTHROPIC_API_KEY", ""),
    "anthropic_model":    os.environ.get("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001"),
    "timeout":            int(os.environ.get("LLM_TIMEOUT", "120")),
    # Last error per provider — exposed via /api/llm/status for the UI
    "last_errors":        {},
}

_VALID_PROVIDERS = {"ollama", "local", "claude", "claude-only"}

# Unix sockets for Docker Model Runner (auto-discovered)
_DOCKER_SOCKETS: list[str] = [
    os.path.expanduser("~/Library/Containers/com.docker.docker/Data/inference.sock"),
    os.path.expanduser("~/Library/Containers/com.docker.docker/Data/inference-0.sock"),
    "/run/docker-model-runner/inference.sock",
    os.path.expanduser("~/.docker/desktop/inference.sock"),
]


def is_enabled() -> bool:
    """Fast enabled check — no provider probing. Use in hot paths."""
    return bool(_state.get("enabled", False))


def get_state() -> dict[str, object]:
    """Snapshot of current LLM state — safe to expose via /api/llm/status."""
    return {
        "provider":            _state["provider"],
        "enabled":             _state["enabled"],
        "ollama_model":        _state["ollama_model"],
        "local_model":         _state["local_model"],
        "anthropic_model":     _state["anthropic_model"],
        "anthropic_key_set":   bool(_state["anthropic_api_key"]),
        "providers_available": _list_available_providers(),
        "last_errors":         dict(_state.get("last_errors", {})),
    }


def _record_error(provider: str, msg: str) -> None:
    errors = _state.setdefault("last_errors", {})
    if isinstance(errors, dict):
        errors[provider] = msg[:300]


def _clear_error(provider: str) -> None:
    errors = _state.get("last_errors")
    if isinstance(errors, dict):
        errors.pop(provider, None)


def set_provider(provider: str) -> tuple[bool, str]:
    """Change provider at runtime. Returns (ok, message)."""
    p = provider.lower().strip()
    if p not in _VALID_PROVIDERS:
        return False, f"provider must be one of: {sorted(_VALID_PROVIDERS)}"
    if p in ("claude", "claude-only") and not _state["anthropic_api_key"]:
        return False, "ANTHROPIC_API_KEY not configured — cannot select claude provider"
    _state["provider"] = p
    return True, p


def set_enabled(enabled: bool) -> bool:
    _state["enabled"] = bool(enabled)
    return _state["enabled"]


def query(system_prompt: str, user_prompt: str, max_tokens: int = 800) -> Optional[str]:
    """Run an LLM query honoring the configured provider. Returns text or None on full failure.

    Fallback chain when primary provider fails:
      ollama   → docker-runner → claude (if key set)
      local    → ollama        → claude (if key set)
      claude   → ollama        → docker-runner
      claude-only → claude only (no fallback)
    """
    if not _state["enabled"]:
        return None

    provider = _state["provider"]

    if provider == "claude-only":
        return _query_claude(system_prompt, user_prompt, max_tokens)

    order: list[str]
    if provider == "ollama":
        order = ["ollama", "local", "claude"]
    elif provider == "local":
        order = ["local", "ollama", "claude"]
    elif provider == "claude":
        order = ["claude", "ollama", "local"]
    else:
        order = ["ollama", "local", "claude"]

    for name in order:
        text = _PROVIDERS[name](system_prompt, user_prompt, max_tokens)
        if text:
            return text
    return None


# ── Ollama native API ────────────────────────────────────────────────────────

def _query_ollama(system_prompt: str, user_prompt: str, max_tokens: int) -> Optional[str]:
    """Ollama native /api/chat — supports `think:false` for gemma4/qwen3."""
    url = f"{str(_state['ollama_url']).rstrip('/')}/api/chat"
    payload = {
        "model": _state["ollama_model"],
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "options": {"temperature": 0.2, "num_predict": max_tokens},
        "stream": False,
        "think": False,
    }
    try:
        r = _SESSION.post(url, json=payload, timeout=int(_state["timeout"]))
        if r.status_code != 200:
            _record_error("ollama", f"HTTP {r.status_code}: {r.text[:200]}")
            return None
        msg = r.json().get("message", {})
        text = (msg.get("content") or "").strip()
        if text:
            _clear_error("ollama")
            return _clean(text)
        _record_error("ollama", "Empty response from Ollama")
        return None
    except requests.Timeout:
        _record_error("ollama", f"Timeout after {_state['timeout']}s — model loading or busy?")
        return None
    except requests.RequestException as e:
        _record_error("ollama", f"Connection error: {e}")
        return None


# ── Anthropic Claude ─────────────────────────────────────────────────────────

def _query_claude(system_prompt: str, user_prompt: str, max_tokens: int) -> Optional[str]:
    api_key = str(_state["anthropic_api_key"])
    if not api_key:
        _record_error("claude", "ANTHROPIC_API_KEY not configured")
        return None
    try:
        r = _SESSION.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": _state["anthropic_model"],
                "max_tokens": max_tokens,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}],
            },
            timeout=int(_state["timeout"]),
        )
        if r.status_code != 200:
            _record_error("claude", f"HTTP {r.status_code}: {r.text[:200]}")
            return None
        text = r.json()["content"][0].get("text", "").strip()
        if text:
            _clear_error("claude")
            return _clean(text)
        _record_error("claude", "Empty content in Claude response")
        return None
    except requests.Timeout:
        _record_error("claude", f"Timeout after {_state['timeout']}s")
        return None
    except requests.RequestException as e:
        _record_error("claude", f"Connection error: {e}")
        return None


# ── Docker Model Runner (TCP + Unix socket) ──────────────────────────────────

def _query_docker_runner(system_prompt: str, user_prompt: str, max_tokens: int) -> Optional[str]:
    payload = {
        "model": _state["local_model"],
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "max_tokens": max_tokens,
        "temperature": 0.2,
        "stream": False,
        "enable_thinking": False,
    }
    api_paths = ["/engines/llama.cpp/v1/chat/completions", "/v1/chat/completions"]

    base = str(_state["local_url"]).rstrip("/")
    if base:
        for path in api_paths:
            try:
                r = _SESSION.post(f"{base}{path}", json=payload, timeout=int(_state["timeout"]))
                if r.status_code == 200:
                    text = _extract_openai_text(r.json())
                    if text:
                        return text
            except requests.RequestException:
                continue

    for sock_path in _DOCKER_SOCKETS:
        if not os.path.exists(sock_path):
            continue
        for path in api_paths:
            text = _query_unix_socket(sock_path, path, payload)
            if text:
                return text
    return None


def _query_unix_socket(sock_path: str, api_path: str, payload: dict) -> Optional[str]:
    body = json.dumps(payload).encode()
    req = (
        f"POST {api_path} HTTP/1.1\r\n"
        f"Host: localhost\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(int(_state["timeout"]))
        s.connect(sock_path)
        s.sendall(req)
        chunks: list[bytes] = []
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        s.close()
        resp = b"".join(chunks)
        if b"\r\n\r\n" not in resp:
            return None
        body_bytes = resp.split(b"\r\n\r\n", 1)[1]
        if b"Transfer-Encoding: chunked" in resp:
            lines = body_bytes.split(b"\r\n")
            body_bytes = b"".join(
                l for l in lines if l and not all(c in b"0123456789abcdefABCDEF" for c in l)
            )
        data = json.loads(body_bytes.strip())
        return _extract_openai_text(data)
    except (OSError, json.JSONDecodeError):
        return None


def _extract_openai_text(data: dict) -> Optional[str]:
    choices = data.get("choices")
    if not choices or not isinstance(choices, list):
        return None
    msg = choices[0].get("message", {})
    raw = (msg.get("content") or msg.get("reasoning_content") or "").strip()
    return _clean(raw) if raw else None


# ── Output cleaning (strip <think> blocks, reasoning preambles) ──────────────

_THINK_RE = re.compile(r"<think>[\s\S]*?</think>", re.IGNORECASE)
_PREAMBLE_RE = re.compile(
    r"^(Okay|Ok|Alright|Sure|Let me|I'll|I will|I need|I should|"
    r"The user|Looking at|Based on|First|Now|Here|So|Hmm|Wait|Right|"
    r"Let's|This is|These are|From the)",
    re.IGNORECASE,
)


def _clean(text: str) -> str:
    if not text:
        return text
    s = _THINK_RE.sub("", text)
    lines = s.split("\n")
    cleaned: list[str] = []
    past_preamble = False
    for line in lines:
        stripped = line.strip()
        if not past_preamble:
            if not stripped:
                continue
            if _PREAMBLE_RE.match(stripped) and not cleaned:
                continue
            past_preamble = True
        cleaned.append(line)
    return "\n".join(cleaned).strip() or text.strip()


# ── Provider availability probing (for UI badges) ────────────────────────────

def _probe_ollama() -> bool:
    try:
        r = _SESSION.get(f"{str(_state['ollama_url']).rstrip('/')}/api/tags", timeout=2)
        return r.status_code == 200
    except requests.RequestException:
        return False


def _probe_docker_runner() -> bool:
    try:
        r = _SESSION.get(f"{str(_state['local_url']).rstrip('/')}/v1/models", timeout=2)
        if r.status_code == 200:
            return True
    except requests.RequestException:
        pass
    return any(os.path.exists(p) for p in _DOCKER_SOCKETS)


def _list_available_providers() -> list[dict]:
    return [
        {"id": "ollama", "available": _cached_probe("ollama", _probe_ollama),
         "model": _state["ollama_model"]},
        {"id": "local",  "available": _cached_probe("local",  _probe_docker_runner),
         "model": _state["local_model"]},
        {"id": "claude", "available": bool(_state["anthropic_api_key"]),
         "model": _state["anthropic_model"]},
    ]


# Registry — declared after the functions are defined
_PROVIDERS: dict[str, Callable[[str, str, int], Optional[str]]] = {
    "ollama": _query_ollama,
    "local":  _query_docker_runner,
    "claude": _query_claude,
}
