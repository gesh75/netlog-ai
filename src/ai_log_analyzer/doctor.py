"""``ai-log-analyzer doctor`` — a quick local self-check: no network calls, no secrets printed.

Checks the Python version, required and optional packages, that the configured
state / index / audit stores are writable, and that the environment is sane
(numeric settings parse, a cloud LLM provider has its key, an externally bound
web UI has an API token). Each check is ``{"name", "status", "detail"}`` with
status ``ok`` | ``info`` (optional, not configured) | ``warn`` | ``fail``;
the command exits 1 only when something ``fail``s.
"""
from __future__ import annotations

import importlib.util
import os
import sqlite3
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

_REQUIRED = {"flask": "flask", "flask_cors": "flask-cors", "requests": "requests",
             "dotenv": "python-dotenv", "regex": "regex"}
_OPTIONAL = {"gunicorn": ("gunicorn", "production serving"), "mcp": ("netlog-ai[mcp]", "the MCP server"),
             "textfsm": ("netlog-ai[parse]", "TextFSM parsing"), "ntc_templates": ("netlog-ai[parse]", "ntc-templates parsing"),
             "yaml": ("pyyaml", "running the test-suite / reading YAML exports")}
_STORES = ("AI_LOG_ANALYZER_STATE_DB", "AI_LOG_ANALYZER_RAG_DB", "AI_LOG_ANALYZER_AUDIT_DB",
           "AI_LOG_ANALYZER_INCIDENT_STORE", "AI_LOG_ANALYZER_TEMPLATE_STORE")
_DIRS = ("AI_LOG_ANALYZER_SITES_DIR", "AI_LOG_ANALYZER_SAMPLES_DIR", "AI_LOG_ANALYZER_GOLDEN_DIR")
_PROVIDERS = {"ollama", "local", "claude", "claude-only", "grok"}


def _c(name: str, status: str, detail: str) -> dict[str, str]:
    return {"name": name, "status": status, "detail": detail}


def _check_store(var: str, raw: str) -> dict[str, str]:
    path = Path(raw).expanduser()
    if path.is_dir():
        return _c(var, "fail", f"{path} is a directory, expected a file path")
    if path.exists():
        if not os.access(path, os.W_OK):
            return _c(var, "fail", f"{path} exists but is not writable by this user")
        if path.suffix in (".db", ".sqlite", ".sqlite3"):
            try:   # take and release the write lock without changing anything
                conn = sqlite3.connect(str(path), timeout=2)
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    conn.execute("ROLLBACK")
                finally:
                    conn.close()
            except sqlite3.Error as exc:
                return _c(var, "fail", f"{path} cannot be opened for writing: {exc}")
        return _c(var, "ok", f"{path} is writable")
    parent = path.parent
    if not parent.is_dir():
        return _c(var, "fail", f"{path} does not exist and its directory {parent} is missing")
    if not os.access(parent, os.W_OK):
        return _c(var, "fail", f"{path} does not exist and {parent} is not writable")
    return _c(var, "ok", f"{path} will be created on first use")


def run_checks(env: Mapping[str, str] | None = None) -> list[dict[str, str]]:
    env = os.environ if env is None else env
    out: list[dict[str, str]] = []
    ver = ".".join(map(str, sys.version_info[:3]))
    out.append(_c("python", "ok" if sys.version_info >= (3, 10) else "fail",
                  f"Python {ver}" + ("" if sys.version_info >= (3, 10) else " — 3.10 or newer is required")))
    for mod, dist in _REQUIRED.items():
        found = importlib.util.find_spec(mod) is not None
        out.append(_c(f"package:{dist}", "ok" if found else "fail",
                      "installed" if found else f"missing — pip install {dist}"))
    for mod, (dist, why) in _OPTIONAL.items():
        found = importlib.util.find_spec(mod) is not None
        out.append(_c(f"optional:{mod}", "ok" if found else "info",
                      "installed" if found else f"not installed (needed for {why}: pip install '{dist}')"))

    for var in _STORES:
        raw = (env.get(var) or "").strip()
        out.append(_check_store(var, raw) if raw else _c(var, "info", "not configured (feature uses in-memory or is off)"))
    for var in _DIRS:
        raw = (env.get(var) or "").strip()
        if raw:
            out.append(_c(var, "ok" if Path(raw).expanduser().is_dir() else "fail",
                          f"{raw}" + ("" if Path(raw).expanduser().is_dir() else " is not a directory")))

    port = (env.get("ANALYZER_PORT") or "6060").strip()
    out.append(_c("ANALYZER_PORT", "ok" if port.isdigit() and 0 < int(port) < 65536 else "fail",
                  port if port.isdigit() and 0 < int(port) < 65536 else f"{port!r} is not a valid TCP port"))
    host = (env.get("ANALYZER_HOST") or "127.0.0.1").strip()
    token = bool((env.get("AI_LOG_ANALYZER_API_TOKEN") or "").strip() or (env.get("AI_LOG_ANALYZER_RBAC_FILE") or "").strip())
    if host in ("127.0.0.1", "localhost", "::1"):
        out.append(_c("ANALYZER_HOST", "ok", f"{host} (loopback only)"))
    elif token:
        out.append(_c("ANALYZER_HOST", "ok", f"{host} with API token / RBAC configured"))
    else:
        out.append(_c("ANALYZER_HOST", "warn", f"{host} is externally reachable but no AI_LOG_ANALYZER_API_TOKEN "
                                               "or RBAC file is set: every route is unauthenticated"))

    provider = (env.get("LLM_PROVIDER") or "ollama").strip().lower()
    if provider not in _PROVIDERS:
        out.append(_c("LLM_PROVIDER", "fail", f"{provider!r} is not one of {sorted(_PROVIDERS)}"))
    else:
        key_var = {"claude": "ANTHROPIC_API_KEY", "claude-only": "ANTHROPIC_API_KEY", "grok": "XAI_API_KEY"}.get(provider)
        if key_var and not (env.get(key_var) or "").strip():
            out.append(_c("LLM_PROVIDER", "fail", f"{provider} selected but {key_var} is not set"))
        else:
            out.append(_c("LLM_PROVIDER", "ok", provider + (f" ({key_var} is set)" if key_var else "")))
    for var in ("LLM_TIMEOUT", "LLM_MAX_RETRIES", "AI_LOG_ANALYZER_RAG_REFRESH_SECONDS", "OLLAMA_NUM_CTX"):
        raw = (env.get(var) or "").strip()
        if raw:
            try:
                float(raw)
            except ValueError:
                out.append(_c(var, "fail", f"{raw!r} is not a number"))
    for var in ("SERVICENOW_URL", "SNOW_URL", "JIRA_URL"):
        raw = (env.get(var) or "").strip()
        if raw and not raw.lower().startswith("https://"):
            out.append(_c(var, "warn", "not an https:// URL: credentials would travel unencrypted"))
    return out


def summarize(checks: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"ok": 0, "info": 0, "warn": 0, "fail": 0}
    for c in checks:
        counts[c["status"]] = counts.get(c["status"], 0) + 1
    return counts
