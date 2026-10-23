"""Safe defaults that must not regress: opt-in docker-exec fallback, pinned CDN script versions."""
from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "ai_log_analyzer"


@pytest.mark.unit
def test_docker_exec_fallback_is_opt_in(monkeypatch):
    from ai_log_analyzer.adapters import network_tool
    monkeypatch.delenv("DOCKER_EXEC_FALLBACK", raising=False)
    try:
        assert importlib.reload(network_tool).DOCKER_EXEC_FALLBACK is False
        monkeypatch.setenv("DOCKER_EXEC_FALLBACK", "true")
        assert importlib.reload(network_tool).DOCKER_EXEC_FALLBACK is True
    finally:
        monkeypatch.delenv("DOCKER_EXEC_FALLBACK", raising=False)
        importlib.reload(network_tool)


@pytest.mark.unit
def test_cdn_scripts_are_pinned_to_an_exact_version():
    for name in ("reports.py", "site_doc.py"):
        for tag in re.findall(r'<script[^>]+cdn\.jsdelivr\.net[^>]*>', (SRC / name).read_text(encoding="utf-8")):
            assert re.search(r"@\d+\.\d+\.\d+/", tag), (name, tag)
            assert 'crossorigin="anonymous"' in tag, (name, tag)
