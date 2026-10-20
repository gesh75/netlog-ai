"""Shared pytest configuration and test fixtures."""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate_incident_store(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure tests run hermetically without polluting ~/.cache/netlog-ai/incidents.jsonl."""
    monkeypatch.delenv("AI_LOG_ANALYZER_INCIDENT_STORE", raising=False)
    monkeypatch.delenv("AI_LOG_ANALYZER_STATE_DB", raising=False)
    monkeypatch.delenv("AI_LOG_ANALYZER_SYSLOG_SPOOL", raising=False)
