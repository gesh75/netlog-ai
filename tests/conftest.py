"""Shared pytest configuration and test fixtures."""
from __future__ import annotations

import pytest

_HERMETIC_ENV = (
    "AI_LOG_ANALYZER_INCIDENT_STORE",
    "AI_LOG_ANALYZER_STATE_DB",
    "AI_LOG_ANALYZER_SYSLOG_SPOOL",
    "AI_LOG_ANALYZER_RAG_DB",
    "AI_LOG_ANALYZER_RAG",
    "AI_LOG_ANALYZER_AUDIT_DB",
    "AI_LOG_ANALYZER_AUDIT_LLM",
    "AI_LOG_ANALYZER_RBAC_FILE",
    "AI_LOG_ANALYZER_VIEWER_TOKENS",
    "AI_LOG_ANALYZER_OPERATOR_TOKENS",
    "AI_LOG_ANALYZER_ADMIN_TOKENS",
    "AI_LOG_ANALYZER_TRIAGE_WORKER",
    "AI_LOG_ANALYZER_TRIAGE_SINKS",
    "AI_LOG_ANALYZER_GOLDEN_DIR",
)


@pytest.fixture(autouse=True)
def _isolate_incident_store(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure tests run hermetically: no incident journal, shared state DB,
    retrieval index, audit log, RBAC principals or triage worker from the
    developer's environment leaks into a test."""
    for name in _HERMETIC_ENV:
        monkeypatch.delenv(name, raising=False)
