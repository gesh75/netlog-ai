"""Pluggable log-source connectors.

Each source implements the `LogSource` Protocol from `base.py` and emits
`LogEvent` instances (defined in `ai_log_analyzer.classifier`). The registry
allows dynamic discovery without modifying core code.

Built-in connectors (each registers itself on import):
  - kibana / elasticsearch  Elasticsearch _search API
  - splunk                  Splunk REST oneshot search
  - loki                    Grafana Loki query_range API
  - syslog                  UDP/TCP syslog listener with ring buffer
  - librenms                LibreNMS REST API eventlog

Custom connectors register themselves with `registry.register(kind, factory)`.
"""
from __future__ import annotations

from ai_log_analyzer.sources.base import (  # noqa: F401
    LogSource,
    SourceConfig,
    SourceError,
    SourceTimeoutError,
    SourceAuthError,
    registry,
)

# Trigger self-registration of all built-in connectors. Import order matters
# only for which alias wins when there are duplicates — currently none.
from ai_log_analyzer.sources import kibana, splunk, loki, syslog, librenms  # noqa: F401,E402

__all__ = [
    "LogSource",
    "SourceConfig",
    "SourceError",
    "SourceTimeoutError",
    "SourceAuthError",
    "registry",
]
