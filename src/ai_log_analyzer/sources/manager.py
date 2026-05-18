"""SourceManager — thread-safe holder for live `LogSource` instances.

The Flask app and the MCP server both use this so a connector (e.g. a syslog
UDP listener) survives across requests instead of being torn down each time.

Sources are configured via environment variables with the NETLOG_SOURCE_*
prefix. Example:

    NETLOG_SOURCE_kibana1_TYPE=kibana
    NETLOG_SOURCE_kibana1_URL=https://es.example.com:9200
    NETLOG_SOURCE_kibana1_API_TOKEN=...
    NETLOG_SOURCE_kibana1_INDEX_PATTERN=network_devices-*

Or programmatically via `manager.add(SourceConfig(...))`.
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Iterable

from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.sources.base import LogSource, SourceConfig, SourceError, registry

log = logging.getLogger(__name__)

_ENV_PREFIX = "NETLOG_SOURCE_"


class SourceManager:
    """Holds live `LogSource` instances keyed by source id."""

    def __init__(self) -> None:
        self._sources: dict[str, LogSource] = {}
        self._configs: dict[str, SourceConfig] = {}
        self._lock = threading.Lock()

    # ── lifecycle ────────────────────────────────────────────────────────────
    def add(self, config: SourceConfig) -> LogSource:
        with self._lock:
            if config.id in self._sources:
                self._sources[config.id].close()
            src = registry.create(config)
            self._sources[config.id] = src
            self._configs[config.id] = config
            log.info("source %s (%s) added", config.id, config.type)
            return src

    def remove(self, source_id: str) -> bool:
        with self._lock:
            src = self._sources.pop(source_id, None)
            self._configs.pop(source_id, None)
        if src is not None:
            try:
                src.close()
            except Exception:  # noqa: BLE001
                log.exception("error closing source %s", source_id)
            return True
        return False

    def shutdown(self) -> None:
        with self._lock:
            sources = list(self._sources.values())
            self._sources.clear()
            self._configs.clear()
        for s in sources:
            try:
                s.close()
            except Exception:  # noqa: BLE001
                log.exception("error during shutdown of %s", s.name)

    # ── inspection ───────────────────────────────────────────────────────────
    def list_ids(self) -> list[str]:
        with self._lock:
            return sorted(self._sources)

    def get(self, source_id: str) -> LogSource | None:
        with self._lock:
            return self._sources.get(source_id)

    def describe(self) -> list[dict]:
        with self._lock:
            return [
                {
                    "id": cfg.id,
                    "type": cfg.type,
                    "url": cfg.url,
                    "auth_methods": list(cfg.auth_methods),
                    "extra": dict(cfg.extra),
                }
                for cfg in self._configs.values()
            ]

    def known_kinds(self) -> list[str]:
        return registry.known()

    # ── ops ──────────────────────────────────────────────────────────────────
    def healthcheck(self, source_id: str) -> dict:
        src = self.get(source_id)
        if src is None:
            return {"ok": False, "error": f"unknown source {source_id!r}"}
        try:
            return {"ok": bool(src.healthcheck())}
        except SourceError as exc:
            return {"ok": False, "error": str(exc)}

    def fetch(self, source_id: str, *, since_seconds: int = 3600,
              limit: int = 10_000, host_filter: str = "") -> list[LogEvent]:
        src = self.get(source_id)
        if src is None:
            raise SourceError(f"unknown source {source_id!r}")
        return list(src.fetch(since_seconds=since_seconds, limit=limit,
                              host_filter=host_filter))

    # ── env bootstrap ────────────────────────────────────────────────────────
    def load_from_env(self) -> list[str]:
        """Scan NETLOG_SOURCE_<id>_<KEY>=value env vars and register every source
        that has a TYPE+URL pair. Returns list of ids successfully added."""
        groups: dict[str, dict[str, str]] = {}
        for key, value in os.environ.items():
            if not key.startswith(_ENV_PREFIX) or not value:
                continue
            stripped = key[len(_ENV_PREFIX):]
            if "_" not in stripped:
                continue
            src_id, field = stripped.split("_", 1)
            groups.setdefault(src_id, {})[field.lower()] = value

        added: list[str] = []
        for src_id, fields in groups.items():
            stype = fields.pop("type", "")
            url = fields.pop("url", "")
            if not stype or not url:
                continue
            auth_methods = tuple(
                m.strip() for m in fields.pop("auth_methods", "api_token,basic,cookie").split(",")
                if m.strip()
            )
            cookies_raw = fields.pop("cookies", "")
            cookies = {}
            for pair in cookies_raw.split(";"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    cookies[k.strip()] = v.strip()
            cfg = SourceConfig(
                id=src_id,
                type=stype,
                url=url,
                auth_methods=auth_methods,
                api_token=fields.pop("api_token", ""),
                username=fields.pop("username", ""),
                password=fields.pop("password", ""),
                cookies=cookies,
                extra={k: v for k, v in fields.items() if v},
                verify_tls=fields.get("verify_tls", "true").lower() != "false",
                timeout_seconds=float(fields.get("timeout_seconds", "30")),
            )
            try:
                self.add(cfg)
                added.append(src_id)
            except Exception as exc:  # noqa: BLE001
                log.warning("failed to add env-configured source %s: %s", src_id, exc)
        return added


# Module-level singleton used by both Flask + MCP server
manager = SourceManager()
