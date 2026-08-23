"""netlog-ai MCP server.

Exposes the analyzer pipeline as MCP tools usable from Claude Code, Cursor,
Continue, or any other MCP-compatible client. Default transport is stdio.

Tools exposed:
  - list_connector_kinds  : enumerate built-in source types
  - list_sources          : registered live sources (with their type/url)
  - add_source            : register a new source from a config dict
  - test_source           : healthcheck a source
  - fetch_logs            : pull raw events from a source
  - search_logs           : pull events filtered by a regex pattern
  - analyze_logs          : pull + classify + dedup + (optional) LLM ranking
  - get_top_offenders     : pull + return the N noisiest hostnames
  - correlate_sources     : cross-source device correlation (confirmed/suspected)
  - analyze_device        : per-device deep triage (verdict, score, process/pattern breakdown)
  - list_sites            : enumerate site bundles available locally
  - analyze_site          : run full site-wide analysis on a bundle

The MCP SDK is an optional dependency — install with
`pip install netlog-ai[mcp]` or `pip install 'mcp>=2,<3'`.
Requires MCP SDK 2.x (MCPServer). See issue #17.
"""
from __future__ import annotations

import logging
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any

from ai_log_analyzer.analyzer import analyze
from ai_log_analyzer.sources import SourceConfig, SourceError, registry
from ai_log_analyzer.sources.manager import manager as source_manager

log = logging.getLogger(__name__)

def _resolve_sites_dir() -> Path:
    """Same resolution order as the web app: env override → packaged data
    (present in pip/Docker installs) → legacy repo-root layout. The old
    repo-root-only lookup made list_sites/analyze_site return empty on any
    `pip install netlog-ai[mcp]` wheel."""
    override = os.environ.get("AI_LOG_ANALYZER_SITES_DIR", "")
    if override:
        return Path(override).expanduser()
    packaged = Path(__file__).resolve().parents[1] / "data" / "sites"
    if packaged.is_dir():
        return packaged
    return Path(__file__).resolve().parents[3] / "sites"


_SITES_DIR = _resolve_sites_dir()


def _mcp_package_version() -> str:
    """Best-effort installed ``mcp`` version.

    SDK 2.x does not set ``mcp.__version__``; fall back to packaging metadata so
    an incompatible-major error can name the version that is actually installed.
    """
    try:
        import mcp as installed
    except ImportError:
        return "unknown"
    ver = getattr(installed, "__version__", None)
    if ver:
        return str(ver)
    try:
        from importlib.metadata import PackageNotFoundError, version
        return version("mcp")
    except PackageNotFoundError:
        return "unknown"


def _build_server():
    """Construct the MCPServer (MCP SDK 2.x). Deferred import so the rest of the
    package works even when the MCP SDK isn't installed.

    MCP SDK 2.0 renamed FastMCP → MCPServer and moved the import path to
    `mcp.server.mcpserver` with no 1.x shim. Dual-major support is not offered:
    this project and mcp 2.x both require Python >=3.10, and a fallback import
    would hide the next API move as a missing dependency again.
    The decorator surface (`@mcp.tool()`) is unchanged.
    """
    try:
        from mcp.server.mcpserver import MCPServer
    except ImportError as exc:
        # Distinguish "SDK absent" from "SDK present but wrong major" so the next
        # break reports itself accurately (issue #17).
        try:
            import mcp as _mcp  # noqa: F401
        except ImportError:
            raise RuntimeError(
                "MCP SDK not installed. Run `pip install 'mcp>=2,<3'` "
                "or `pip install netlog-ai[mcp]`."
            ) from exc
        ver = _mcp_package_version()
        raise RuntimeError(
            f"MCP SDK 2.x required (MCPServer at mcp.server.mcpserver); "
            f"found mcp {ver}. Upgrade with `pip install 'mcp>=2,<3'`."
        ) from exc

    mcp = MCPServer("netlog-ai")

    # ── inventory ────────────────────────────────────────────────────────────
    @mcp.tool()
    def list_connector_kinds() -> dict[str, Any]:
        """List all built-in connector types (kibana, splunk, loki, syslog, librenms)."""
        return {"kinds": registry.known()}

    @mcp.tool()
    def list_sources() -> dict[str, Any]:
        """List registered live log sources with their config (no secrets)."""
        return {"sources": source_manager.describe()}

    @mcp.tool()
    def add_source(
        source_id: str,
        source_type: str,
        url: str,
        api_token: str = "",
        username: str = "",
        password: str = "",
        extra: dict[str, str] | None = None,
        verify_tls: bool = True,
    ) -> dict[str, Any]:
        """Register a new log source. Returns {ok, id}.

        Examples of `extra`:
          - kibana:  {"index_pattern": "network_devices-*"}
          - splunk:  {"search": "index=network"}
          - loki:    {"query": "{job=\"network\"}"}
          - syslog:  {"port": "5514", "proto": "udp"}
        """
        if not registry.is_registered(source_type):
            return {"ok": False, "error": f"unknown source type {source_type!r}",
                    "known": registry.known()}
        cfg = SourceConfig(
            id=source_id,
            type=source_type,
            url=url,
            api_token=api_token,
            username=username,
            password=password,
            extra=dict(extra or {}),
            verify_tls=verify_tls,
        )
        try:
            source_manager.add(cfg)
        except SourceError as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "id": source_id}

    @mcp.tool()
    def test_source(source_id: str) -> dict[str, Any]:
        """Run a healthcheck against a registered source."""
        return source_manager.healthcheck(source_id)

    # ── log retrieval ────────────────────────────────────────────────────────
    @mcp.tool()
    def fetch_logs(
        source_id: str,
        since_seconds: int = 3600,
        limit: int = 500,
        host_filter: str = "",
    ) -> dict[str, Any]:
        """Pull raw events from a source. Default window: last hour, max 500 events."""
        try:
            events = source_manager.fetch(
                source_id,
                since_seconds=since_seconds,
                limit=limit,
                host_filter=host_filter,
            )
        except SourceError as exc:
            return {"ok": False, "error": str(exc)}
        return {
            "ok": True,
            "count": len(events),
            "events": [
                {"timestamp": e.timestamp, "hostname": e.hostname,
                 "appname": e.appname, "severity_raw": e.severity_raw,
                 "message": e.message}
                for e in events
            ],
        }

    @mcp.tool()
    def search_logs(
        source_id: str,
        pattern: str,
        since_seconds: int = 3600,
        limit: int = 1000,
        max_matches: int = 100,
    ) -> dict[str, Any]:
        """Search a source for events whose message matches the regex `pattern`."""
        try:
            rx = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            return {"ok": False, "error": f"bad regex: {exc}"}
        try:
            events = source_manager.fetch(
                source_id, since_seconds=since_seconds, limit=limit, host_filter="",
            )
        except SourceError as exc:
            return {"ok": False, "error": str(exc)}
        matches = [e for e in events if rx.search(e.message)][:max_matches]
        return {
            "ok": True,
            "total_scanned": len(events),
            "match_count": len(matches),
            "matches": [
                {"hostname": e.hostname, "appname": e.appname,
                 "severity_raw": e.severity_raw, "message": e.message}
                for e in matches
            ],
        }

    @mcp.tool()
    def analyze_logs(
        source_id: str,
        since_seconds: int = 3600,
        limit: int = 5000,
        use_llm: bool = False,
    ) -> dict[str, Any]:
        """Fetch + classify + dedup + (optional) LLM ranking. Returns the full
        analyzer payload — same shape as the web UI's /api/analyze."""
        try:
            events = source_manager.fetch(
                source_id, since_seconds=since_seconds, limit=limit, host_filter="",
            )
        except SourceError as exc:
            return {"ok": False, "error": str(exc)}
        if not events:
            return {"ok": True, "count": 0, "result": None,
                    "message": "no events in window"}
        result = analyze(events, use_llm=use_llm)
        return {"ok": True, "count": len(events), "result": result.to_dict()}

    @mcp.tool()
    def get_top_offenders(
        source_id: str,
        since_seconds: int = 3600,
        limit: int = 5000,
        top_n: int = 10,
    ) -> dict[str, Any]:
        """Return the N noisiest hostnames in the time window (event count)."""
        try:
            events = source_manager.fetch(
                source_id, since_seconds=since_seconds, limit=limit, host_filter="",
            )
        except SourceError as exc:
            return {"ok": False, "error": str(exc)}
        counter: Counter[str] = Counter(e.hostname or "unknown" for e in events)
        offenders = [{"hostname": h, "count": n} for h, n in counter.most_common(top_n)]
        return {"ok": True, "total_events": len(events), "offenders": offenders}

    # ── cross-source correlation ─────────────────────────────────────────────
    @mcp.tool()
    def correlate_sources(
        source_ids: list[str] | None = None,
        since_seconds: int = 3600,
        limit: int = 5000,
        min_severity: str = "medium",
    ) -> dict[str, Any]:
        """Cross-source correlation: classify each source's events, then mark
        every device `confirmed` (appears with actionable events in >=2 sources)
        or `suspected` (1 source). Defaults to ALL registered sources."""
        from ai_log_analyzer.correlate import correlate_from_manager
        try:
            return correlate_from_manager(
                source_ids,
                since_seconds=since_seconds,
                limit=limit,
                min_severity=min_severity,
            )
        except Exception as exc:  # noqa: BLE001 - never crash the MCP session
            return {"ok": False, "error": str(exc)}

    # ── per-device triage ────────────────────────────────────────────────────
    @mcp.tool()
    def analyze_device(
        hostname: str,
        source_ids: list[str] | None = None,
        since_seconds: int = 86_400,
        limit: int = 5000,
    ) -> dict[str, Any]:
        """Per-device deep triage: severity histogram, process breakdown,
        frequency-deduped error patterns, a verdict (HARDWARE/ROUTING/LAG/...)
        and a 0-100 health score. Pulls this host's events from the given
        sources (default: all registered)."""
        from ai_log_analyzer.device_triage import triage_from_manager
        try:
            return triage_from_manager(
                hostname, source_ids,
                since_seconds=since_seconds, limit=limit,
            )
        except Exception as exc:  # noqa: BLE001 - never crash the MCP session
            return {"ok": False, "error": str(exc)}

    # ── site bundle helpers ──────────────────────────────────────────────────
    @mcp.tool()
    def list_sites() -> dict[str, Any]:
        """Enumerate site bundles available in the local `sites/` directory."""
        if not _SITES_DIR.is_dir():
            return {"sites": [], "sites_dir": str(_SITES_DIR)}
        import json as _json
        out: list[dict] = []
        for sd in sorted(p for p in _SITES_DIR.iterdir() if p.is_dir()):
            manifest_path = sd / "manifest.json"
            if not manifest_path.is_file():
                continue
            try:
                manifest = _json.loads(manifest_path.read_text(encoding="utf-8"))
            except _json.JSONDecodeError:
                continue
            out.append({
                "id": sd.name,
                "site": manifest.get("site", sd.name.upper()),
                "vendor": manifest.get("vendor", "unknown"),
                "device_count": len(manifest.get("devices", [])),
            })
        return {"sites": out, "sites_dir": str(_SITES_DIR)}

    @mcp.tool()
    def analyze_site(site_id: str) -> dict[str, Any]:
        """Run full site-wide analysis on a local site bundle. Returns
        cross-device findings (BGP, OSPF, MTU, BFD, LLDP gaps + topology hints).

        Note: LLM usage is governed by the server-side LLM toggle, not a per-call
        parameter — same behaviour as the web UI's /api/optimize/site endpoint.
        """
        from ai_log_analyzer.analyzer import analyze_site as _analyze_site
        safe_id = re.sub(r"[^a-zA-Z0-9_\-]", "", site_id)
        site_dir = _SITES_DIR / safe_id
        manifest_path = site_dir / "manifest.json"
        if not manifest_path.is_file():
            return {"ok": False, "error": f"unknown site {site_id!r}",
                    "sites_dir": str(_SITES_DIR)}
        import json as _json
        try:
            manifest = _json.loads(manifest_path.read_text(encoding="utf-8"))
        except _json.JSONDecodeError as exc:
            return {"ok": False, "error": f"bad manifest: {exc}"}
        devices: list[dict] = []
        for d in manifest.get("devices", []):
            fpath = site_dir / d.get("file", "")
            if not fpath.is_file():
                continue
            devices.append({
                "hostname": d.get("hostname", fpath.stem),
                "platform": d.get("platform", "unknown"),
                "function": d.get("function", "unknown"),
                "config_text": fpath.read_text(encoding="utf-8", errors="replace"),
            })
        if not devices:
            return {"ok": False, "error": "no devices loaded from manifest",
                    "manifest_path": str(manifest_path)}
        try:
            result = _analyze_site(safe_id, devices)
            return {"ok": True, "device_count": len(devices), "result": result}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": f"analyze_site failed: {exc}"}

    return mcp


def run(transport: str = "stdio") -> None:
    """Entry point — start the MCP server on the requested transport.

    Auto-loads env-configured sources before serving so the MCP client sees
    them immediately on list_sources().
    """
    try:
        source_manager.load_from_env()
    except Exception:  # noqa: BLE001
        log.exception("failed to load env-configured sources")

    server = _build_server()
    if transport not in {"stdio", "streamable-http"}:
        raise ValueError(f"Unsupported transport: {transport!r}")
    if transport == "stdio":
        server.run()
    else:
        server.run(transport=transport)


if __name__ == "__main__":
    transport_env = os.environ.get("NETLOG_MCP_TRANSPORT", "stdio")
    run(transport=transport_env)
