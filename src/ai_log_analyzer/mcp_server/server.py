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
  - analyze_evpn_causality: bipartite underlay/overlay causal inference for a site
  - generate_remediation_plan : vendor-safe change plan with rollback timer
  - enrich_itsm_incident  : two-way Jira / ServiceNow enrichment
  - fetch_solarwinds_logs : SolarWinds syslog / OLM / SaaS logs (read-only)
  - fetch_solarwinds_alerts : SolarWinds active alerts (read-only)
  - push_solarwinds_alert_note : explicit Orion.AlertActive/AppendNote writeback
  - netlog_deep_analytics : flap physics and topology blast radius
  - netlog_servicenow_correlate_changes : score change records against findings
  - netlog_servicenow_sync_incident : dry-run or upsert one ServiceNow incident

The MCP SDK is an optional dependency — install with
`pip install netlog-ai[mcp]` or `pip install 'mcp>=2,<3'`.
Requires MCP SDK 2.x (MCPServer). See issue #17.
"""
from __future__ import annotations

import json
import logging
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any

from ai_log_analyzer.analyzer import analyze
from ai_log_analyzer.deep_report import load_site_topology, run_deep_report
from ai_log_analyzer.servicenow_sync import ServiceNowClient
from ai_log_analyzer.sources import SourceConfig, SourceError, registry
from ai_log_analyzer.sources.manager import manager as source_manager
from ai_log_analyzer.sources.solarwinds import SolarWindsConnector

log = logging.getLogger(__name__)


def _plan_export(plan: Any, export: str) -> dict[str, Any]:
    """Optional Ansible / Nornir export block for remediation tool results."""
    fmt = (export or "").strip().lower()
    if not fmt:
        return {}
    from ai_log_analyzer.remediation import SafetyViolationError
    from ai_log_analyzer.remediation_export import ExportUnsupportedError, export_plan
    try:
        return {"export": {"format": fmt, "content": export_plan(plan, fmt)}}
    except (ExportUnsupportedError, SafetyViolationError) as exc:
        return {"export": {"format": fmt, "error": str(exc)}}


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


def _solarwinds_connector(source_id: str = "") -> SolarWindsConnector:
    """Resolve a live SolarWinds connector by id, kind, or SOLARWINDS_* env."""
    if source_id:
        src = source_manager.get(source_id)
        if src is None:
            raise SourceError(f"unknown source {source_id!r}")
        if getattr(src, "kind", None) != "solarwinds":
            raise SourceError(
                f"source {source_id!r} is not solarwinds "
                f"(got {getattr(src, 'kind', None)!r})"
            )
        return src  # type: ignore[return-value]
    for sid in source_manager.list_ids():
        src = source_manager.get(sid)
        if getattr(src, "kind", None) == "solarwinds":
            return src  # type: ignore[return-value]
    return SolarWindsConnector.from_env()


def _mcp_package_version() -> str | None:
    """Best-effort installed ``mcp`` version.

    Returns ``None`` when the distribution is not importable (absent SDK).
    SDK 2.x does not set ``mcp.__version__``; fall back to packaging metadata
    so an incompatible-major error can name the version that is actually
    installed.
    """
    try:
        import mcp as installed
    except ImportError:
        return None
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
        ver = _mcp_package_version()
        if ver is None:
            raise RuntimeError(
                "MCP SDK not installed. Run `pip install 'mcp>=2,<3'` "
                "or `pip install 'netlog-ai[mcp]'`."
            ) from exc
        raise RuntimeError(
            f"MCP SDK 2.x required (MCPServer at mcp.server.mcpserver); "
            f"found mcp {ver}. Upgrade with `pip install 'mcp>=2,<3'`."
        ) from exc

    mcp = MCPServer("netlog-ai")

    # ── inventory ────────────────────────────────────────────────────────────
    @mcp.tool()
    def list_connector_kinds() -> dict[str, Any]:
        """List all built-in connector types (kibana, splunk, loki, syslog, librenms, solarwinds)."""
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
          - solarwinds: {"mode": "swis"}
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
        except Exception as exc:
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
        except Exception as exc:
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
        except Exception as exc:
            return {"ok": False, "error": f"analyze_site failed: {exc}"}

    @mcp.tool()
    def analyze_evpn_causality(site_name: str) -> dict[str, Any]:
        """Analyze bipartite EVPN causality across underlay and overlay for a site.

        Loads manifest.json from the site bundle, parses device syslog lines,
        runs EVPNBipartiteCausalEngine.analyze(), and returns root cause +
        suppressed overlay symptoms.
        """
        import json as _json

        from ai_log_analyzer.adapters.file import parse_file
        from ai_log_analyzer.evpn_causal import EVPNBipartiteCausalEngine

        safe_id = re.sub(r"[^a-zA-Z0-9_\-]", "", site_name)
        site_dir = _SITES_DIR / safe_id
        manifest_path = site_dir / "manifest.json"
        if not manifest_path.is_file():
            return {"ok": False, "error": f"unknown site {site_name!r}", "sites_dir": str(_SITES_DIR)}

        try:
            manifest = _json.loads(manifest_path.read_text(encoding="utf-8"))
        except _json.JSONDecodeError as exc:
            return {"ok": False, "error": f"bad manifest: {exc}"}

        events: list[Any] = []
        for d in manifest.get("devices", []):
            fpath = site_dir / d.get("file", "")
            if fpath.is_file():
                try:
                    events.extend(parse_file(fpath))
                except Exception:
                    pass

        engine = EVPNBipartiteCausalEngine.from_site_manifest(manifest)
        hypotheses = engine.analyze(events)

        root_causes = []
        for h in hypotheses:
            rc_data = {
                "event_id": h.root_cause.event_id,
                "timestamp": h.root_cause.timestamp.isoformat() if hasattr(h.root_cause.timestamp, "isoformat") else str(h.root_cause.timestamp),
                "device": h.root_cause.device,
                "layer": h.root_cause.layer.name if hasattr(h.root_cause.layer, "name") else str(h.root_cause.layer),
                "summary": h.root_cause.summary,
                "raw_message": h.root_cause.raw_message,
                "interface": h.root_cause.interface,
                "vni": h.root_cause.vni,
            }
            symptoms_data = [
                {
                    "event_id": s.event_id,
                    "timestamp": s.timestamp.isoformat() if hasattr(s.timestamp, "isoformat") else str(s.timestamp),
                    "device": s.device,
                    "layer": s.layer.name if hasattr(s.layer, "name") else str(s.layer),
                    "summary": s.summary,
                    "raw_message": s.raw_message,
                    "interface": s.interface,
                    "vni": s.vni,
                }
                for s in h.suppressed_symptoms
            ]
            root_causes.append({
                "root_cause": rc_data,
                "suppressed_symptoms": symptoms_data,
                "affected_devices": sorted(list(h.affected_devices)),
                "affected_vnis": sorted(list(h.affected_vnis)),
                "confidence": h.confidence,
                "rationale": h.rationale,
                "symptom_suppression_ratio": h.symptom_suppression_ratio,
            })

        return {
            "ok": True,
            "site": manifest.get("site", safe_id),
            "hypothesis_count": len(hypotheses),
            "hypotheses": root_causes,
            "root_cause": root_causes[0]["root_cause"] if root_causes else None,
            "suppressed_symptoms": root_causes[0]["suppressed_symptoms"] if root_causes else [],
            "cytoscape_elements": [el for h in hypotheses for el in h.to_cytoscape_elements()],
        }

    # ── remediation & itsm ───────────────────────────────────────────────────
    @mcp.tool()
    def generate_remediation_plan(
        device: str,
        vendor: str,
        action: str = "drain",
        interface: str = "Ethernet1",
        bgp_neighbor_ip: str = "",
        commands: list[str] | None = None,
        pre_checks: list[str] | None = None,
        post_checks: list[str] | None = None,
        rollback_minutes: int = 5,
        rationale: str = "",
        export: str = "",
    ) -> dict[str, Any]:
        """Generate vendor-safe configuration change plan with rollback guardrails.

        Supported vendors: 'arista_eos', 'juniper_junos', 'cisco_nxos', 'cisco_ios', 'frr',
        'fortinet_fortios', 'paloalto_panos', 'cisco_sdwan'.
        Supported actions: 'drain' (graceful link drain), 'copp' (control-plane QoS boost), 'custom'.
        export: '' | 'ansible' | 'nornir' — also return a ready-to-run playbook / script
        (dry-run diff task first, rollback in a rescue block; screened by SafetyGuardrail).
        """
        from ai_log_analyzer.remediation import (
            RemediationActionType,
            RemediationGenerator,
            SafetyViolationError,
            VendorOS,
        )

        try:
            vendor_os = VendorOS(vendor.lower().strip())
        except ValueError:
            return {
                "ok": False,
                "error": f"Unsupported vendor OS: {vendor!r}",
                "valid_vendors": [v.value for v in VendorOS],
            }

        gen = RemediationGenerator(default_rollback_minutes=rollback_minutes)
        act = action.lower().strip()
        try:
            if act in ("drain", RemediationActionType.GRACEFUL_LINK_DRAIN.value):
                plan = gen.build_graceful_link_drain(
                    device=device,
                    vendor=vendor_os,
                    interface=interface,
                    bgp_neighbor_ip=bgp_neighbor_ip or None,
                    rollback_minutes=rollback_minutes,
                    rationale=rationale or "Drain traffic gracefully prior to physical maintenance.",
                )
            elif act in ("copp", "qos", RemediationActionType.QOS_COPP_CONTROL_PLANE_BOOST.value):
                plan = gen.build_qos_copp_remediation(
                    device=device,
                    vendor=vendor_os,
                    interface=interface,
                    rollback_minutes=rollback_minutes,
                    rationale=rationale or "Prioritize BFD/BGP control plane traffic.",
                )
            elif act in ("custom", RemediationActionType.CUSTOM_SAFE_CONFIG.value):
                if not commands:
                    return {"ok": False, "error": "commands list required for custom action"}
                plan = gen.build_custom_safe_plan(
                    device=device,
                    vendor=vendor_os,
                    commands=commands,
                    pre_checks=pre_checks or [],
                    post_checks=post_checks or [],
                    rationale=rationale or "Custom safe configuration plan.",
                    rollback_minutes=rollback_minutes,
                )
            else:
                return {"ok": False, "error": f"Unsupported action {action!r}"}
        except SafetyViolationError as exc:
            return {"ok": False, "error": f"Safety violation: {exc}"}

        return {
            "ok": True,
            "plan_id": plan.plan_id,
            "device": plan.device,
            "vendor": plan.vendor.value,
            "action_type": plan.action_type.value,
            "rollback_minutes": plan.rollback_minutes,
            "plan": plan.to_dict(),
            "markdown_card": plan.to_markdown_card(),
            **_plan_export(plan, export),
        }

    @mcp.tool()
    def enrich_itsm_incident(
        system: str,
        device: str,
        vendor: str,
        root_cause_summary: str,
        site: str = "default",
        layer: str = "L1_PHYSICAL",
        interface: str = "Ethernet1",
        confidence: float = 0.95,
        rollback_minutes: int = 5,
        pre_checks: list[str] | None = None,
        config_commands: list[str] | None = None,
        post_checks: list[str] | None = None,
        suppressed_symptoms_count: int = 0,
        affected_devices: list[str] | None = None,
        affected_vnis: list[int] | None = None,
        telemetry_summary: str = "",
        plan_id: str = "",
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Format or dispatch two-way ITSM incident enrichment to Jira or ServiceNow.

        Parameters:
          system: 'jira' or 'servicenow'
          device: Device hostname
          vendor: Operating system vendor
          root_cause_summary: Summary description of diagnosed root cause
          site: Site / fabric identifier
          layer: Protocol layer (e.g. L1_PHYSICAL, L3_UNDERLAY, L5_OVERLAY_EVPN)
          interface: Faulty interface
          confidence: Causal confidence score (0.0 - 1.0)
          rollback_minutes: Revert timer duration in minutes
          pre_checks: Read-only pre-checks
          config_commands: Applied configuration commands
          post_checks: Post-check verification commands
          suppressed_symptoms_count: Number of suppressed symptom events
          affected_devices: List of impacted hostnames
          affected_vnis: List of impacted VXLAN VNIs
          telemetry_summary: Optical/telemetry diagnostics text
          plan_id: Remediation plan identifier (e.g. REM-1234ABCD)
          dry_run: When True (default), previews the payload without external API requests
        """
        from ai_log_analyzer.itsm import (
            IncidentEnrichmentPayload,
            JiraITSMClient,
            ServiceNowITSMClient,
        )
        from ai_log_analyzer.remediation import (
            RemediationActionType,
            RemediationPlan,
            VendorOS,
        )

        sys_name = system.lower().strip()
        if sys_name not in ("jira", "servicenow"):
            return {"ok": False, "error": f"Unsupported ITSM system: {system!r}. Must be 'jira' or 'servicenow'."}

        plan = None
        if plan_id or config_commands:
            try:
                vos = VendorOS(vendor.lower().strip())
            except ValueError:
                vos = VendorOS.ARISTA_EOS
            plan = RemediationPlan(
                plan_id=plan_id or f"REM-{device.upper()}",
                device=device,
                vendor=vos,
                action_type=RemediationActionType.GRACEFUL_LINK_DRAIN,
                rollback_minutes=rollback_minutes,
                rationale=root_cause_summary,
                pre_checks=pre_checks or [],
                config_commands=config_commands or [],
                commit_with_timer_commands=[],
                post_checks=post_checks or [],
                confirm_commit_commands=[],
                manual_rollback_commands=[],
            )

        payload = IncidentEnrichmentPayload(
            site=site,
            root_device=device,
            root_layer=layer,
            root_interface=interface or None,
            summary_title=root_cause_summary,
            rca_rationale=f"Diagnosed root cause on {device}: {root_cause_summary}",
            confidence=confidence,
            affected_devices=affected_devices or [device],
            affected_vnis=affected_vnis or [],
            suppressed_symptom_count=suppressed_symptoms_count,
            telemetry_summary=telemetry_summary or None,
            remediation_plan=plan,
        )

        if dry_run:
            return {
                "ok": True,
                "dry_run": True,
                "system": sys_name,
                "fingerprint": payload.fingerprint,
                "markdown_card": payload.to_markdown_body(),
                "jira_payload": payload.to_jira_issue_fields("NET"),
                "servicenow_payload": payload.to_servicenow_record(),
            }

        try:
            if sys_name == "jira":
                base_url = os.environ.get("JIRA_URL") or os.environ.get("JIRA_BASE_URL", "")
                email = os.environ.get("JIRA_EMAIL", "")
                token = os.environ.get("JIRA_API_TOKEN", "")
                project = os.environ.get("JIRA_PROJECT_KEY", "NET")
                if not (base_url and email and token):
                    return {"ok": False, "error": "Missing Jira credentials in environment (JIRA_URL, JIRA_EMAIL, JIRA_API_TOKEN)"}
                client = JiraITSMClient(base_url, email, token, project_key=project)
                res = client.enrich_incident(payload)
                return {"ok": True, "dry_run": False, "system": "jira", "result": res}
            else:
                instance_url = os.environ.get("SERVICENOW_URL") or os.environ.get("SNOW_URL", "")
                user = os.environ.get("SERVICENOW_USER") or os.environ.get("SNOW_USER", "")
                pwd = os.environ.get("SERVICENOW_PASSWORD") or os.environ.get("SNOW_PASSWORD", "")
                if not (instance_url and user and pwd):
                    return {"ok": False, "error": "Missing ServiceNow credentials in environment (SERVICENOW_URL, SERVICENOW_USER, SERVICENOW_PASSWORD)"}
                client = ServiceNowITSMClient(instance_url, user, pwd)
                res = client.enrich_incident(payload)
                return {"ok": True, "dry_run": False, "system": "servicenow", "result": res}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    @mcp.tool()
    def fetch_solarwinds_logs(
        source_id: str = "",
        since_seconds: int = 3600,
        limit: int = 500,
        host_filter: str = "",
    ) -> dict[str, Any]:
        """Pull SolarWinds syslog / OLM / SaaS log lines. Read-only; no alert writeback."""
        try:
            conn = _solarwinds_connector(source_id)
            lines = conn.pull_logs(
                limit=limit,
                since_seconds=since_seconds,
                host_filter=host_filter,
                include_alerts=False,
            )
        except SourceError as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "count": len(lines), "lines": lines}

    @mcp.tool()
    def fetch_solarwinds_alerts(
        source_id: str = "",
        since_seconds: int = 3600,
        host_filter: str = "",
    ) -> dict[str, Any]:
        """Pull SolarWinds active alerts (SWIS join query or SaaS GET /v1/alerts). Read-only."""
        try:
            conn = _solarwinds_connector(source_id)
            alerts = conn.fetch_active_alerts(
                since_seconds=since_seconds, host_filter=host_filter,
            )
        except SourceError as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "count": len(alerts), "alerts": alerts}

    @mcp.tool()
    def push_solarwinds_alert_note(
        alert_object_id: int,
        note: str,
        source_id: str = "",
    ) -> dict[str, Any]:
        """Explicit writeback: invoke Orion.AlertActive/AppendNote with an RCA note.

        Never runs automatically — callers must invoke this tool.
        """
        try:
            conn = _solarwinds_connector(source_id)
            result = conn.append_alert_note(int(alert_object_id), note)
        except SourceError as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "alert_object_id": int(alert_object_id), "result": result}

    @mcp.tool()
    def netlog_deep_analytics(log_text: str, site_name: str = "") -> dict[str, Any]:
        """Flap physics, dampening status, and topology blast radius for a log snippet."""
        topology = None
        if site_name:
            try:
                topology = load_site_topology(_SITES_DIR, site_name)
            except ValueError as exc:
                return {"ok": False, "error": str(exc)}
        bundle = run_deep_report(log_text=log_text, topology=topology)
        return {"ok": True, **bundle.payload}

    @mcp.tool()
    def netlog_servicenow_correlate_changes(log_text: str, changes_json: str) -> dict[str, Any]:
        """Correlate log anomalies with a JSON array of ServiceNow change records."""
        try:
            changes = json.loads(changes_json or "[]")
        except json.JSONDecodeError as exc:
            return {"ok": False, "error": f"changes_json is not JSON: {exc}"}
        if not isinstance(changes, list):
            return {"ok": False, "error": "changes_json must be a JSON array"}
        bundle = run_deep_report(log_text=log_text, changes=changes)
        return {"ok": True, "change_correlation": bundle.payload["change_correlation"]}

    @mcp.tool()
    def netlog_servicenow_sync_incident(
        log_text: str,
        instance_url: str = "",
        dry_run: bool = True,
        changes_json: str = "[]",
    ) -> dict[str, Any]:
        """Preview or upsert an idempotent ServiceNow incident. Defaults to dry-run."""
        try:
            changes = json.loads(changes_json or "[]")
        except json.JSONDecodeError as exc:
            return {"ok": False, "error": f"changes_json is not JSON: {exc}"}
        if not isinstance(changes, list):
            return {"ok": False, "error": "changes_json must be a JSON array"}
        live = bool(instance_url) and not dry_run
        bundle = run_deep_report(log_text=log_text, changes=changes)
        try:
            client = ServiceNowClient(
                instance_url=instance_url,
                username=os.environ.get("SERVICENOW_USER", ""),
                password=os.environ.get("SERVICENOW_PASSWORD", ""),
                bearer_token=os.environ.get("SERVICENOW_TOKEN", ""),
            )
            result = client.sync_incident(
                bundle.summary,
                blast_radius=bundle.blast,
                change_report=bundle.changes,
                flap_report=bundle.flap,
                dry_run=not live,
            )
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, **result.to_dict()}

    return mcp


def run(transport: str = "stdio") -> None:
    """Entry point — start the MCP server on the requested transport.

    Auto-loads env-configured sources before serving so the MCP client sees
    them immediately on list_sources().
    """
    try:
        source_manager.load_from_env()
    except Exception:
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
