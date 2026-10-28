"""Shared deep-analytics bundle for the CLI, web API, and MCP tools."""
from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ai_log_analyzer.adapters.file import parse_lines
from ai_log_analyzer.analytics import (
    Finding,
    _is_transition,
    _iter_rows,
    _row_from_text,
    analyze_blast_radius,
    analyze_flap_dynamics,
    build_device_overlays,
    correlate_config_drift,
)
from ai_log_analyzer.analyzer import analyze
from ai_log_analyzer.diff import ConfigDiff
from ai_log_analyzer.servicenow_sync import correlate_changes_with_findings
from ai_log_analyzer.topology import Topology, apply_manifest_metadata, build_topology

# Topology inference tests every kept host against every distinct message (a substring test), so
# both factors are bounded: the hosts that become nodes, and the total number of host-in-message tests.
_MAX_TOPOLOGY_HOSTS = 2_000
_MAX_TOPOLOGY_CHECKS = 5_000_000


@dataclass
class DeepBundle:
    payload: dict[str, Any]
    flap: Any
    blast: Any
    changes: Any
    summary: dict[str, Any]


def load_site_topology(sites_dir: Path, site_id: str) -> Topology | None:
    """Build a topology from ``sites_dir/site_id`` when the bundle exists."""
    safe = "".join(ch for ch in site_id if ch.isalnum() or ch in "-_").lower()
    if not safe or safe != site_id.lower():
        raise ValueError("invalid site id")
    site_dir = sites_dir / safe
    manifest_path = site_dir / "manifest.json"
    if not manifest_path.is_file():
        return None
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    devices: list[dict[str, str]] = []
    for entry in manifest.get("devices") or []:
        if not isinstance(entry, dict) or "file" not in entry:
            continue
        path = site_dir / str(entry["file"])
        if not path.is_file():
            continue
        devices.append({
            "hostname": str(entry.get("hostname") or path.stem),
            "function": str(entry.get("function") or "unknown"),
            "platform": str(entry.get("platform") or "unknown"),
            "config_text": path.read_text(encoding="utf-8", errors="replace"),
        })
    if not devices:
        return None
    topo = build_topology(safe.upper(), devices)
    return apply_manifest_metadata(topo, manifest)


def run_deep_report(
    *,
    log_text: str = "",
    events: Iterable[Any] | None = None,
    topology: Any | None = None,
    changes: list[Any] | None = None,
    config_before: str = "",
    config_after: str = "",
    incident_timestamp: str | None = None,
) -> DeepBundle:
    """Run flap, blast-radius, change, and config-drift analysis offline."""
    raw_lines = [line for line in log_text.splitlines() if line.strip()]
    if events is not None:
        materialized = list(events)
        flap_input: list[Any] = materialized
    else:
        materialized = list(parse_lines(raw_lines))
        flap_input = raw_lines or materialized
    flap = analyze_flap_dynamics(flap_input)
    findings = _findings(materialized, raw_lines)
    truncated: dict[str, Any] = {}
    if topology is not None:
        graph = topology
    else:
        graph = _infer_topology(flap_input)
        if "truncated" in graph:
            truncated["topology"] = graph["truncated"]
    blast = analyze_blast_radius(graph, findings)
    when = incident_timestamp or _latest_stamp(flap_input)
    change_report = correlate_changes_with_findings(
        list(changes or []),
        findings,
        incident_timestamp=when,
    )
    diff = _config_diff(config_before, config_after)
    drift = correlate_config_drift(diff, findings)
    if drift.truncated:
        truncated["config_drift"] = drift.truncated
    overlays = build_device_overlays(blast, flap, change_report.to_dict()["hits"])
    summary = _summary(findings)
    payload = {
        "flap_analysis": flap.to_dict(),
        "blast_radius": blast.to_dict(),
        "change_correlation": change_report.to_dict(),
        "config_drift": drift.to_dict(),
        "device_overlays": overlays,
        "markdown": _markdown(flap.to_dict(), blast.to_dict(), change_report.to_dict()),
    }
    if truncated:   # say so: a capped answer must not read as a complete one
        warning = "Input was bounded (" + ", ".join(sorted(truncated)) + "); the result may be incomplete."
        payload["truncated"] = {"warning": warning, **truncated}
        payload["markdown"] += f"\n- {warning}"
    return DeepBundle(
        payload=payload,
        flap=flap,
        blast=blast,
        changes=change_report,
        summary=summary,
    )


def _findings(events: list[Any], raw_lines: list[str]) -> list[Any]:
    classified = _classify(events)
    if any(getattr(item, "hostname", "") or getattr(item, "device", "") for item in classified):
        return classified
    synthesized: list[Finding] = []
    for line in raw_lines:
        device, message, stamp = _row_from_text(line)
        if not _is_transition(message or line):
            continue
        synthesized.append(Finding(
            device=device or "unknown",
            severity="high",
            message=message or line,
            timestamp=stamp,
        ))
    return synthesized or classified


def _classify(events: list[Any]) -> list[Any]:
    if not events:
        return []
    result = analyze(iter(events), use_llm=False)
    return list(result.classified_events)


def _infer_topology(rows: list[Any]) -> dict[str, Any]:
    hosts: dict[str, None] = {}   # insertion-ordered set
    dropped: set[str] = set()
    messages: dict[tuple[str, str], None] = {}   # distinct (device, message), first-seen order
    for device, message, _stamp in _iter_rows(rows):
        if not device:
            continue
        if device not in hosts:
            if len(hosts) >= _MAX_TOPOLOGY_HOSTS:
                dropped.add(device)
                continue
            hosts[device] = None
        messages[(device, message)] = None
    names = list(hosts)
    edges: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    checks = 0
    unscanned = 0
    for i, (device, message) in enumerate(messages):
        if checks + len(names) > _MAX_TOPOLOGY_CHECKS:
            unscanned = len(messages) - i
            break
        checks += len(names)
        for other in names:
            if other == device or other not in message:
                continue
            pair = tuple(sorted((device, other)))
            if pair not in seen:
                seen.add(pair)
                edges.append((device, other))
    graph: dict[str, Any] = {"nodes": [{"id": host} for host in names], "edges": edges}
    if dropped or unscanned:
        graph["truncated"] = {"hosts_dropped": len(dropped), "messages_unscanned": unscanned}
    return graph


def _latest_stamp(rows: list[Any]) -> str | None:
    stamps = [stamp for _device, _message, stamp in _iter_rows(rows) if stamp]
    return stamps[-1] if stamps else None


def _config_diff(before: str, after: str) -> ConfigDiff | None:
    if not before and not after:
        return None
    return ConfigDiff(before=before, after=after)


def _summary(findings: list[Any]) -> dict[str, Any]:
    devices = sorted({
        str(getattr(item, "hostname", "") or getattr(item, "device", ""))
        for item in findings
        if getattr(item, "hostname", "") or getattr(item, "device", "")
    })
    descriptions = [str(getattr(item, "description", "") or getattr(item, "message", "")) for item in findings]
    title = next((text for text in descriptions if text), "Network anomaly")
    return {"summary": title[:160], "detail": " ".join(descriptions[:5]), "devices": devices}


def _markdown(flap: dict[str, Any], blast: dict[str, Any], changes: dict[str, Any]) -> str:
    return "\n".join([
        "## Deep analytics",
        f"- Dampened storms: {flap.get('dampened_count', 0)}",
        f"- Most unstable: {flap.get('most_unstable_entity') or 'none'}",
        f"- Blast radius score: {blast.get('blast_radius_score', 0)}",
        f"- Critical SPOFs: {', '.join(blast.get('critical_spofs') or []) or 'none'}",
        f"- Top change: {changes.get('top_suspect_change') or 'none'}",
    ])
