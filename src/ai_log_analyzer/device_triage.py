"""Per-device deep triage.

Ports DCN api_device_deep() (DCN_AI_Intelligence/app.py:2412) error-pattern
normalization (strip hex addrs / IPs / PIDs, then frequency-dedup) and the
verdict + health-score chain — re-targeted from Kibana hits to netlog-ai
LogEvents for a single host.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ai_log_analyzer.classifier import LogEvent

# Raw-severity buckets considered error-grade for pattern dedup (DCN parity).
_ERROR_SEVS: frozenset[str] = frozenset({"err", "error", "crit", "emerg", "alert"})

# Normalization passes (order matters; DCN app.py:2501-2503).
_HEX_RE: re.Pattern[str] = re.compile(r"\b0x[0-9a-fA-F]+\b")
_PID_RE: re.Pattern[str] = re.compile(r"\[\d+\]")
_IP_RE: re.Pattern[str]  = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


def normalize_pattern(message: str) -> str:
    """Collapse a log message to a dedup key: 0x.. -> 0xADDR, [123] -> [N],
    a.b.c.d -> IP, then truncate to 120 chars. (DCN app.py:2501-2504)."""
    key = _HEX_RE.sub("0xADDR", message or "")
    key = _PID_RE.sub("[N]", key)
    key = _IP_RE.sub("IP", key)
    return key[:120].strip()


@dataclass
class DevicePattern:
    """Frequency-deduped error-pattern entry."""

    pattern: str
    count: int
    severity: str       # raw severity of first occurrence
    app: str

    def to_dict(self) -> dict[str, Any]:
        """Return a plain-dict representation."""
        return {
            "pattern": self.pattern,
            "count": self.count,
            "severity": self.severity,
            "app": self.app,
        }


@dataclass
class DeviceTriage:
    """Full per-device triage result."""

    hostname: str
    total_events: int
    severity_dist: dict[str, int]        # raw-severity histogram
    processes: list[dict[str, Any]]      # [{process, count, pct}] desc by count
    patterns: list[dict[str, Any]]       # top-20 deduped error patterns desc
    verdict: str
    issue_type: str                      # hardware|routing|lag|license|memory|security|general|info
    health_score: int                    # 0-100
    top_process: str

    def to_dict(self) -> dict[str, Any]:
        """Return a plain-dict representation suitable for JSON serialization."""
        return {
            "hostname": self.hostname,
            "total_events": self.total_events,
            "severity_dist": self.severity_dist,
            "processes": self.processes,
            "patterns": self.patterns,
            "verdict": self.verdict,
            "issue_type": self.issue_type,
            "health_score": self.health_score,
            "top_process": self.top_process,
        }


def triage_device(hostname: str, events: list[LogEvent]) -> DeviceTriage:
    """Analyze one host's LogEvents into a triage verdict.

    Uses ``ev.severity_raw`` for the DCN-style raw histogram + error dedup, and
    ``ev.appname`` as the process. Pure: does not mutate ``events``. Empty input
    yields verdict 'No events found', score 100, issue_type 'info'.
    """
    if not events:
        return DeviceTriage(
            hostname=hostname,
            total_events=0,
            severity_dist={},
            processes=[],
            patterns=[],
            verdict="No events found",
            issue_type="info",
            health_score=100,
            top_process="",
        )

    total = len(events)

    # ── Raw severity histogram ───────────────────────────────────────────────
    sev_dist: dict[str, int] = {}
    for ev in events:
        raw_sev = (ev.severity_raw or "").lower()
        sev_dist[raw_sev] = sev_dist.get(raw_sev, 0) + 1

    # ── Process breakdown ────────────────────────────────────────────────────
    process_counts: dict[str, int] = {}
    for ev in events:
        proc = ev.appname or "unknown"
        process_counts[proc] = process_counts.get(proc, 0) + 1

    processes: list[dict[str, Any]] = sorted(
        [
            {
                "process": k,
                "count": v,
                "pct": round(v / total * 100, 1),
            }
            for k, v in process_counts.items()
        ],
        key=lambda x: x["count"],
        reverse=True,
    )

    top_process: str = processes[0]["process"] if processes else "unknown"

    # ── Error pattern deduplication (DCN app.py:2496-2511) ──────────────────
    pattern_acc: dict[str, dict[str, Any]] = {}
    error_apps: set[str] = set()
    for ev in events:
        raw_sev = (ev.severity_raw or "").lower()
        if raw_sev not in _ERROR_SEVS:
            continue
        error_apps.add(ev.appname or "unknown")
        key = normalize_pattern(ev.message)
        if not key:
            continue
        if key not in pattern_acc:
            pattern_acc[key] = {
                "pattern": key,
                "count": 0,
                "severity": raw_sev,
                "app": ev.appname or "unknown",
            }
        pattern_acc[key]["count"] += 1

    patterns: list[dict[str, Any]] = sorted(
        pattern_acc.values(),
        key=lambda x: x["count"],
        reverse=True,
    )[:20]

    # ── Health score (DCN app.py:2524-2528) ─────────────────────────────────
    crit_count = (
        sev_dist.get("crit", 0)
        + sev_dist.get("emerg", 0)
        + sev_dist.get("alert", 0)
    )
    err_count = sev_dist.get("err", 0) + sev_dist.get("error", 0)
    warn_count = sev_dist.get("warning", 0) + sev_dist.get("warn", 0)

    score = 100
    score -= min(crit_count * 5, 50)
    score -= min(err_count // 100 * 5, 30)
    score -= min(warn_count // 500 * 2, 10)
    score = max(0, score)

    # ── Verdict chain (DCN app.py:2530-2560) — evaluated in exact order ─────
    top_pat: str = patterns[0]["pattern"].lower() if patterns else ""

    if (
        top_process in ("fpc0", "fpc1", "fpc2", "chassisd")
        or "parity" in top_pat
        or "sbus" in top_pat
    ):
        verdict = "HARDWARE FAILURE — FPC/ASIC Hardware Errors"
        issue_type = "hardware"
    elif top_process == "rpd" or "bgp" in top_pat:
        verdict = "ROUTING ISSUE — BGP/Routing Protocol Errors"
        issue_type = "routing"
    elif "lacpd" in top_process or "lag" in top_pat or "lacp" in top_pat:
        verdict = "LAG/LACP ISSUE — Link Aggregation Errors"
        issue_type = "lag"
    elif "license" in top_pat:
        verdict = "LICENSE EXPIRATION — Feature License Issues"
        issue_type = "license"
    elif "swap" in top_pat or "memory" in top_pat:
        verdict = "MEMORY EXHAUSTION — Kernel/Process Memory Issues"
        issue_type = "memory"
    elif top_process == "sshd" and "sshd" in error_apps:
        verdict = "SSH ACTIVITY — Authentication / Session Events"
        issue_type = "security"
    elif crit_count > 100:
        verdict = "CRITICAL ERRORS — Multiple High-Severity Events"
        issue_type = "general"
    elif err_count > 1000:
        verdict = "HIGH ERROR RATE — Sustained Error Condition"
        issue_type = "general"
    else:
        verdict = "INFORMATIONAL — No Critical Issues Detected"
        issue_type = "info"

    return DeviceTriage(
        hostname=hostname,
        total_events=total,
        severity_dist=sev_dist,
        processes=processes,
        patterns=patterns,
        verdict=verdict,
        issue_type=issue_type,
        health_score=score,
        top_process=top_process,
    )


def triage_from_manager(
    hostname: str,
    source_ids: list[str] | None = None,
    *,
    since_seconds: int = 86_400,
    limit: int = 5000,
) -> dict[str, Any]:
    """Fetch this host's events from one or more live sources and triage.

    ``source_ids`` None => all registered sources; an explicit empty list
    selects none. Failing sources are skipped (error captured under
    ``"skipped"``; never raises for a single bad source). Returns::

        {
          "ok": True,
          **DeviceTriage.to_dict(),
          "sources": [...used...],
          "skipped": {source_id: error_str},
        }
    """
    # Deferred import avoids import cycle at module load time.
    from ai_log_analyzer.sources.manager import manager as source_manager
    from ai_log_analyzer.sources.base import SourceError

    # None => all registered sources; an explicit empty list => no sources.
    ids: list[str] = (
        source_manager.list_ids() if source_ids is None else list(source_ids)
    )

    all_events: list[LogEvent] = []
    used_sources: list[str] = []
    skipped: dict[str, str] = {}

    for sid in ids:
        try:
            events = source_manager.fetch(
                sid,
                since_seconds=since_seconds,
                limit=limit,
                host_filter=hostname,
            )
            all_events.extend(events)
            used_sources.append(sid)
        except SourceError as exc:
            skipped[sid] = str(exc)

    result_obj = triage_device(hostname, all_events)
    return {
        "ok": True,
        **result_obj.to_dict(),
        "sources": used_sources,
        "skipped": skipped,
    }
