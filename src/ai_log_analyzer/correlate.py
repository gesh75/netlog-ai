"""Cross-source device correlation.

Generalizes the DCN "device appears in Kibana AND LibreNMS" intersection
(DCN_AI_Intelligence/app.py:1778-1815) to N netlog-ai sources. A device that
surfaces actionable (>= medium) events from >=2 distinct sources is `confirmed`
(corroborated by independent telemetry); a device seen in exactly 1 source is
`suspected` (single-source, may be noise).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ai_log_analyzer.classifier import LogEvent, classify_events

# Severity rank used to pick a device's worst severity across sources.
_SEV_RANK: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _short_host(hostname: str) -> str:
    """Normalize a hostname to its short form (strip domain), lowercased."""
    return (hostname or "").split(".")[0].strip().lower()


def _site_of(hostname: str) -> str:
    """Best-effort site/pod prefix, e.g. 'fra4-fw-01' -> 'fra4'. '' if no match."""
    m = re.match(r"([a-z]{2,}\d+)", _short_host(hostname))
    return m.group(1) if m else ""


@dataclass
class DeviceCorrelation:
    """Per-device cross-source roll-up."""

    hostname: str
    site: str
    sources: list[str]                  # distinct source ids the device appears in (sorted)
    source_count: int
    status: str                         # "confirmed" (>=2 sources) | "suspected" (1 source)
    worst_severity: str                 # worst severity seen across all sources
    total_events: int                   # actionable events across all sources
    per_source_counts: dict[str, int]   # source_id -> actionable event count
    categories: list[str]              # sorted distinct categories observed

    def to_dict(self) -> dict[str, Any]:
        """Return a plain-dict representation suitable for JSON serialisation."""
        return {
            "hostname": self.hostname,
            "site": self.site,
            "sources": self.sources,
            "source_count": self.source_count,
            "status": self.status,
            "worst_severity": self.worst_severity,
            "total_events": self.total_events,
            "per_source_counts": self.per_source_counts,
            "categories": self.categories,
        }


def correlate_sources(
    events_by_source: dict[str, list[LogEvent]],
    *,
    min_severity: str = "medium",
) -> dict[str, Any]:
    """Correlate actionable devices across multiple sources.

    ``events_by_source`` maps a source id to its raw LogEvents. Each source's
    events are classified independently, devices are keyed by short hostname,
    and a device is ``confirmed`` when it appears (with >= ``min_severity``
    events) in >= 2 sources, else ``suspected``.

    Returns an immutable result dict::

        {
          "ok": True,
          "source_ids": [...],                 # sources actually seen
          "device_count": int,
          "confirmed_count": int,
          "suspected_count": int,
          "confirmed": [DeviceCorrelation.to_dict(), ...],   # sorted worst-first
          "suspected": [DeviceCorrelation.to_dict(), ...],
          "devices": [ ...all... ],            # confirmed + suspected, worst-first
        }

    Raises ``ValueError`` if *min_severity* is not a known severity label.
    """
    if min_severity not in _SEV_RANK:
        raise ValueError(
            f"Unknown min_severity {min_severity!r}. "
            f"Valid values: {sorted(_SEV_RANK, key=_SEV_RANK.__getitem__)}"
        )

    min_rank: int = _SEV_RANK[min_severity]

    # Accumulate per-device stats across sources.
    # Key: short hostname.
    # Value dict keys: "source_ids" (set), "per_source" (dict), "worst_rank" (int),
    #                  "total" (int), "categories" (set).
    device_acc: dict[str, dict[str, Any]] = {}

    source_ids_seen: list[str] = sorted(events_by_source.keys())

    for source_id, raw_events in events_by_source.items():
        classified, _, _ = classify_events(raw_events)
        # Filter down to actionable events only.
        for ev in classified:
            if _SEV_RANK.get(ev.severity, 999) > min_rank:
                continue
            host = _short_host(ev.hostname)
            if not host:
                continue
            if host not in device_acc:
                device_acc[host] = {
                    "source_ids": set(),
                    "per_source": {},
                    "worst_rank": 999,
                    "total": 0,
                    "categories": set(),
                }
            acc = device_acc[host]
            acc["source_ids"].add(source_id)
            acc["per_source"][source_id] = acc["per_source"].get(source_id, 0) + 1
            ev_rank = _SEV_RANK.get(ev.severity, 999)
            if ev_rank < acc["worst_rank"]:
                acc["worst_rank"] = ev_rank
            acc["total"] += 1
            acc["categories"].add(ev.category)

    # Build DeviceCorrelation objects.
    confirmed: list[DeviceCorrelation] = []
    suspected: list[DeviceCorrelation] = []

    # Reverse-map rank -> label.
    _RANK_SEV: dict[int, str] = {v: k for k, v in _SEV_RANK.items()}

    for host, acc in device_acc.items():
        sources_list = sorted(acc["source_ids"])
        source_count = len(sources_list)
        status = "confirmed" if source_count >= 2 else "suspected"
        worst_rank = acc["worst_rank"]
        worst_sev = _RANK_SEV.get(worst_rank, "info")
        dc = DeviceCorrelation(
            hostname=host,
            site=_site_of(host),
            sources=sources_list,
            source_count=source_count,
            status=status,
            worst_severity=worst_sev,
            total_events=acc["total"],
            per_source_counts=dict(acc["per_source"]),
            categories=sorted(acc["categories"]),
        )
        if status == "confirmed":
            confirmed.append(dc)
        else:
            suspected.append(dc)

    def _sort_key(dc: DeviceCorrelation) -> tuple[int, int, str]:
        return (_SEV_RANK.get(dc.worst_severity, 999), -dc.total_events, dc.hostname)

    confirmed.sort(key=_sort_key)
    suspected.sort(key=_sort_key)

    all_devices: list[DeviceCorrelation] = confirmed + suspected

    return {
        "ok": True,
        "source_ids": source_ids_seen,
        "device_count": len(all_devices),
        "confirmed_count": len(confirmed),
        "suspected_count": len(suspected),
        "confirmed": [dc.to_dict() for dc in confirmed],
        "suspected": [dc.to_dict() for dc in suspected],
        "devices": [dc.to_dict() for dc in all_devices],
    }


def correlate_from_manager(
    source_ids: list[str] | None = None,
    *,
    since_seconds: int = 3600,
    limit: int = 5000,
    min_severity: str = "medium",
) -> dict[str, Any]:
    """Fetch from the live SourceManager singleton and correlate.

    When ``source_ids`` is None, use all registered sources
    (``source_manager.list_ids()``); an explicit empty list selects none.
    Unknown or failing sources are skipped (their error captured under
    ``"skipped"``); never raises for a single bad source.

    Returns the ``correlate_sources(...)`` dict plus a
    ``"skipped": {source_id: error_str}`` key.
    """
    # Deferred import avoids an import cycle at module load time.
    from ai_log_analyzer.sources.manager import manager as source_manager
    from ai_log_analyzer.sources.base import SourceError

    # None => all registered sources; an explicit empty list => no sources.
    ids: list[str] = (
        source_manager.list_ids() if source_ids is None else list(source_ids)
    )

    events_by_source: dict[str, list[LogEvent]] = {}
    skipped: dict[str, str] = {}

    for sid in ids:
        try:
            events = source_manager.fetch(
                sid,
                since_seconds=since_seconds,
                limit=limit,
            )
            events_by_source[sid] = events
        except SourceError as exc:
            skipped[sid] = str(exc)

    # Build a new dict rather than mutating correlate_sources()'s result,
    # whose contract is to return a fresh, self-contained dict.
    return {
        **correlate_sources(events_by_source, min_severity=min_severity),
        "skipped": skipped,
    }
