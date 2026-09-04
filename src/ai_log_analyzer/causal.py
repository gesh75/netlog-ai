"""Causal console helpers — timeline, blast radius, change-window correlator.

Pure functions over classified events / action items. Wired into
``analyze()`` so the Flask UI, CLI, and MCP server all see the same 0.6
surfaces. No I/O, no LLM.
"""
from __future__ import annotations

from typing import Any, Iterable

from ai_log_analyzer.classifier import SEV_ORDER, ClassifiedEvent

# Actionable for the timeline: critical / high / medium. Recovery (link-up,
# peer-established) stays visible so the causal chain can close.
_ACTIONABLE = {"critical", "high", "medium"}
_CONFIG_CATEGORIES = {"config"}
_DOWNSTREAM = ("BGP", "OSPF", "LAG", "VPN", "EVPN", "BFD", "MLAG")
# Display cap is 24. A fabric-wide flap fills that window with high-severity
# rows and would hide a late config commit — the same signal change_window
# exists to surface. Pin a handful so the causal console stays honest.
_TIMELINE_CONFIG_PIN = 4


def _select_timeline_rows(
    events: Iterable[ClassifiedEvent], limit: int,
) -> list[ClassifiedEvent]:
    """Chronological incident rows, with config commits pinned into ``limit``.

    The display cap is applied after timestamp sort. Without a pin, a
    commit that lands after ``limit`` earlier flaps never appears even when
    the caller reserved it specifically for the causal console.
    """
    rows = [
        e for e in events
        if e.severity in _ACTIONABLE or e.category == "config"
    ]
    rows.sort(key=lambda e: (e.timestamp or "", e.hostname or ""))
    if len(rows) <= limit:
        return rows
    prefix = rows[:limit]
    shown = {id(e) for e in prefix}
    missing = [e for e in rows if e.category == "config" and id(e) not in shown]
    if not missing:
        return prefix
    pin = missing[:_TIMELINE_CONFIG_PIN]
    incidents = sum(1 for e in prefix if e.category != "config")
    # Never wipe the last incident row still inside the window just to
    # make room for extra commits.
    max_evict = min(len(pin), max(0, incidents - 1))
    if max_evict == 0:
        return prefix
    evicted = 0
    kept: list[ClassifiedEvent] = []
    for e in reversed(prefix):
        if evicted < max_evict and e.category != "config":
            evicted += 1
            continue
        kept.append(e)
    kept.reverse()
    kept.extend(pin[:evicted])
    kept.sort(key=lambda e: (e.timestamp or "", e.hostname or ""))
    return kept


def build_timeline(events: Iterable[ClassifiedEvent], limit: int = 24) -> list[dict[str, Any]]:
    """Chronological causal timeline of the incident.

    Each node is one classified event. A later node gets ``cause_of`` set
    when a simple heuristic says the previous event likely precipitated it
    (link-down → BGP/OSPF/LAG, BGP → EVPN, OSPF → drops).
    """
    rows = _select_timeline_rows(events, limit)
    nodes: list[dict[str, Any]] = []
    for e in rows[:limit]:
        nodes.append({
            "t": e.timestamp or "—",
            "device": e.hostname or "unknown",
            "severity": e.severity,
            "category": e.category,
            "title": e.description,
        })
    for i in range(1, len(nodes)):
        prev, cur = nodes[i - 1], nodes[i]
        prev_title = prev["title"].lower()
        cur_title = cur["title"]
        if "link down" in prev_title and any(k in cur_title.upper() for k in _DOWNSTREAM):
            cur["cause_of"] = prev["title"]
        elif "bgp" in prev_title and "evpn" in cur_title.lower():
            cur["cause_of"] = prev["title"]
        elif "ospf" in prev_title and any(
            k in cur_title.lower() for k in ("drop", "blackhole", "unreachable", "discard")
        ):
            cur["cause_of"] = prev["title"]
        elif prev["category"] == "config" and SEV_ORDER.get(cur["severity"], 9) <= 1:
            cur["cause_of"] = prev["title"]
    return nodes


def blast_radius(
    action_items: Iterable[Any],
    stability: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Estimate which devices / categories sit in the blast radius.

    ``action_items`` is the ranked list from ``analyze()``. Optional
    ``stability`` is the fabric-stability report (flap detector).
    """
    items = list(action_items)
    devices: list[str] = []
    seen: set[str] = set()
    categories: list[str] = []
    cat_seen: set[str] = set()
    for a in items:
        for d in getattr(a, "devices", None) or []:
            if d and d not in seen:
                seen.add(d)
                devices.append(d)
        cat = getattr(a, "category", "")
        if cat and cat not in cat_seen:
            cat_seen.add(cat)
            categories.append(cat)
    devices = devices[:12]
    top = items[0] if items else None
    flap_note = "no flap signature"
    if stability:
        for d in (stability.get("devices") or []):
            flaps = d.get("flaps") or 0
            if flaps:
                flap_note = (
                    f"flapping {flaps}× on {d.get('hostname', 'unknown')}"
                    f"{(' (' + d['flapping_entity'] + ')') if d.get('flapping_entity') else ''}"
                )
                break
    if not top:
        estimated = "Quiet fabric — no ranked actions."
        epicenter = "—"
    else:
        epicenter = (getattr(top, "devices", None) or ["unknown"])[0]
        n = len(devices)
        estimated = (
            f"{n} device{'s' if n != 1 else ''} in {', '.join(categories[:3]) or 'uncategorized'}. "
            f"Epicenter {epicenter} ({getattr(top, 'description', '').lower()} "
            f"×{getattr(top, 'count', 1)}). {flap_note}."
        )
    return {
        "epicenter": epicenter,
        "devices": devices,
        "categories": categories,
        "estimated_impact": estimated,
        "device_count": len(devices),
    }


def change_window(events: Iterable[ClassifiedEvent]) -> dict[str, Any]:
    """Detect a configuration-commit sitting inside the same incident window.

    A hit is a strong hint the outage is change-induced until proven otherwise.
    """
    hits = [e for e in events if e.category in _CONFIG_CATEGORIES]
    # Order is not guaranteed: analyze() concatenates severity-priority
    # top_k (newest-first within a severity) ahead of the reserved extras.
    # Oldest-first so devices[0] is the earliest commit host, not the
    # noisiest late one.
    hits.sort(key=lambda e: (e.timestamp or "", e.hostname or ""))
    devices: list[str] = []
    seen: set[str] = set()
    samples: list[str] = []
    for e in hits:
        if e.hostname and e.hostname not in seen:
            seen.add(e.hostname)
            devices.append(e.hostname)
        if e.sample_message and len(samples) < 4:
            samples.append(e.sample_message[:200])
    return {
        "detected": bool(hits),
        "count": len(hits),
        "devices": devices,
        "samples": samples,
    }
