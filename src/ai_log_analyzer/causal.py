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
# The inverse is also true: a commit flood that fills the cap hides every
# later incident. Floor a few incident rows so the outage stays visible.
_TIMELINE_CONFIG_PIN = 4
_TIMELINE_INCIDENT_FLOOR = 8


def _select_timeline_rows(
    events: Iterable[ClassifiedEvent], limit: int,
) -> list[ClassifiedEvent]:
    """Chronological incident rows, with config commits pinned into ``limit``.

    The display cap is applied after timestamp sort. Without a pin, a
    commit that lands after ``limit`` earlier flaps never appears even when
    the caller reserved it specifically for the causal console. Without the
    inverse floor, ``limit`` earlier commits hide every later incident.
    """
    rows = [
        e for e in events
        if e.severity in _ACTIONABLE or e.category == "config"
    ]
    rows.sort(key=lambda e: (e.timestamp or "", e.hostname or ""))
    if len(rows) <= limit:
        return rows
    prefix = rows[:limit]
    orig_prefix_ids = {id(e) for e in prefix}
    shown = set(orig_prefix_ids)
    pulled_incidents = False

    missing_incidents = [
        e for e in rows if e.category != "config" and id(e) not in shown
    ]
    incidents = sum(1 for e in prefix if e.category != "config")
    if missing_incidents:
        # A trailing commit burst hid the later outage. Leftover flaps
        # from earlier in the window do not satisfy the floor — they are
        # not the storm that follows the configs.
        trailing_config = bool(prefix and prefix[-1].category == "config")
        leftover_budget = incidents if trailing_config else 0
        if trailing_config:
            incidents = 0
        floor = min(_TIMELINE_INCIDENT_FLOOR, incidents + len(missing_incidents))
        need = max(0, floor - incidents)
        configs_in_prefix = sum(1 for e in prefix if e.category == "config")
        # Keep at least one commit in the window when both signals exist.
        config_budget = max(0, configs_in_prefix - 1)
        # Commit-only eviction cannot free slots when leftover flaps already
        # occupy the cap (23 flaps + 1 trailing commit → budget 0).
        take = min(need, config_budget + leftover_budget, len(missing_incidents))
        if take:
            evicted_cfg = 0
            kept: list[ClassifiedEvent] = []
            cfg_take = min(take, config_budget)
            for e in prefix:  # drop oldest commits; keep those closest to the storm
                if evicted_cfg < cfg_take and e.category == "config":
                    evicted_cfg += 1
                    continue
                kept.append(e)
            evicted = evicted_cfg
            if evicted < take:
                still = take - evicted
                dropped = 0
                trimmed: list[ClassifiedEvent] = []
                for e in kept:  # then drop oldest leftover flaps
                    if dropped < still and e.category != "config":
                        dropped += 1
                        continue
                    trimmed.append(e)
                kept = trimmed
                evicted += dropped
            kept.extend(missing_incidents[:evicted])
            kept.sort(key=lambda e: (e.timestamp or "", e.hostname or ""))
            prefix = kept
            shown = {id(e) for e in prefix}
            pulled_incidents = True

    # Only pin commits that never fit the chronological window — not the
    # early ones we just evicted to surface the outage.
    missing = [
        e for e in rows
        if e.category == "config"
        and id(e) not in shown
        and id(e) not in orig_prefix_ids
    ]
    if not missing:
        return prefix
    pin = missing[:_TIMELINE_CONFIG_PIN]
    incidents = sum(1 for e in prefix if e.category != "config")
    # After pulling later incidents in, swap remaining early commits for
    # true late commits — do not evict the outage we just surfaced.
    if pulled_incidents:
        configs_in_prefix = sum(1 for e in prefix if e.category == "config")
        take = min(len(pin), max(0, configs_in_prefix - 1))
        if take == 0:
            return prefix
        evicted = 0
        kept = []
        for e in prefix:
            if evicted < take and e.category == "config":
                evicted += 1
                continue
            kept.append(e)
        kept.extend(pin[:evicted])
        kept.sort(key=lambda e: (e.timestamp or "", e.hostname or ""))
        return kept
    # Never wipe the last incident row still inside the window just to
    # make room for extra commits.
    max_evict = min(len(pin), max(0, incidents - 1))
    if max_evict == 0:
        return prefix
    evicted = 0
    kept = []
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
