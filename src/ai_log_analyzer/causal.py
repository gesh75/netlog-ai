"""Causal console helpers — timeline, blast radius, change-window correlator.

Pure functions over classified events / action items. Wired into
``analyze()`` so the Flask UI, CLI, and MCP server all see the same 0.6
surfaces. No I/O, no LLM.
"""
from __future__ import annotations

from datetime import datetime
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
# Leftover overflow and a later storm are separate clusters when they
# sit at least this far apart. Morning flaps are seconds apart; the
# leftover tests place the BGP storm an hour later.
_LEFTOVER_CLUSTER_GAP_S = 60.0
_RFC3164_MONTHS = {
    name: idx
    for idx, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}


def _as_naive(dt: datetime) -> datetime:
    return dt.replace(tzinfo=None) if dt.tzinfo is not None else dt


def _parse_event_ts(ts: str) -> datetime | None:
    """Parse ISO/RFC5424, FRR, and RFC3164/Junos stamps. None if unknown."""
    if not ts:
        return None
    stamp = ts.strip()
    iso = stamp.replace("Z", "+00:00")
    try:
        return _as_naive(datetime.fromisoformat(iso))
    except ValueError:
        pass
    collapsed = " ".join(stamp.split())
    for fmt in ("%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(collapsed, fmt)
        except ValueError:
            continue
    parts = collapsed.split()
    if len(parts) == 3 and parts[0] in _RFC3164_MONTHS:
        try:
            day = int(parts[1])
            hour, minute, sec = (int(p) for p in parts[2].split(":"))
            return datetime(1900, _RFC3164_MONTHS[parts[0]], day, hour, minute, sec)
        except ValueError:
            return None
    return None


def _event_gap_seconds(prev: ClassifiedEvent, nxt: ClassifiedEvent) -> float:
    ta = _parse_event_ts(prev.timestamp or "")
    tb = _parse_event_ts(nxt.timestamp or "")
    if ta is None or tb is None:
        # Unknown stamps stay in the current cluster; the caller falls
        # back to the newest missing rows when no gap can be found.
        return 0.0
    return abs((tb - ta).total_seconds())


def _gap_clusters(events: list[ClassifiedEvent]) -> list[list[ClassifiedEvent]]:
    if not events:
        return []
    clusters: list[list[ClassifiedEvent]] = [[events[0]]]
    for prev, event in zip(events, events[1:]):
        if _event_gap_seconds(prev, event) >= _LEFTOVER_CLUSTER_GAP_S:
            clusters.append([event])
        else:
            clusters[-1].append(event)
    return clusters


def _later_storm_incidents(
    prefix: list[ClassifiedEvent],
    missing: list[ClassifiedEvent],
) -> list[ClassifiedEvent]:
    """Skip leftover overflow so the floor pulls the later outage.

    Resetting the leftover *count* is not enough when leftover flaps
    overflow the chronological cap: ``missing`` then starts with more
    morning flaps (or an intermediate leftover category), and a first-N
    pull never reaches the BGP storm. Drop the leftover-contiguous head,
    drop later clusters that still share a leftover category (afternoon
    flaps of the same signature), and take the last remaining cluster.
    If every later cluster is leftover-category (same-signature storm)
    or stamps cannot be clustered, fall back to the last cluster / the
    newest floor-sized slice.
    """
    leftover = [e for e in prefix if e.category != "config"]
    if not leftover or not missing:
        return missing
    leftover_cats = {e.category for e in leftover}
    idx = 0
    prev = leftover[-1]
    while (
        idx < len(missing)
        and _event_gap_seconds(prev, missing[idx]) < _LEFTOVER_CLUSTER_GAP_S
    ):
        prev = missing[idx]
        idx += 1
    later = missing[idx:]
    if not later:
        return missing[-min(_TIMELINE_INCIDENT_FLOOR, len(missing)):]
    clusters = _gap_clusters(later)
    preferred = [c for c in clusters if c[0].category not in leftover_cats]
    if not preferred:
        preferred = clusters
    return preferred[-1]


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
    pulled_ids: set[int] = set()

    missing_incidents = [
        e for e in rows if e.category != "config" and id(e) not in shown
    ]
    incidents = sum(1 for e in prefix if e.category != "config")
    if missing_incidents:
        # Leftover earlier flaps do not satisfy the floor when a commit
        # exists in the window — whether it precedes the later storm,
        # sat at the end of the prefix, overflowed past a flap-filled
        # cap, or arrived after the storm (a late pin).
        config_in_window = any(e.category == "config" for e in rows)
        leftover_budget = incidents if config_in_window else 0
        if config_in_window:
            incidents = 0
        if leftover_budget:
            missing_incidents = _later_storm_incidents(prefix, missing_incidents)
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
            pulled = missing_incidents[:evicted]
            kept.extend(pulled)
            pulled_ids = {id(e) for e in pulled}
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
    # true late commits — do not evict the outage we just surfaced. If
    # the prefix had no commit (it overflowed past leftover flaps), evict
    # those leftover flaps instead so the late commit still appears.
    if pulled_incidents:
        configs_in_prefix = sum(1 for e in prefix if e.category == "config")
        spare = max(0, configs_in_prefix - 1) if configs_in_prefix else len(pin)
        take = min(len(pin), spare)
        if take == 0:
            return prefix
        evicted = 0
        kept = []
        for e in prefix:
            if evicted < take and e.category == "config":
                evicted += 1
                continue
            kept.append(e)
        if evicted < take:
            still = take - evicted
            dropped = 0
            trimmed = []
            for e in kept:
                if (
                    dropped < still
                    and e.category != "config"
                    and id(e) not in pulled_ids
                ):
                    dropped += 1
                    continue
                trimmed.append(e)
            kept = trimmed
            evicted += dropped
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
