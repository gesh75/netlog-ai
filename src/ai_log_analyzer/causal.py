"""Causal console helpers — timeline, blast radius, change-window correlator.

Pure functions over classified events / action items. Wired into
``analyze()`` so the Flask UI, CLI, and MCP server all see the same 0.6
surfaces. No I/O, no LLM.
"""
from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from ai_log_analyzer.classifier import SEV_ORDER, ClassifiedEvent

# Actionable for the timeline: critical / high / medium. Recovery (link-up,
# peer-established) stays visible so the causal chain can close.
_ACTIONABLE = {"critical", "high", "medium"}
_CONFIG_CATEGORIES = {"config"}
_DOWNSTREAM = ("BGP", "OSPF", "LAG", "VPN", "EVPN", "BFD", "MLAG")
# Display cap is 24. A fabric-wide flap fills that window with high-severity
# rows and would hide a late config commit — the same signal change_window
# exists to surface. Pin a handful so the causal console stays honest.
# The inverse is also true: a commit flood — or a leftover flap flood
# with no commit at all — that fills the cap hides every later incident.
# Floor a few incident rows so the outage stays visible.
_TIMELINE_CONFIG_PIN = 4
_TIMELINE_INCIDENT_FLOOR = 8
# Leftover overflow and a later storm are separate clusters when they
# sit at least this far apart. Morning flaps are seconds apart; the
# leftover tests place the BGP storm an hour later.
_LEFTOVER_CLUSTER_GAP_S = 60.0
# Morning leftover and the afternoon outage can share a category
# (BGP flaps → later BGP collapse). Category-only skip then treats the
# real storm as leftover overflow. These are the leftover categories
# where a later same-category burst on the timeline is still the storm.
_SAME_CATEGORY_STORM = frozenset({"routing"})
_STORM_SEVERITY = frozenset({"critical", "high"})
_RFC3164_MONTHS = {
    name: idx
    for idx, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}
# Leap year so 29 Feb RFC3164 parses. Never a real ingest year; restamped
# from a sibling ISO/epoch event (or datetime.now().year).
_RFC3164_YEARLESS = 4
# Year-boundary months for RFC3164 wrap. A dated June sibling must keep
# December in the same calendar year; only Nov/Dec next to Jan/Feb wrap.
_YEARLESS_EARLY = frozenset({1, 2})
_YEARLESS_LATE = frozenset({11, 12})


def _as_naive(dt: datetime) -> datetime:
    """Compare instants, not wall clocks. Aware stamps become UTC naive.

    Stripping ``tzinfo`` without converting left ``10:00+05:00`` (05:00 UTC)
    later than ``09:55Z``, so a later offset host stole ``devices[0]``.
    Timezone-less ISO / RFC3164 stay wall-clock naive.
    """
    if dt.tzinfo is None:
        return dt
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def _parse_epoch(stamp: str) -> datetime | None:
    """Unix seconds / ms / µs / ns, as Loki and some Splunk _time values emit."""
    try:
        n: float = float(stamp) if "." in stamp else int(stamp)
    except ValueError:
        return None
    abs_n = abs(n)
    if abs_n >= 1e18:
        n /= 1e9
    elif abs_n >= 1e15:
        n /= 1e6
    elif abs_n >= 1e12:
        n /= 1e3
    elif abs_n < 1e9:
        return None
    try:
        return _as_naive(datetime.fromtimestamp(n, tz=timezone.utc))
    except (OSError, OverflowError, ValueError):
        return None


def _parse_event_ts(ts: str) -> datetime | None:
    """Parse ISO/RFC5424, FRR, epoch, and RFC3164/Junos stamps. None if unknown.

    RFC3164 has no year — ``_RFC3164_YEARLESS`` is a sentinel so callers
    can re-stamp from a sibling event that does carry a year (ISO / Loki
    epoch). The sentinel is a leap year so 29 Feb still parses.
    """
    if not ts:
        return None
    stamp = ts.strip()
    iso = stamp.replace("Z", "+00:00")
    try:
        return _as_naive(datetime.fromisoformat(iso))
    except ValueError:
        pass
    epoch = _parse_epoch(stamp)
    if epoch is not None:
        return epoch
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
            return datetime(
                _RFC3164_YEARLESS, _RFC3164_MONTHS[parts[0]], day, hour, minute, sec,
            )
        except ValueError:
            return None
    return None


def _now() -> datetime:
    """Clock seam so year-inference tests can freeze ``datetime.now()``."""
    return datetime.now()


def _reference_dt(events: Iterable[ClassifiedEvent]) -> datetime:
    """Anchor for RFC3164 year inference.

    Prefer the first dated sibling. With only yearless stamps, pin the
    first RFC3164 stamp to ``now()`` and use that instant so the rest of
    the set restamps relative to a sibling — not independently against
    ``now()``. Independent restamp around 2 July assigned ``Dec 31`` and
    ``Jan 1`` the same calendar year and inverted ``devices[0]``.
    """
    first_yearless: datetime | None = None
    for event in events:
        parsed = _parse_event_ts(event.timestamp or "")
        if parsed is None:
            continue
        if parsed.year != _RFC3164_YEARLESS:
            return parsed
        if first_yearless is None:
            first_yearless = parsed
    if first_yearless is not None:
        return _restamp_yearless(first_yearless, _now())
    return _now()


def _anchor_dt(
    events: Iterable[ClassifiedEvent], ref: datetime | int | None,
) -> datetime | int:
    """Pass through an explicit restamp anchor; otherwise derive one."""
    if isinstance(ref, (datetime, int)):
        return ref
    return _reference_dt(events)


def _is_rollover_pair(parsed: datetime, ref: datetime) -> bool:
    """True when a yearless stamp and its anchor sit on opposite sides of 1 Jan."""
    return (
        (parsed.month in _YEARLESS_LATE and ref.month in _YEARLESS_EARLY)
        or (parsed.month in _YEARLESS_EARLY and ref.month in _YEARLESS_LATE)
    )


def _with_year(parsed: datetime, year: int) -> datetime:
    """``replace(year=…)`` that keeps 29 Feb parseable on a common year."""
    try:
        return parsed.replace(year=year)
    except ValueError:
        return parsed.replace(year=year, day=28)


def _restamp_yearless(parsed: datetime, ref: datetime) -> datetime:
    """Assign a calendar year so RFC3164 Dec/Jan rollovers stay ordered.

    A single global year put ``Dec 31`` after ``Jan 1`` of that year, so a
    year-end Junos commit lost ``devices[0]`` to a January sibling. Only
    wrap when the pair is actually a year boundary (Nov/Dec next to
    Jan/Feb). Blind nearest-year on a June ISO sibling restamped
    December into the previous year and inverted same-year order.
    """
    if not _is_rollover_pair(parsed, ref):
        return _with_year(parsed, ref.year)
    best: datetime | None = None
    best_delta: float | None = None
    for year in (ref.year - 1, ref.year, ref.year + 1):
        candidate = _with_year(parsed, year)
        delta = abs((candidate - ref).total_seconds())
        if best is None or delta < best_delta:
            best = candidate
            best_delta = delta
    assert best is not None
    return best


def event_time(event: ClassifiedEvent, year: datetime | int | None = None) -> datetime | None:
    """Best-effort naive datetime for ``event``, or None if the stamp is unknown.

    A datetime ``year`` is a restamp anchor: wrap only at a Nov/Dec–Jan/Feb
    boundary so year-end rollovers stay chronological without inverting
    a mid-year sibling. An int ``year`` is a literal calendar year
    (``Aug 29`` + ``2026`` stays ``2026-08-29``). ``None`` restamps
    against ``now()``.
    """
    parsed = _parse_event_ts(event.timestamp or "")
    if parsed is None:
        return None
    if parsed.year != _RFC3164_YEARLESS:
        return parsed
    if isinstance(year, datetime):
        return _restamp_yearless(parsed, year)
    if isinstance(year, int):
        try:
            return parsed.replace(year=year)
        except ValueError:
            return parsed.replace(year=year, day=28)
    return _restamp_yearless(parsed, _now())


def _event_sort_key(event: ClassifiedEvent, year: datetime | int) -> tuple[datetime, str]:
    """Chronological key. Unparseable stamps sort last so they cannot steal earliest."""
    return (event_time(event, year) or datetime.max, event.hostname or "")


def _event_gap_seconds(
    prev: ClassifiedEvent, nxt: ClassifiedEvent, year: datetime | int | None = None,
) -> float:
    ta = event_time(prev, year)
    tb = event_time(nxt, year)
    if ta is None or tb is None:
        # Unknown stamps stay in the current cluster; the caller falls
        # back to the newest missing rows when no gap can be found.
        return 0.0
    return abs((tb - ta).total_seconds())


def _gap_clusters(
    events: list[ClassifiedEvent], year: datetime | int | None = None,
) -> list[list[ClassifiedEvent]]:
    if not events:
        return []
    stamp_ref = _anchor_dt(events, year)
    clusters: list[list[ClassifiedEvent]] = [[events[0]]]
    for prev, event in zip(events, events[1:]):
        if _event_gap_seconds(prev, event, stamp_ref) >= _LEFTOVER_CLUSTER_GAP_S:
            clusters.append([event])
        else:
            clusters[-1].append(event)
    return clusters


def _is_stormish(cluster: list[ClassifiedEvent], storm_cats: set[str]) -> bool:
    """True when a gap-cluster carries a high/critical leftover-storm category."""
    return any(
        e.category in storm_cats and e.severity in _STORM_SEVERITY
        for e in cluster
    )


def _leftover_host_only(
    cluster: list[ClassifiedEvent], leftover_cats: set[str], leftover_hosts: set[str],
) -> bool:
    """True when leftover-category rows in ``cluster`` stay on leftover hosts."""
    return all(
        e.hostname in leftover_hosts
        for e in cluster
        if e.category in leftover_cats
    )


def _same_category_later_storm(
    leftover: list[ClassifiedEvent],
    leftover_cats: set[str],
    missing: list[ClassifiedEvent],
    stamp_year: int,
) -> list[ClassifiedEvent] | None:
    """Floor a later leftover-category storm; skip leftover overflow.

    Category-only skip treats a later routing collapse as leftover
    overflow. Taking the last high/critical leftover-category cluster
    then lets trailing leftover-signature flaps steal the floor, and a
    leftover-headed cluster (flaps resume, then BGP <60s later) fills
    the floor with leftover hosts. Keep the first later storm after
    leftover-host overflow; strip a leftover-host prefix that shares
    that cluster.
    """
    storm_cats = leftover_cats & _SAME_CATEGORY_STORM
    if not storm_cats:
        return None
    leftover_hosts = {e.hostname for e in leftover}
    leftover_last = leftover[-1]
    clusters = _gap_clusters(missing, stamp_year)
    idx = 0
    while idx < len(clusters):
        cluster = clusters[idx]
        if cluster[0].category not in leftover_cats:
            break
        # Leftover-host burst still abutting leftover[-1] is overflow.
        # A new-host storm (or a same-host storm after the 60s gap) is not.
        if (
            not _leftover_host_only(cluster, leftover_cats, leftover_hosts)
            or _event_gap_seconds(leftover_last, cluster[0], stamp_year)
            >= _LEFTOVER_CLUSTER_GAP_S
        ):
            break
        idx += 1
    remaining = clusters[idx:]
    stormish = [c for c in remaining if _is_stormish(c, storm_cats)]
    if not stormish:
        return None
    has_new_host = any(
        e.hostname not in leftover_hosts
        for cluster in stormish
        for e in cluster
        if e.category in storm_cats and e.severity in _STORM_SEVERITY
    )
    if has_new_host:
        stormish = [
            c for c in stormish
            if any(
                e.hostname not in leftover_hosts
                and e.category in storm_cats
                and e.severity in _STORM_SEVERITY
                for e in c
            )
        ]
    if not stormish:
        return None
    chosen = list(stormish[0])
    while (
        len(chosen) > 1
        and chosen[0].category in leftover_cats
        and chosen[0].hostname in leftover_hosts
        and any(
            e.hostname not in leftover_hosts
            and e.category in storm_cats
            and e.severity in _STORM_SEVERITY
            for e in chosen[1:]
        )
    ):
        chosen = chosen[1:]
    return chosen


def _later_storm_incidents(
    prefix: list[ClassifiedEvent],
    missing: list[ClassifiedEvent],
    year: datetime | int | None = None,
) -> list[ClassifiedEvent]:
    """Skip leftover overflow so the floor pulls the later outage.

    Resetting the leftover *count* is not enough when leftover flaps
    overflow the chronological cap: ``missing`` then starts with more
    morning flaps (or an intermediate leftover category), and a first-N
    pull never reaches the BGP storm. Drop leftover-category overflow
    even across a commit or time gap (not a later storm that merely
    starts soon after leftover flaps), drop later clusters that still
    share a leftover category (afternoon flaps of the same signature),
    and take the last remaining cluster.
    If leftover itself is a storm category (routing), a later
    high/critical cluster of that category is the outage — do not skip
    it as overflow or let trailing leftover-category / other-category /
    recovery rows win. Leftover-host flaps that resume immediately
    before that storm are still overflow.
    If every later cluster is leftover-category (same-signature storm)
    or stamps cannot be clustered, fall back to the last cluster / the
    newest floor-sized slice.
    """
    leftover = [e for e in prefix if e.category != "config"]
    if not leftover or not missing:
        return missing
    stamp_ref = _anchor_dt([*prefix, *missing], year)
    leftover_cats = {e.category for e in leftover}
    later_storm = _same_category_later_storm(
        leftover, leftover_cats, missing, stamp_ref,
    )
    if later_storm is not None:
        return later_storm
    idx = 0
    # Leftover-category overflow is leftover whether it abuts the prefix
    # or resumes after a commit / time gap. Requiring a <60s gap from
    # leftover[-1] left a leftover-headed burst that sat just before the
    # storm (typical: flaps → commit → more flaps → BGP) to swallow the
    # outage. Still do not skip a non-leftover storm that starts close
    # to leftover flaps.
    while idx < len(missing) and missing[idx].category in leftover_cats:
        idx += 1
    later = missing[idx:]
    if not later:
        return missing[-min(_TIMELINE_INCIDENT_FLOOR, len(missing)):]
    clusters = _gap_clusters(later, stamp_ref)
    preferred = [c for c in clusters if c[0].category not in leftover_cats]
    if not preferred:
        preferred = clusters
    return preferred[-1]


def _earliest_config_id(
    events: Iterable[ClassifiedEvent], year: datetime | int | None = None,
) -> int | None:
    """Object id of the earliest config row, if any.

    The change-window reserve pins this commit so a later noisy host cannot
    steal ``devices[0]``. The timeline floor evicts oldest commits to make
    room for a later storm — without protecting this row, that eviction
    hides the same causative commit the reserve just recovered.
    """
    rows = list(events)
    stamp_ref = _anchor_dt(rows, year)
    chosen: ClassifiedEvent | None = None
    chosen_key: tuple[datetime, str] | None = None
    for event in rows:
        if event.category != "config":
            continue
        key = _event_sort_key(event, stamp_ref)
        if chosen_key is None or key < chosen_key:
            chosen = event
            chosen_key = key
    return id(chosen) if chosen is not None else None


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
    stamp_ref = _reference_dt(rows)
    rows.sort(key=lambda e: _event_sort_key(e, stamp_ref))
    if len(rows) <= limit:
        return rows
    protect_id = _earliest_config_id(rows, stamp_ref)
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
        # Leftover earlier flaps do not satisfy the floor when a later
        # storm exists — whether a commit is in the window or not.
        # Gating the reset on config_in_window hid a two-phase outage
        # with no change window (morning flaps filling the cap, then
        # afternoon BGP on another device): leftover_budget stayed 0,
        # need stayed 0, and the storm never entered the timeline.
        leftover_budget = incidents
        incidents = 0
        missing_incidents = _later_storm_incidents(
            prefix, missing_incidents, stamp_ref,
        )
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
                if (
                    evicted_cfg < cfg_take
                    and e.category == "config"
                    and id(e) != protect_id
                ):
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
            kept.sort(key=lambda e: _event_sort_key(e, stamp_ref))
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
            if evicted < take and e.category == "config" and id(e) != protect_id:
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
        kept.sort(key=lambda e: _event_sort_key(e, stamp_ref))
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
    kept.sort(key=lambda e: _event_sort_key(e, stamp_ref))
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
    # noisiest late one. Must parse stamps — FRR/ISO vs RFC3164 vs Loki
    # epoch do not sort lexicographically.
    stamp_ref = _reference_dt(hits)
    hits.sort(key=lambda e: _event_sort_key(e, stamp_ref))
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
