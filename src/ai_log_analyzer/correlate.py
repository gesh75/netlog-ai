"""Cross-source device correlation.

Generalizes the DCN "device appears in Kibana AND LibreNMS" intersection
(DCN_AI_Intelligence/app.py:1778-1815) to N netlog-ai sources. A device that
surfaces actionable (>= medium) events from >=2 distinct sources is `confirmed`
(corroborated by independent telemetry); a device seen in exactly 1 source is
`suspected` (single-source, may be noise).
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ai_log_analyzer.classifier import LogEvent, classify_events
from ai_log_analyzer.hostnames import short_host
from ai_log_analyzer.url_redact import redact_text

# Severity rank used to pick a device's worst severity across sources.
_SEV_RANK: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _short_host(hostname: str) -> str:
    """Normalize a hostname to its short form (strip domain), lowercased."""
    return short_host(hostname)


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
    from ai_log_analyzer.sources.base import SourceError
    from ai_log_analyzer.sources.manager import manager as source_manager

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
            skipped[sid] = redact_text(str(exc))

    # Build a new dict rather than mutating correlate_sources()'s result,
    # whose contract is to return a fresh, self-contained dict.
    return {
        **correlate_sources(events_by_source, min_severity=min_severity),
        "skipped": skipped,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Cross-vendor entity correlation
# ─────────────────────────────────────────────────────────────────────────────
#
# Joins failure events across devices and vendors on the *entities* the
# parsers extracted — not on hostnames. Example: a FortiGate SD-WAN SLA miss
# on wan1 → FortiGate IPsec HQ-DC1 down (same egress interface) → Junos KMD
# VPN down (peer IP = FortiGate locip) → FortiGate BGP 169.254.10.1 down and
# Junos BGP 169.254.10.2 Idle (same /30 point-to-point subnet).

_LAYER_BY_EVENT_TYPE: dict[str, tuple[int, str]] = {
    "conserve_mode": (0, "platform"), "session_table": (0, "platform"), "ha_state": (0, "platform"),
    "interface_link": (1, "physical"), "lag_member": (1, "physical"), "optical": (1, "physical"),
    "sdwan_sla": (2, "transport"), "ipsec_tunnel": (2, "transport"), "ike_phase1": (2, "transport"),
    "ike_phase2": (2, "transport"), "bfd_session": (2, "transport"), "control_connection": (2, "transport"),
    "bgp_session": (3, "routing"), "bgp_max_prefix": (3, "routing"), "bgp_path_change": (3, "routing"),
    "ospf_adjacency": (3, "routing"), "omp_peer": (3, "routing"), "evpn": (4, "overlay"),
    "isis_adjacency": (3, "routing"), "ldp_session": (3, "routing"),
}
# Events less than this far apart are one instant: syslog stamps have 1 s
# resolution, so their arrival order says nothing about cause and effect.
_SAME_INSTANT_S = 1.0
_SEV_PRIORITY = {"critical": 0, "high": 1, "medium": 2}
_IP_ATTRS = ("remip", "locip", "tunnelip", "local_ip", "system_ip", "local_tloc_ip",
             "remote_tloc_ip", "src_ip", "dst_ip")
_P2P_EVENT_TYPES = frozenset({"bgp_session", "bgp_max_prefix", "ospf_adjacency"})
# shared_asn / same_vrf are deliberately not "strong": two drops towards the
# same transit AS are worth grouping, but on their own they do not prove a
# common cause the way a shared address or tunnel does.
_STRONG_EVIDENCE = frozenset({"shared_ip", "p2p_subnet", "same_interface", "same_tunnel"})

# ── ASN / VRF joins ─────────────────────────────────────────────────────────
# Event types whose ASN names the remote / origin AS (the parsers take it from
# "External AS 65010", "VRF default AS 65101", "remote-as", "origin AS").
_ASN_EVENT_TYPES = frozenset({"bgp_session", "bgp_max_prefix", "bgp_path_change", "omp_peer"})
# Not a real peer AS: unset, AS_TRANS (RFC 6793), and the last 16/32-bit ASNs.
_RESERVED_ASNS = frozenset({0, 23456, 65535, 4294967295})
# Routing tables every device has. Sharing one says nothing about a common
# cause, so these join only alongside a second routing identity (see below).
DEFAULT_VRF_NAMES = frozenset({
    "default", "global", "main", "0", "root", "mgmt",
    # vendor spellings of the same tables
    "master", "inet.0", "management", "mgmt-vrf", "default-vrf",
})
_ANOMALY_LAYERS = frozenset({"transport", "routing"})
_IBGP_RE = re.compile(r"\bInternal\s+AS\b|\biBGP\b", re.IGNORECASE)


def normalize_asn(value: Any) -> str:
    """Canonical asplain ASN string, or "" when unusable.

    Accepts "65010", "AS65010", "as65010" and asdot "1.10" (= 65546).
    Reserved / placeholder ASNs come back as "".
    """
    raw = str(value or "").strip().lower().removeprefix("as").strip()
    if not raw:
        return ""
    try:
        if "." in raw:
            hi, lo = raw.split(".", 1)
            num = int(hi) * 65536 + int(lo)
        else:
            num = int(raw)
    except ValueError:
        return ""
    if num in _RESERVED_ASNS or not 0 < num < 2**32:
        return ""
    return str(num)


def normalize_vrf(value: Any) -> str:
    """Lowercased VRF / virtual-router name ("" when unset)."""
    return str(value or "").strip().lower()


def root_sort_key(layer: int, when: datetime | None, tiebreak: Any = ()) -> tuple:
    """Sort key shared by correlation and suppression to name an incident's root.

    The root is the lowest-layer event, then the earliest (untimed events
    last), then ``tiebreak`` (event content, never arrival order, so that the
    same events in any order name the same root).
    """
    return (layer, when is None, when or datetime.min, tiebreak)


def _entity_of(ev: Any) -> str:
    return getattr(ev, "peer_ip", "") or getattr(ev, "tunnel_id", "") or getattr(ev, "interface", "") or ""


def _content_key(ev: Any) -> tuple[str, ...]:
    """Arrival-order-independent identity used as the final sort tiebreak."""
    return (_short_host(ev.hostname), ev.event_type or "", _entity_of(ev).lower(),
            getattr(ev, "description", "") or "", getattr(ev, "timestamp", "") or "",
            getattr(ev, "severity", "") or "")


def _pool_key(ev: Any) -> tuple[str, str, str, str]:
    return (_short_host(ev.hostname), ev.event_type or "", _entity_of(ev).lower(),
            getattr(ev, "state", "") or "")


def _pool_warning(dropped: int, collapsed: int, limit: int) -> str:
    if not (dropped or collapsed):
        return ""
    bits = []
    if collapsed:
        bits.append(f"collapsed {collapsed} repeated event(s) to their first and last occurrence")
    if dropped:
        bits.append(f"dropped {dropped} lower-severity / later event(s) over the {limit}-event limit")
    return "Correlation input was bounded: " + " and ".join(bits) + "; incidents may be incomplete."


def bound_events(events: list[Any], max_events: int) -> tuple[list[Any], int, int]:
    """Bound a correlation pool: ``(events, dropped, collapsed)``.

    Within the limit nothing changes. Over it, repeats of the same
    (host, event type, entity, state) collapse to their first AND last
    occurrence (a flap storm keeps its span), then, if still over, the
    most severe events win and the rest are dropped. Arrival order is kept.
    """
    if len(events) <= max_events:
        return events, 0, 0
    first: dict[tuple, int] = {}
    last: dict[tuple, int] = {}
    for i, ev in enumerate(events):
        k = _pool_key(ev)
        first.setdefault(k, i)
        last[k] = i
    keep = sorted(set(first.values()) | set(last.values()))
    collapsed = len(events) - len(keep)
    dropped = max(0, len(keep) - max_events)
    if dropped:
        ranked = sorted(keep, key=lambda i: (_SEV_PRIORITY.get(getattr(events[i], "severity", ""), 3), i))
        keep = sorted(ranked[:max_events])
    return [events[i] for i in keep], dropped, collapsed


class CorrelationPool:
    """Streaming, bounded intake for ``correlate_entities`` / ``suppress_alerts``.

    ``analyze()`` feeds every failure event through ``add``. Keeping the first
    N in arrival order lets a noisy storm starve a real incident that arrives
    later; instead, once the buffer grows past twice the limit, repeats of the
    same (host, event type, entity, state) collapse to their first and last
    occurrence and, if that is not enough, the most severe events win.
    Memory stays O(2 x max_events). Small inputs are never touched.
    """

    def __init__(self, max_events: int = 2000) -> None:
        self.max_events = max_events
        self._buf: list[Any] = []
        self._collapsed = 0
        self._dropped = 0

    def add(self, ev: Any) -> None:
        self._buf.append(ev)
        if len(self._buf) > 2 * self.max_events:
            self._compact()

    def _compact(self) -> None:
        buf = self._buf
        first: dict[tuple, int] = {}
        last: dict[tuple, int] = {}
        for i, ev in enumerate(buf):
            k = _pool_key(ev)
            first.setdefault(k, i)
            last[k] = i
        keep = sorted(set(first.values()) | set(last.values()))
        self._collapsed += len(buf) - len(keep)
        room = self.max_events * 3 // 2
        if len(keep) > room:
            ranked = sorted(keep, key=lambda i: (_SEV_PRIORITY.get(getattr(buf[i], "severity", ""), 3), i))
            self._dropped += len(keep) - room
            keep = sorted(ranked[:room])
        self._buf = [buf[i] for i in keep]

    def events(self) -> list[Any]:
        kept, dropped, collapsed = bound_events(self._buf, self.max_events)
        self._dropped += dropped
        self._collapsed += collapsed
        self._buf = kept
        return list(kept)

    @property
    def dropped(self) -> int:
        return self._dropped

    @property
    def collapsed(self) -> int:
        return self._collapsed

    @property
    def warning(self) -> str:
        return _pool_warning(self._dropped, self._collapsed, self.max_events)

    def __len__(self) -> int:
        return len(self._buf)


def _active_anomaly(ev: Any) -> bool:
    """A routing or transport failure that is still down (not a recovery or a notice)."""
    layer = _layer(ev)
    if layer is None or layer[1] not in _ANOMALY_LAYERS:
        return False
    state = getattr(ev, "state", "") or ""
    return state == "down" or (not state and ev.event_type in ("bgp_max_prefix", "bgp_path_change"))


def _is_ibgp(ev: Any) -> bool:
    return bool(_IBGP_RE.search(getattr(ev, "message", "") or ""))


def _local_asns(events: Iterable[Any]) -> frozenset[str]:
    """ASNs seen on iBGP sessions in this batch: the network's own AS(es)."""
    return frozenset(a for ev in events
                     if getattr(ev, "event_type", "") in _ASN_EVENT_TYPES and _is_ibgp(ev)
                     and (a := normalize_asn(getattr(ev, "asn", ""))))


def _peer_asn(ev: Any, local_asns: frozenset[str] = frozenset()) -> str:
    """The remote / origin AS of a routing event, or "" for iBGP and unknowns.

    iBGP sessions report the network's own AS, which every iBGP session
    shares, so they never join on it. Some vendors (EOS, FRR) do not mark a
    session as iBGP, so an AS that appears on any iBGP session in the batch
    is treated as local too.
    """
    if ev.event_type not in _ASN_EVENT_TYPES or _is_ibgp(ev):
        return ""
    asn = normalize_asn(getattr(ev, "asn", ""))
    return "" if asn in local_asns else asn


def _layer(ev: Any) -> tuple[int, str] | None:
    return _LAYER_BY_EVENT_TYPE.get(getattr(ev, "event_type", "") or "")


def _join_keys(ev: Any, local_asns: frozenset[str] = frozenset()) -> list[tuple[str, str]]:
    """(evidence, key) pairs an event can be joined on."""
    from ai_log_analyzer.parsers.entities import valid_ip

    host = _short_host(ev.hostname)
    attrs = getattr(ev, "attrs", {}) or {}
    ips = {valid_ip(ev.peer_ip)} | {valid_ip(attrs.get(k)) for k in _IP_ATTRS}
    ips.discard("")
    keys: list[tuple[str, str]] = [("shared_ip", f"ip:{ip}") for ip in sorted(ips)]
    # Both ends of a /30 or /31 point-to-point routing session name each
    # other's address. Only session peers qualify — system IPs / TLOCs are
    # loopback-style identifiers and would join unrelated devices.
    p2p = {valid_ip(ev.peer_ip)} if ev.event_type in _P2P_EVENT_TYPES else set()
    p2p |= {valid_ip(attrs.get("tunnelip"))}
    for ip in sorted(p2p - {""}):
        if ipaddress.ip_address(ip).version == 4:
            for plen in (30, 31):
                keys.append(("p2p_subnet", f"p2p:{ipaddress.ip_network(f'{ip}/{plen}', strict=False)}"))
    if ev.interface:
        keys.append(("same_interface", f"if:{host}:{ev.interface.lower()}"))
    if ev.tunnel_id:
        keys.append(("same_tunnel", f"tun:{host}:{ev.tunnel_id.lower()}"))
    # Several devices losing sessions to the same external / origin AS at once
    # (a transit or peer outage, a route leak) is one incident.
    asn = _peer_asn(ev, local_asns)
    if asn and _active_anomaly(ev):
        keys.append(("shared_asn", f"asn:{asn}"))
    # A tenant VRF failing on several devices is one incident. Default-like
    # tables are on every device: they join only paired with an active
    # routing / tunnel anomaly towards the same peer AS, never on their own.
    vrf = normalize_vrf(getattr(ev, "vrf", ""))
    if vrf and vrf not in DEFAULT_VRF_NAMES:
        keys.append(("same_vrf", f"vrf:{vrf}"))
    elif vrf and asn and _active_anomaly(ev):
        keys.append(("same_vrf", f"vrf:{vrf}|AS{asn}"))
    return keys


def correlate_entities(
    events: Iterable[Any],
    *,
    window_s: float = 300.0,
    same_device_window_s: float = 60.0,
    hold_window_s: float = 240.0,
    max_events: int = 2000,
) -> dict[str, Any]:
    """Cluster failure events that share entities into cross-vendor incidents.

    Considers events with a known layer (platform → physical → transport →
    routing → overlay) that are not recoveries. Two events join when they
    share an entity key (IP, /30-/31 p2p subnet, device interface, device
    tunnel, external / origin ASN, tenant VRF) within ``window_s``, or sit on
    the same device within ``same_device_window_s`` with the later one at the
    same or a higher layer (events under a second apart count as simultaneous,
    so the result never depends on arrival order).
    A transport → routing step on one device may take up to ``hold_window_s``
    (a BGP hold timer expires up to 180-240 s after the tunnel under it dies).
    Each cluster that spans >= 2 devices, vendors or layers is an incident;
    its root comes from ``root_sort_key``: lowest layer, then earliest, then a
    content-based tiebreak (the same rule ``suppress_alerts`` uses).
    Untimed events join only other untimed events.

    ASN and VRF joins carry noise guardrails: ASNs join only on active
    (non-recovered) routing / transport failures and never for iBGP, the
    local AS or reserved ASNs; default-like VRFs (``DEFAULT_VRF_NAMES``) never
    join on their own, only paired with the same external AS. Neither counts
    as strong evidence, so an ASN- or VRF-only incident stays "medium"; so
    does one whose parts are joined only by same-device timing (an unrelated
    tunnel and BGP session on one device). Devices that merely lose sessions
    to the same external AS are siblings, not downstream of each other: such an
    incident is rooted at the shared AS, not at one of the devices.

    Over ``max_events`` the pool is deduplicated (first and last occurrence of
    each host / type / entity / state), then cut to the most severe events;
    ``dropped`` and ``collapsed`` count what was lost and ``warning`` says so.
    """
    from ai_log_analyzer.causal import _reference_dt, event_time

    events = list(events)
    local_asns = _local_asns(events)
    pool = [e for e in events
            if _layer(e) is not None and getattr(e, "state", "") != "up"
            and getattr(e, "severity", "info") in ("critical", "high", "medium")]
    pool, dropped, collapsed = bound_events(pool, max_events)
    note = ({"collapsed": collapsed, "warning": _pool_warning(dropped, collapsed, max_events)}
            if collapsed or dropped else {})
    if not pool:
        return {"incidents": [], "events_considered": 0, "dropped": dropped, **note}

    ref = _reference_dt(pool)
    times = [event_time(e, ref) for e in pool]
    layers = [_layer(e)[0] for e in pool]
    content = [_content_key(e) for e in pool]
    parent = list(range(len(pool)))
    eparent = list(range(len(pool)))   # entity-based edges only (no same-device timing)
    edges: dict[int, set[tuple[str, str]]] = {}

    def find(par: list[int], i: int) -> int:
        while par[i] != i:
            par[i] = par[par[i]]
            i = par[i]
        return i

    def union(a: int, b: int, evidence: tuple[str, str]) -> None:
        for par in (parent,) if evidence[0] == "same_device_temporal" else (parent, eparent):
            ra, rb = find(par, a), find(par, b)
            if ra != rb:
                par[rb] = ra
        edges.setdefault(a, set()).add(evidence)
        edges.setdefault(b, set()).add(evidence)

    def gap(a: int, b: int) -> float | None:
        ta, tb = times[a], times[b]
        return None if ta is None or tb is None else abs((tb - ta).total_seconds())

    def close(a: int, b: int, limit: float) -> bool:
        g = gap(a, b)
        if g is None:  # an untimed event joins only another untimed one
            return times[a] is None and times[b] is None
        return g <= limit

    def order_key(i: int) -> tuple:
        return (times[i] is None, times[i] or datetime.min, layers[i], content[i])

    def order(idx: list[int]) -> list[int]:
        return sorted(idx, key=order_key)

    by_key: dict[str, list[int]] = {}
    evidence_of: dict[str, str] = {}
    for i, ev in enumerate(pool):
        for evidence, key in _join_keys(ev, local_asns):
            by_key.setdefault(key, []).append(i)
            evidence_of[key] = evidence
    for key, members in by_key.items():
        if len(members) < 2:
            continue
        ordered = order(members)
        for a, b in zip(ordered, ordered[1:]):
            if close(a, b, window_s):
                union(a, b, (evidence_of[key], key.split(":", 1)[1]))

    by_host: dict[str, list[int]] = {}
    for i, ev in enumerate(pool):
        by_host.setdefault(_short_host(ev.hostname), []).append(i)
    for host, members in by_host.items():
        ordered = order(members)
        for a, b in zip(ordered, ordered[1:]):
            la, lb = _layer(pool[a]), _layer(pool[b])
            g = gap(a, b)
            simultaneous = g is not None and g <= _SAME_INSTANT_S
            if not (la and lb and (simultaneous or la[0] <= lb[0])):
                continue
            limit = hold_window_s if la[1] == "transport" and lb[1] == "routing" else same_device_window_s
            if close(a, b, limit):
                union(a, b, ("same_device_temporal", host))

    clusters: dict[int, list[int]] = {}
    for i in range(len(pool)):
        clusters.setdefault(find(parent, i), []).append(i)

    incidents: list[dict[str, Any]] = []
    for members in clusters.values():
        if len(members) < 2:
            continue
        hosts = {_short_host(pool[i].hostname) for i in members}
        vendors = {pool[i].vendor for i in members if pool[i].vendor}
        if len(hosts) < 2 and len(vendors) < 2 and len({layers[i] for i in members}) < 2:
            continue
        ordered = order(members)
        root = min(members, key=lambda i: root_sort_key(layers[i], times[i], content[i]))
        evidence = sorted({e for i in members for e in edges.get(i, ())})
        kinds = {e[0] for e in evidence}
        root_first = all(times[root] is None or times[i] is None or times[root] <= times[i] for i in members)
        # Parts that share no entity and are held together only by same-device
        # timing. Parts over the same devices (a tunnel and the BGP session riding
        # it) or nested ones are one story; parts with devices of their own (tunnel
        # A-B, then an unrelated ISP session A-C) are two incidents on one box.
        parts: dict[int, set[str]] = {}
        for i in members:
            parts.setdefault(find(eparent, i), set()).add(_short_host(pool[i].hostname))
        chain_sets = sorted(parts.values(), key=len)
        bridged = any(not a <= b for a, b in zip(chain_sets, chain_sets[1:]))
        # Cross-device joins are always entity-based; "high" needs at least one
        # entity join, a root that really came first and no timing-only bridge.
        confidence = "high" if kinds & _STRONG_EVIDENCE and root_first and not bridged else "medium"
        incidents.append(_incident(pool, ordered, root, hosts, vendors, evidence, confidence))

    incidents.sort(key=lambda inc: (-inc["device_count"], -inc["event_count"], inc["summary"]))
    return {"incidents": incidents, "events_considered": len(pool), "dropped": dropped, **note}


def _incident(pool, ordered, root, hosts, vendors, evidence, confidence) -> dict[str, Any]:
    def step(i: int) -> dict[str, Any]:
        ev = pool[i]
        layer = _layer(ev)
        return {
            "hostname": ev.hostname, "vendor": ev.vendor, "event_type": ev.event_type,
            "layer": layer[1] if layer else "", "description": ev.description,
            "severity": ev.severity, "timestamp": ev.timestamp,
            "entity": ev.peer_ip or ev.tunnel_id or ev.interface or "",
        }

    seen: set[tuple[str, str, str]] = set()
    chain: list[dict[str, Any]] = []
    for i in ordered:
        s = step(i)
        sig = (s["hostname"], s["event_type"], s["entity"])
        if sig in seen:
            continue
        seen.add(sig)
        chain.append(s)
    r = step(root)
    symptoms = [c for c in chain if (c["hostname"], c["event_type"], c["entity"]) !=
                (r["hostname"], r["event_type"], r["entity"])]
    effect_layers = sorted({c["layer"] for c in symptoms if c["layer"]})
    shared_asns = sorted({k for t, k in evidence if t == "shared_asn"}, key=int)
    shared_vrfs = sorted({k.split("|", 1)[0] for t, k in evidence if t == "same_vrf"})
    kinds = {t for t, _ in evidence}
    if (shared_asns or shared_vrfs) and kinds <= {"shared_asn", "same_vrf"} and len(hosts) >= 2:
        # Siblings that lost sessions to the same outside party: nothing among
        # them is upstream of the others, so root the incident at that party.
        what = f"AS{shared_asns[0]}" if shared_asns else f"VRF {shared_vrfs[0]}"
        sev = min((pool[i].severity for i in ordered), key=lambda v: _SEV_PRIORITY.get(v, 3))
        r = {"hostname": what, "vendor": "", "event_type": "external_as" if shared_asns else "shared_vrf",
             "layer": "routing", "description": f"Sessions lost to {what}", "severity": sev,
             "timestamp": next((pool[i].timestamp for i in ordered if pool[i].timestamp), ""), "entity": what}
        symptoms = chain
        summary = f"{len(hosts)} devices lost sessions to {what}" + (
            f" [{', '.join(effect_layers)}]" if effect_layers else "")
    else:
        summary = (f"{r['description']} on {r['hostname']} ({r['vendor'] or 'unknown'}, {r['layer']}) → "
                   f"{len(symptoms)} downstream event(s) across {len(hosts)} device(s)"
                   + (f" [{', '.join(effect_layers)}]" if effect_layers else ""))
    if shared_asns:
        summary += f"; shared peer AS {', '.join(f'AS{a}' for a in shared_asns)}"
    if shared_vrfs:
        summary += f"; VRF {', '.join(shared_vrfs)}"
    return {
        "root_cause": r,
        "chain": chain[:15],
        "symptoms": symptoms[:15],
        "devices": sorted(hosts),
        "vendors": sorted(vendors),
        "device_count": len(hosts),
        "event_count": len(ordered),
        "evidence": [{"type": k, "key": v} for k, v in evidence[:20]],
        "shared": {"asn": shared_asns, "vrf": shared_vrfs},
        "confidence": confidence,
        "summary": summary,
    }
