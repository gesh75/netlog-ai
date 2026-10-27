"""Topology-aware alert suppression.

When an upstream element fails, every dependent session and interface below
it alerts too. This module groups those child alerts under the root, so the
operator sees one incident instead of an alert storm. Upstream elements are
a core/WAN router, a firewall HA pair, or an SD-WAN / IPsec transport.

Root kinds, strongest first:

* ``platform``: firewall HA failover / split-brain (the HA peer is folded in),
  conserve mode, session-table exhaustion.
* ``device_unreachable``: a device whose own addresses at least
  ``min_children`` other devices lose sessions to. It is inferred even if the
  dead device logged nothing, which is the classic core-router storm.
  Declared topology children of a failing device are grouped too.
* ``transport``: SD-WAN SLA / BFD / control-connection, IPsec / IKE, or link
  down. Children are the same device's later events that share an entity
  with it (interface, tunnel, address) or follow promptly at a higher layer,
  and the remote ends of sessions that ride on it. Roots are tried lowest
  layer first, then earliest (``correlate.root_sort_key``, shared with the
  entity correlator).

Device address ownership comes from the optional dependency map
(``AI_LOG_ANALYZER_DEPENDENCIES`` JSON file or ``site_manifest``) and is
learned from the logs themselves: FortiOS ``locip``, Junos ``Local-ip``,
SD-WAN ``system_ip``, and the far end of a /30-/31 BGP session. Text a sender
writes is forgeable, so for events that reached the syslog listener (they carry
``sender_ip``) a claim counts only when the dependency map binds that sender
address to the host the line names (or lists it as a trusted relay that
forwards for other devices); the map's own addresses always win. Logs with no
transport information (files, uploads) are taken as the operator supplied
them. The same rule decides which events may pair up as HA peers.

Dependency map format::

    {"devices": {"core-01": {"ips": ["10.0.0.0", "10.0.0.2"],
                             "children": ["leaf-01", "leaf-02"],
                             "ha_peer": "core-02", "role": "core"}},
     "relays": ["192.0.2.50"]}

``ips`` should include the address the device sends syslog from. ``relays``
lists collectors / managers that forward other devices' logs.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
from bisect import bisect_left, bisect_right
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ai_log_analyzer.correlate import (
    _LAYER_BY_EVENT_TYPE,
    _STRONG_EVIDENCE,
    _content_key,
    _join_keys,
    _short_host,
    root_sort_key,
)
from ai_log_analyzer.entity_state import entity_key
from ai_log_analyzer.parsers.entities import valid_ip

log = logging.getLogger(__name__)

_OWN_IP_ATTRS = ("sender_ip", "locip", "local_ip", "system_ip", "local_tloc_ip")
_ROUTING_TYPES = frozenset({"bgp_session", "bgp_max_prefix", "ospf_adjacency", "omp_peer"})
_TRANSPORT_TYPES = frozenset({"sdwan_sla", "ipsec_tunnel", "ike_phase1", "ike_phase2", "bfd_session",
                              "control_connection", "interface_link", "lag_member"})
_PLATFORM_TYPES = frozenset({"ha_state", "conserve_mode", "session_table"})
_KIND_PRIORITY = {"platform": 0, "device_unreachable": 1, "transport": 2}
_CLOCK_SKEW_S = 30.0
_PHYSICAL_LAYER = _LAYER_BY_EVENT_TYPE["interface_link"][0]
_ROUTING_LAYER = _LAYER_BY_EVENT_TYPE["bgp_session"][0]


@dataclass
class Topology:
    ips: dict[str, str] = field(default_factory=dict)          # ip → host
    children: dict[str, set[str]] = field(default_factory=dict)  # host → dependent hosts
    ha_peer: dict[str, str] = field(default_factory=dict)
    roles: dict[str, str] = field(default_factory=dict)
    relays: set[str] = field(default_factory=set)              # sender addresses trusted to name any host

    def owner(self, ip: str) -> str:
        return self.ips.get(ip, "")


def load_topology(manifest: Mapping[str, Any] | None = None, path: str | None = None) -> Topology:
    """Dependency map from a JSON file (or ``AI_LOG_ANALYZER_DEPENDENCIES``) and/or a manifest."""
    topo = Topology()
    blobs: list[Mapping[str, Any]] = []
    path = path or os.environ.get("AI_LOG_ANALYZER_DEPENDENCIES", "").strip()
    if path:
        try:
            with open(path, encoding="utf-8") as fh:
                blobs.append(json.load(fh))
        except (OSError, ValueError) as exc:
            log.warning("dependency map %s unreadable: %s", path, exc)
    if manifest:
        blobs.append(manifest)
    for blob in blobs:
        for relay in blob.get("relays") or []:
            if valid_ip(str(relay)):
                topo.relays.add(valid_ip(str(relay)))
        devices = blob.get("devices") or {}
        items = devices.items() if isinstance(devices, Mapping) else (
            (d.get("hostname") or d.get("name"), d) for d in devices if isinstance(d, Mapping))
        for host, spec in items:
            if not host or not isinstance(spec, Mapping):
                continue
            h = _short_host(str(host))
            for ip in spec.get("ips") or ([spec["mgmt_ip"]] if spec.get("mgmt_ip") else []):
                if valid_ip(str(ip)):
                    topo.ips[valid_ip(str(ip))] = h
            for child in spec.get("children") or []:
                topo.children.setdefault(h, set()).add(_short_host(str(child)))
            if spec.get("ha_peer"):
                peer = _short_host(str(spec["ha_peer"]))
                topo.ha_peer[h], topo.ha_peer[peer] = peer, h
            if spec.get("role"):
                topo.roles[h] = str(spec["role"])
    return topo


def _p2p_far_end(ip: str) -> str:
    """The other usable address of the /31 or /30 an IPv4 peer sits in."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return ""
    n = int(addr)
    if (n & 3) in (1, 2):  # usable host of a /30 → the other usable host
        return str(ipaddress.IPv4Address(n ^ 3))
    return str(ipaddress.IPv4Address(n ^ 1))  # /31 pair


def _trusted_origin(ev: Any, topo: Topology) -> bool:
    """May this event teach us addresses or HA pairings?

    An event from the syslog listener carries the sender address the transport saw; its text (hostname,
    ``locip=``, BGP neighbour) is whatever that sender chose to write, so it is believed only when the
    dependency map says that sender is the host the line names (or a relay it lists). No sender
    address: not a network event (file / upload), nothing to check it against.
    """
    sender = valid_ip((getattr(ev, "attrs", None) or {}).get("sender_ip"))
    return not sender or sender in topo.relays or topo.ips.get(sender) == _short_host(ev.hostname)


def _learn_ownership(events: Iterable[Any], topo: Topology) -> dict[str, tuple[str, str]]:
    """ip → (host, how) from the map plus what the devices themselves logged."""
    owned: dict[str, tuple[str, str]] = {ip: (host, "dependency_map") for ip, host in topo.ips.items()}
    for ev in events:
        if not _trusted_origin(ev, topo):
            continue
        host = _short_host(ev.hostname)
        attrs = getattr(ev, "attrs", {}) or {}
        for key in _OWN_IP_ATTRS:
            ip = valid_ip(attrs.get(key))
            if ip and ip not in owned:
                owned[ip] = (host, key)
        if ev.event_type in _ROUTING_TYPES and ev.peer_ip:
            far = _p2p_far_end(ev.peer_ip)
            if far and far not in owned:
                owned[far] = (host, "p2p_inferred")
    return owned


def _root_id(kind: str, host: str, stamp: str) -> str:
    return "ROOT-" + hashlib.sha1(f"{kind}|{host}|{stamp}".encode()).hexdigest()[:8].upper()


def _brief(ev: Any) -> dict[str, Any]:
    return {"hostname": ev.hostname, "vendor": ev.vendor, "event_type": ev.event_type,
            "description": ev.description, "severity": ev.severity, "timestamp": ev.timestamp,
            "entity": ev.peer_ip or ev.tunnel_id or ev.interface or ""}


def _infer_ha_peers(ha_events: list[Any], host_of: dict[int, str], secs: dict[int, float | None]) -> dict[int, str]:
    """id(event) → the other same-vendor host with an HA event within 60 s.

    One sort + two linear passes (nearest earlier / later event of a different
    host) instead of a scan of every HA event per event. An untimed event pairs
    with the first other host of its vendor.
    """
    peer: dict[int, str] = {}
    by_vendor: dict[str, list[Any]] = {}
    for e in ha_events:
        by_vendor.setdefault(e.vendor, []).append(e)
    for evs in by_vendor.values():
        timed = sorted((e for e in evs if secs[id(e)] is not None), key=lambda e: secs[id(e)])
        for seq in (timed, timed[::-1]):
            last: Any = None
            other_last: Any = None
            for e in seq:
                h = host_of[id(e)]
                cand = last if last is not None and host_of[id(last)] != h else other_last
                if cand is not None and abs(secs[id(e)] - secs[id(cand)]) <= 60.0:
                    peer.setdefault(id(e), host_of[id(cand)])
                if last is None or host_of[id(last)] != h:
                    other_last = last
                last = e
        all_hosts = list(dict.fromkeys(host_of[id(e)] for e in evs))
        untimed_hosts = list(dict.fromkeys(host_of[id(e)] for e in evs if secs[id(e)] is None))
        for e in evs:  # untimed stamps match anything
            if id(e) not in peer:
                other = next((x for x in (all_hosts if secs[id(e)] is None else untimed_hosts)
                              if x != host_of[id(e)]), "")
                if other:
                    peer[id(e)] = other
    return peer


def suppress_alerts(
    events: Iterable[Any],
    topology: Topology | None = None,
    *,
    window_s: float = 300.0,
    hold_window_s: float = 240.0,
    same_device_window_s: float = 60.0,
    min_children: int = 2,
) -> dict[str, Any]:
    """Group dependent failure events under their upstream root.

    Returns ``{"groups": [...], "suppressed_entities": [entity keys],
    "suppressed_events": n, "roots": n}``. Pure; never mutates events.

    A transport / physical event (SD-WAN SLA, IPsec, BFD, link down, LAG
    member) claims a later event on the SAME device only when it shares an
    entity with it (interface, tunnel, peer / local address, p2p subnet; within
    ``hold_window_s``) or is a higher-layer follow-on within
    ``same_device_window_s``. A link root never claims same-layer events, and
    same-device children must not predate their root (cross-device children
    get ``_CLOCK_SKEW_S`` of tolerance). Roots are tried lowest layer first,
    then earliest: the same rule as ``correlate.root_sort_key``.
    """
    from ai_log_analyzer.causal import _reference_dt, event_time

    topo = topology or Topology()
    pool = [e for e in events
            if e.event_type in _LAYER_BY_EVENT_TYPE and getattr(e, "state", "") != "up"
            and e.severity in ("critical", "high", "medium")]
    if not pool:
        return {"groups": [], "suppressed_entities": [], "suppressed_events": 0, "roots": 0}
    ref = _reference_dt(pool)
    times: dict[int, datetime | None] = {id(e): event_time(e, ref) for e in pool}
    secs: dict[int, float | None] = {k: (v - datetime.min).total_seconds() if v is not None else None
                                     for k, v in times.items()}
    owned = _learn_ownership(pool, topo)
    host_of = {id(e): _short_host(e.hostname) for e in pool}
    layer = {id(e): _LAYER_BY_EVENT_TYPE[e.event_type][0] for e in pool}
    order = {id(e): i for i, e in enumerate(pool)}

    def delta(e: Any, t0: datetime | None) -> float | None:
        a, b = secs[id(e)], (t0 - datetime.min).total_seconds() if t0 is not None else None
        return None if a is None or b is None else a - b

    def within(e: Any, t0: datetime | None, after: float, before: float = _CLOCK_SKEW_S) -> bool:
        d = delta(e, t0)
        return True if d is None else -before <= d <= after

    # Per-host, per-layer events by time (bisect) plus the untimed ones, so a
    # root looks only at the events inside its window and layer range instead
    # of every event on the host.
    by_host: dict[str, list[Any]] = {}
    for e in pool:
        by_host.setdefault(host_of[id(e)], []).append(e)
    host_timed: dict[tuple[str, int], tuple[list[float], list[Any]]] = {}
    host_untimed: dict[tuple[str, int], list[Any]] = {}
    host_layers: dict[str, set[int]] = {}
    for h, evs in by_host.items():
        for lyr in {layer[id(e)] for e in evs}:
            host_layers.setdefault(h, set()).add(lyr)
            lyr_evs = [e for e in evs if layer[id(e)] == lyr]
            timed = sorted((e for e in lyr_evs if secs[id(e)] is not None),
                           key=lambda e: (secs[id(e)], order[id(e)]))
            host_timed[(h, lyr)] = ([secs[id(e)] for e in timed], timed)
            host_untimed[(h, lyr)] = [e for e in lyr_evs if secs[id(e)] is None]

    def host_window(h: str, t0: datetime | None, before: float, after: float, min_layer: int = 0) -> list[Any]:
        out: list[Any] = []
        base = (t0 - datetime.min).total_seconds() if t0 is not None else 0.0
        for lyr in host_layers.get(h, ()):
            if lyr < min_layer:
                continue
            stamps, timed = host_timed[(h, lyr)]
            if t0 is None:
                out.extend(timed)
            else:
                out.extend(timed[bisect_left(stamps, base - before):bisect_right(stamps, base + after)])
            out.extend(host_untimed[(h, lyr)])
        return out

    by_peer: dict[str, list[Any]] = {}
    for e in pool:
        if e.peer_ip:
            by_peer.setdefault(valid_ip(e.peer_ip) or e.peer_ip, []).append(e)
    host_events = by_host
    strong_keys: dict[int, list[str]] = {}
    by_entity: dict[str, list[Any]] = {}   # shared-entity key → events carrying it
    for e in pool:
        ks = strong_keys[id(e)] = [k for kind, k in _join_keys(e) if kind in _STRONG_EVIDENCE]
        for k in ks:
            by_entity.setdefault(k, []).append(e)

    candidates: list[dict[str, Any]] = []
    ha_events = [o for o in pool if o.event_type == "ha_state" and _trusted_origin(o, topo)]
    ha_peer = _infer_ha_peers(ha_events, host_of, secs) if ha_events else {}
    # Platform roots (HA pair folded together).
    for e in pool:
        if e.event_type in _PLATFORM_TYPES:
            members = {host_of[id(e)]}
            peer = topo.ha_peer.get(host_of[id(e)])
            if e.event_type == "ha_state":
                peer = peer or ha_peer.get(id(e), "")  # infer: another same-vendor HA event close in time
                if peer:
                    members.add(peer)
            candidates.append({"kind": "platform", "event": e, "hosts": members,
                               "t0": times[id(e)], "label": e.description})
    # Inferred device-unreachable roots: >= min_children other devices lose
    # sessions/tunnels to addresses this device owns.
    lost_to: dict[str, list[Any]] = {}
    for e in pool:
        if e.event_type in _ROUTING_TYPES | _TRANSPORT_TYPES and e.peer_ip:
            owner = owned.get(valid_ip(e.peer_ip) or e.peer_ip, ("", ""))[0]
            if owner and owner != host_of[id(e)]:
                lost_to.setdefault(owner, []).append(e)
    for owner, evs in lost_to.items():
        reporters = {host_of[id(e)] for e in evs}
        if len(reporters) >= min_children or owner in topo.children:
            first = min(evs, key=lambda e: (times[id(e)] is None, times[id(e)] or datetime.min))
            own_events = host_events.get(owner, [])
            candidates.append({"kind": "device_unreachable", "event": own_events[0] if own_events else None,
                               "hosts": {owner}, "t0": times[id(first)],
                               "label": f"{owner} unreachable — {len(reporters)} dependent device(s) lost sessions",
                               "reporters": sorted(reporters), "inferred": not own_events})
    # Declared-topology parents with their own failure.
    for parent in topo.children:
        own = host_events.get(parent, [])
        if own and parent not in lost_to:
            first = min(own, key=lambda e: (times[id(e)] is None, times[id(e)] or datetime.min))
            candidates.append({"kind": "device_unreachable", "event": first, "hosts": {parent},
                               "t0": times[id(first)], "label": f"{parent} failure (upstream of "
                               f"{len(topo.children[parent])} device(s))", "inferred": False})
    # Transport roots.
    for e in pool:
        if e.event_type in _TRANSPORT_TYPES:
            candidates.append({"kind": "transport", "event": e, "hosts": {host_of[id(e)]},
                               "t0": times[id(e)], "label": e.description})

    def cand_key(c: dict[str, Any]) -> tuple:
        ev = c["event"]
        lyr = layer[id(ev)] if c["kind"] == "transport" else 0
        return (_KIND_PRIORITY[c["kind"]],
                root_sort_key(lyr, c["t0"], _content_key(ev) if ev is not None else (c["label"],)))

    candidates.sort(key=cand_key)

    claimed: dict[int, str] = {}
    root_events: set[int] = set()
    groups: list[dict[str, Any]] = []
    for cand in candidates:
        root_ev = cand["event"]
        if root_ev is not None and id(root_ev) in claimed:
            continue  # already explained by a stronger / earlier root
        hosts: set[str] = cand["hosts"]
        dependents = set().union(*(topo.children.get(h, set()) for h in hosts))
        owned_ips = {ip for ip, (h, _how) in owned.items() if h in hosts}
        root_layer = layer[id(root_ev)] if root_ev is not None else 0
        t0 = cand["t0"]
        # A link / tunnel / SLA root explains same-device events only through a
        # shared entity or a prompt higher-layer follow-on; platform and
        # device-unreachable roots take the whole device.
        narrow = cand["kind"] == "transport"
        root_keys = set(strong_keys[id(root_ev)]) if narrow else set()
        root_host = host_of[id(root_ev)] if root_ev is not None else ""
        # Indexed candidate set (same / dependent hosts + sessions to owned IPs),
        # then filtered — O(window) per root, not O(pool). A narrow root takes
        # same-device events only above its own layer (the prompt follow-on)
        # or through a shared entity.
        maybe: list[Any] = []
        reach = max(window_s, hold_window_s)
        for h in hosts | dependents:
            own = h in hosts
            maybe.extend(host_window(h, t0, _CLOCK_SKEW_S if h != root_host else 0.0,
                                     (hold_window_s if root_layer != _PHYSICAL_LAYER else same_device_window_s) if own and narrow else reach,
                                     root_layer + 1 if own and narrow else root_layer if own else 0))
        if narrow:
            for k in root_keys:
                maybe.extend(x for x in by_entity.get(k, ()) if host_of[id(x)] in hosts)
        for ip in owned_ips:
            maybe.extend(by_peer.get(ip, ()))
        seen: set[int] = set()
        children = []
        for e in maybe:
            if id(e) in seen or e is root_ev or id(e) in claimed:
                continue
            seen.add(id(e))
            h = host_of[id(e)]
            if h in hosts:
                before = 0.0 if h == root_host else _CLOCK_SKEW_S
                higher = layer[id(e)] > root_layer
                if layer[id(e)] < root_layer:
                    ok = False
                elif not narrow:
                    ok = within(e, t0, hold_window_s, before)
                elif root_keys.intersection(strong_keys[id(e)]):
                    # same interface / tunnel / address; a link never explains another link
                    ok = (higher or root_layer != _PHYSICAL_LAYER) and within(e, t0, hold_window_s, before)
                elif higher:
                    # prompt higher-layer follow-on; a tunnel / SLA root also gets the BGP hold timer
                    limit = hold_window_s if root_layer != _PHYSICAL_LAYER and layer[id(e)] == _ROUTING_LAYER \
                        else same_device_window_s
                    ok = within(e, t0, limit, before)
                else:
                    ok = False
            elif h in dependents:
                ok = within(e, t0, window_s)
            else:
                ok = within(e, t0, window_s)  # reached via a session to an owned address
            if ok:
                children.append(e)
        children.sort(key=lambda ev: order[id(ev)])
        if not children:
            continue
        rid = _root_id(cand["kind"], ",".join(sorted(hosts)), str(t0))
        for e in children:
            claimed[id(e)] = rid
        if root_ev is not None:
            claimed[id(root_ev)] = rid
            root_events.add(id(root_ev))
        child_hosts = sorted({host_of[id(e)] for e in children} - hosts)
        groups.append({
            "id": rid,
            "kind": cand["kind"],
            "root": _brief(root_ev) if root_ev is not None else {"hostname": next(iter(hosts)),
                                                                 "event_type": "device_unreachable"},
            "root_hosts": sorted(hosts),
            "label": cand["label"],
            "inferred": bool(cand.get("inferred", False)),
            "children": [_brief(e) for e in children[:50]],
            "child_devices": child_hosts,
            "suppressed_count": len(children),
            "summary": (f"{cand['label']} on {', '.join(sorted(hosts))}: {len(children)} dependent alert(s)"
                        + (f" across {len(child_hosts)} other device(s)" if child_hosts else "")),
        })

    root_keys_ent = {entity_key(e) for e in pool if id(e) in root_events}
    entity_root: dict[tuple[str, str, str], str] = {}
    for e in pool:
        key = entity_key(e)
        if key is not None and id(e) in claimed and id(e) not in root_events and key not in root_keys_ent:
            entity_root.setdefault(key, claimed[id(e)])
    return {
        "groups": groups,
        "suppressed_entities": [{"entity": list(k), "root": r} for k, r in sorted(entity_root.items())],
        "suppressed_events": sum(g["suppressed_count"] for g in groups),
        "roots": len(groups),
    }


def suppressed_entity_map(result: Mapping[str, Any]) -> dict[tuple[str, str, str], str]:
    """entity key → root id, from a ``suppress_alerts`` result."""
    return {tuple(item["entity"]): item["root"] for item in result.get("suppressed_entities", [])}
