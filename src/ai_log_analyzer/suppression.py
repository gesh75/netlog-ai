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
  down. Children are the same device's later higher-layer events and the
  remote ends of sessions that ride on it.

Device address ownership comes from the optional dependency map
(``AI_LOG_ANALYZER_DEPENDENCIES`` JSON file or ``site_manifest``) and is
learned from the logs themselves: syslog sender IP, FortiOS ``locip``, Junos
``Local-ip``, SD-WAN ``system_ip``, and the far end of a /30-/31 BGP session.

Dependency map format::

    {"devices": {"core-01": {"ips": ["10.0.0.0", "10.0.0.2"],
                             "children": ["leaf-01", "leaf-02"],
                             "ha_peer": "core-02", "role": "core"}}}
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ai_log_analyzer.correlate import _LAYER_BY_EVENT_TYPE, _short_host
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


@dataclass
class Topology:
    ips: dict[str, str] = field(default_factory=dict)          # ip → host
    children: dict[str, set[str]] = field(default_factory=dict)  # host → dependent hosts
    ha_peer: dict[str, str] = field(default_factory=dict)
    roles: dict[str, str] = field(default_factory=dict)

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


def _learn_ownership(events: Iterable[Any], topo: Topology) -> dict[str, tuple[str, str]]:
    """ip → (host, how) from the map plus what the devices themselves logged."""
    owned: dict[str, tuple[str, str]] = {ip: (host, "dependency_map") for ip, host in topo.ips.items()}
    for ev in events:
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


def suppress_alerts(
    events: Iterable[Any],
    topology: Topology | None = None,
    *,
    window_s: float = 300.0,
    hold_window_s: float = 240.0,
    min_children: int = 2,
) -> dict[str, Any]:
    """Group dependent failure events under their upstream root.

    Returns ``{"groups": [...], "suppressed_entities": [entity keys],
    "suppressed_events": n, "roots": n}``. Pure; never mutates events.
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
    owned = _learn_ownership(pool, topo)
    host_of = {id(e): _short_host(e.hostname) for e in pool}
    layer = {id(e): _LAYER_BY_EVENT_TYPE[e.event_type][0] for e in pool}

    def within(e: Any, t0: datetime | None, after: float, before: float = _CLOCK_SKEW_S) -> bool:
        t = times[id(e)]
        if t is None or t0 is None:
            return True
        delta = (t - t0).total_seconds()
        return -before <= delta <= after

    host_events: dict[str, list[Any]] = {}
    for e in pool:
        host_events.setdefault(host_of[id(e)], []).append(e)

    candidates: list[dict[str, Any]] = []
    ha_events = [o for o in pool if o.event_type == "ha_state"]
    # Platform roots (HA pair folded together).
    for e in pool:
        if e.event_type in _PLATFORM_TYPES:
            members = {host_of[id(e)]}
            peer = topo.ha_peer.get(host_of[id(e)])
            if e.event_type == "ha_state":
                if not peer:  # infer the peer: another same-vendor HA event close in time
                    peer = next((host_of[id(o)] for o in ha_events if o is not e
                                 and o.vendor == e.vendor and host_of[id(o)] != host_of[id(e)]
                                 and within(o, times[id(e)], 60.0, 60.0)), "")
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

    candidates.sort(key=lambda c: (_KIND_PRIORITY[c["kind"]], c["t0"] is None, c["t0"] or datetime.min))

    order = {id(e): i for i, e in enumerate(pool)}
    by_host: dict[str, list[Any]] = {}
    by_peer: dict[str, list[Any]] = {}
    for e in pool:
        by_host.setdefault(host_of[id(e)], []).append(e)
        if e.peer_ip:
            by_peer.setdefault(valid_ip(e.peer_ip) or e.peer_ip, []).append(e)

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
        # Indexed candidate set (same / dependent hosts + sessions to owned IPs),
        # then filtered in pool order — O(candidates) per root, not O(pool).
        seen: set[int] = set()
        maybe: list[Any] = []
        for h in hosts | dependents:
            maybe.extend(by_host.get(h, ()))
        for ip in owned_ips:
            maybe.extend(by_peer.get(ip, ()))
        children = []
        for e in sorted(maybe, key=lambda ev: order[id(ev)]):
            if id(e) in seen or e is root_ev or id(e) in claimed:
                continue
            seen.add(id(e))
            h = host_of[id(e)]
            if h in hosts:
                ok = layer[id(e)] >= root_layer and within(e, t0, hold_window_s)
            elif h in dependents:
                ok = within(e, t0, window_s)
            else:
                ok = within(e, t0, window_s)  # reached via a session to an owned address
            if ok:
                children.append(e)
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

    root_keys = {entity_key(e) for e in pool if id(e) in root_events}
    entity_root: dict[tuple[str, str, str], str] = {}
    for e in pool:
        key = entity_key(e)
        if key is not None and id(e) in claimed and id(e) not in root_events and key not in root_keys:
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
