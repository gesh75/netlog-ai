"""Down → up state pairing per network entity.

A classic regex classifier sees "BGP peer 10.0.0.1 down" and raises a HIGH
outage — even when the same peer came back 20 seconds later. This module
pairs transitions on the *same entity* (device + BGP peer / interface /
tunnel / SD-WAN SLA / BFD session / OMP peer / control connection …) and
labels each one:

    active     last transition is down, no matching recovery
    recovered  went down, then a matching up (outage length reported)
    flapping   >= flap_threshold down transitions inside flap_window_s
    up         only up transitions seen (no incident)

Memory is bounded: at most ``max_entities`` entities and ``max_transitions``
transitions each (oldest dropped). Timestamps are interpreted with the same
RFC 3164 year-inference as the causal console so mixed-vendor streams order
consistently; unparseable stamps fall back to arrival order.
"""
from __future__ import annotations

import os
from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from types import SimpleNamespace
from typing import Any

from ai_log_analyzer.causal import _reference_dt, event_time

EntityKey = tuple[str, str, str]   # (hostname, kind, id)

_KIND_BY_EVENT_TYPE: dict[str, str] = {
    "bgp_session": "bgp", "bgp_max_prefix": "bgp",
    "interface_link": "intf",
    "ipsec_tunnel": "tunnel", "ike_phase1": "tunnel", "ike_phase2": "tunnel",
    "sdwan_sla": "sla",
    "bfd_session": "bfd",
    "omp_peer": "omp",
    "control_connection": "control",
    "ospf_adjacency": "ospf",
    "lag_member": "lag",
    "conserve_mode": "conserve",
}
_STATUS_RANK = {"active": 0, "flapping": 1, "recovered": 2, "up": 3}


def _env_int(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, "") or default))
    except ValueError:
        return default


def entity_key(ev: Any) -> EntityKey | None:
    """Stable identity of the network object an event is about, or None."""
    kind = _KIND_BY_EVENT_TYPE.get(getattr(ev, "event_type", "") or "")
    if not kind:
        return None
    host = (getattr(ev, "hostname", "") or "").lower()
    attrs = getattr(ev, "attrs", {}) or {}
    if kind == "bgp":
        ident = ev.peer_ip and f"{ev.vrf or 'default'}|{ev.peer_ip}"
    elif kind in ("intf", "lag"):
        ident = ev.interface
    elif kind == "tunnel":
        ident = ev.tunnel_id or ev.peer_ip
    elif kind == "sla":
        ident = f"{attrs.get('healthcheck', '')}|{ev.interface}" if (attrs.get("healthcheck") or ev.interface) else ""
    elif kind in ("bfd", "control"):
        ident = ev.tunnel_id or ev.peer_ip
    elif kind in ("omp", "ospf"):
        ident = ev.peer_ip or ev.interface
    else:  # conserve
        ident = "memory"
    if not ident:
        return None
    return (host, kind, ident.lower())


@dataclass
class EntityState:
    hostname: str
    kind: str
    entity: str
    status: str
    current_state: str
    downs: int
    ups: int
    first_down: str
    last_change: str
    outage_seconds: float | None
    vendor: str
    event_type: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname, "kind": self.kind, "entity": self.entity,
            "status": self.status, "current_state": self.current_state,
            "downs": self.downs, "ups": self.ups, "first_down": self.first_down,
            "last_change": self.last_change, "outage_seconds": self.outage_seconds,
            "vendor": self.vendor, "event_type": self.event_type,
        }


class EntityStateTracker:
    """Streaming collector of per-entity down/up transitions."""

    def __init__(
        self,
        flap_threshold: int | None = None,
        flap_window_s: int | None = None,
        max_entities: int = 5000,
        max_transitions: int = 32,
    ) -> None:
        self.flap_threshold = flap_threshold or _env_int("AI_LOG_ANALYZER_FLAP_THRESHOLD", 3)
        self.flap_window_s = flap_window_s or _env_int("AI_LOG_ANALYZER_FLAP_WINDOW_S", 600)
        self.max_entities = max_entities
        self.max_transitions = max_transitions
        # key → {"t": [(timestamp, seq, state)], "vendor", "event_type", "display"}
        self._entities: OrderedDict[EntityKey, dict[str, Any]] = OrderedDict()
        self.dropped_entities = 0

    def add(self, ev: Any, seq: int) -> EntityKey | None:
        state = getattr(ev, "state", "")
        if state not in ("down", "up"):
            return None
        key = entity_key(ev)
        if key is None:
            return None
        slot = self._entities.get(key)
        if slot is None:
            if len(self._entities) >= self.max_entities:
                self._entities.popitem(last=False)
                self.dropped_entities += 1
            slot = {"t": [], "vendor": ev.vendor, "event_type": ev.event_type,
                    "host": ev.hostname}
            self._entities[key] = slot
        slot["t"].append((ev.timestamp or "", seq, state))
        if len(slot["t"]) > self.max_transitions:
            del slot["t"][0]
        return key

    def __len__(self) -> int:
        return len(self._entities)

    def report(self) -> dict[EntityKey, EntityState]:
        ref = _reference_dt(
            SimpleNamespace(timestamp=ts) for slot in self._entities.values() for ts, _, _ in slot["t"][:1]
        )
        out: dict[EntityKey, EntityState] = {}
        for key, slot in self._entities.items():
            out[key] = self._state_for(key, slot, ref)
        return out

    def _state_for(self, key: EntityKey, slot: dict[str, Any], ref: datetime) -> EntityState:
        timed = []
        for ts, seq, state in slot["t"]:
            when = event_time(SimpleNamespace(timestamp=ts), ref) if ts else None
            timed.append((when, seq, state, ts))
        # Chronological when every stamp parses; otherwise arrival order.
        if all(t[0] is not None for t in timed):
            timed.sort(key=lambda t: (t[0], t[1]))
        else:
            timed.sort(key=lambda t: t[1])

        downs: list[tuple[datetime | None, str]] = []
        ups = 0
        current = ""
        last_change = ""
        outage: float | None = None
        last_down_at: datetime | None = None
        for when, _seq, state, ts in timed:
            if state == current:
                continue  # repeated "down" while already down is one outage
            current = state
            last_change = ts
            if state == "down":
                downs.append((when, ts))
                last_down_at = when
            else:
                ups += 1
                if last_down_at is not None and when is not None:
                    outage = (when - last_down_at).total_seconds()

        flapping = self._is_flapping([d[0] for d in downs])
        if flapping:
            status = "flapping"
        elif not downs:
            status = "up"
        elif current == "up":
            status = "recovered"
        else:
            status = "active"
            outage = None
        return EntityState(
            hostname=slot["host"], kind=key[1], entity=key[2], status=status,
            current_state=current, downs=len(downs), ups=ups,
            first_down=downs[0][1] if downs else "", last_change=last_change,
            outage_seconds=outage if status != "active" else None,
            vendor=slot["vendor"], event_type=slot["event_type"],
        )

    def _is_flapping(self, down_times: list[datetime | None]) -> bool:
        n = self.flap_threshold
        if len(down_times) < n:
            return False
        if any(t is None for t in down_times):
            return True  # no clock → count alone decides
        times = sorted(t for t in down_times if t is not None)
        return any(
            (times[i + n - 1] - times[i]).total_seconds() <= self.flap_window_s
            for i in range(len(times) - n + 1)
        )


def summarize(states: Iterable[EntityState], limit: int = 50) -> dict[str, Any]:
    """JSON-ready roll-up for AnalysisResult.entity_states."""
    items = sorted(states, key=lambda s: (_STATUS_RANK.get(s.status, 9), s.hostname, s.entity))
    counts: dict[str, int] = {}
    for s in items:
        counts[s.status] = counts.get(s.status, 0) + 1
    return {"counts": counts, "entities": [s.to_dict() for s in items[:limit]],
            "total": len(items)}


def group_state(keys: Iterable[EntityKey], report: dict[EntityKey, EntityState]) -> tuple[str, dict[str, Any]]:
    """Status for an action-item group from its member entities."""
    states = [report[k] for k in keys if k in report]
    if not states:
        return "", {}
    counts: dict[str, int] = {}
    for s in states:
        counts[s.status] = counts.get(s.status, 0) + 1
    if counts.get("active"):
        status = "active"
    elif counts.get("flapping"):
        status = "flapping"
    elif counts.get("recovered"):
        status = "recovered"
    else:
        status = "up"
    detail = {
        "counts": counts,
        "entities": [s.to_dict() for s in sorted(
            states, key=lambda s: (_STATUS_RANK.get(s.status, 9), s.hostname, s.entity))[:10]],
    }
    return status, detail
