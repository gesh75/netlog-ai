"""Fabric stability scoring — flap detection, volume bursts, 24h risk forecast.

Classified events tell you what broke; this module tells you what keeps
breaking. It tracks, per device:

  * **Flapping** — down→up→down oscillation of the same entity class
    (interface, BGP peer, OSPF neighbor, LAG member, VPN tunnel). A link that
    bounces six times an hour is a worse signal than one clean failure, but a
    severity-ranked action list shows them the same way.
  * **Volume bursts** — a device whose event rate spikes far above its own
    baseline is misbehaving even when every individual event looks routine.
  * **Trend** — whether a device's error activity is rising or falling across
    the analysis window, projected into a deterministic 24h risk band.

Everything is heuristic, streaming-safe (O(devices × entity classes) memory),
and dependency-free. Timestamps in network logs are unreliable — mixed
formats, missing entirely — so bucketing uses the minute prefix of whatever
timestamp string exists and falls back to arrival order.
"""
from __future__ import annotations

import re
from collections import OrderedDict
from dataclasses import dataclass, field

from ai_log_analyzer.classifier import ClassifiedEvent

# Descriptions that represent an entity going DOWN / coming back UP.
# Keyed by KB description (stable strings from the classifier), grouped into
# an entity class so "BGP peer down" and "BGP peer established" pair up.
_DOWN_DESCRIPTIONS: dict[str, str] = {
    "Interface link down": "interface",
    "BGP peer down / connect failure": "bgp",
    "BGP peer idle / notification": "bgp",
    "BGP notification / adjacency down (FRR/IOS)": "bgp",
    "OSPF neighbor state change": "ospf",
    "OSPF adjacency loss (FRR/IOS)": "ospf",
    "BFD session down": "bfd",
    "LACP/LAG member down": "lag",
    "LAG member leaving bundle": "lag",
    "VPN/IPsec tunnel failure": "vpn",
    "VRRP/gateway failover": "redundancy",
}
_UP_DESCRIPTIONS: dict[str, str] = {
    "Interface link up": "interface",
    "BGP peer established": "bgp",
    "OSPF neighbor established": "ospf",
    "LAG member joining bundle": "lag",
}

_ENTITY_LABELS: dict[str, str] = {
    "interface": "interface", "bgp": "BGP peer", "ospf": "OSPF neighbor",
    "bfd": "BFD session", "lag": "LAG member", "vpn": "VPN tunnel",
    "redundancy": "gateway redundancy",
}

# Strip trailing ":SS" / ":SS.mmm" so bucket keys have minute granularity.
_SECONDS_RE = re.compile(r":\d{2}(?:[.,]\d+)?\s*(?:Z|[+-]\d{2}:?\d{2})?$")

_MAX_BUCKETS_PER_HOST = 512
_ARRIVAL_BUCKET_SIZE = 200  # events per synthetic bucket when no timestamp


@dataclass
class _DeviceState:
    transitions: dict[str, int] = field(default_factory=dict)   # entity → down↔up flips
    last_state: dict[str, str] = field(default_factory=dict)    # entity → "down"|"up"
    downs: dict[str, int] = field(default_factory=dict)         # entity → down events
    criticals: int = 0
    highs: int = 0
    total: int = 0
    buckets: OrderedDict[str, int] = field(default_factory=OrderedDict)  # minute → count


class StabilityTracker:
    """Single-pass stability aggregator — feed every classified event."""

    def __init__(self) -> None:
        self._devices: dict[str, _DeviceState] = {}
        self._seq = 0

    def add(self, e: ClassifiedEvent) -> None:
        if not e.hostname:
            return
        st = self._devices.setdefault(e.hostname, _DeviceState())
        st.total += 1
        if e.severity == "critical":
            st.criticals += 1
        elif e.severity == "high":
            st.highs += 1

        entity = _DOWN_DESCRIPTIONS.get(e.description)
        if entity is not None:
            st.downs[entity] = st.downs.get(entity, 0) + 1
            if st.last_state.get(entity) == "up":
                st.transitions[entity] = st.transitions.get(entity, 0) + 1
            st.last_state[entity] = "down"
        else:
            entity = _UP_DESCRIPTIONS.get(e.description)
            if entity is not None:
                if st.last_state.get(entity) == "down":
                    st.transitions[entity] = st.transitions.get(entity, 0) + 1
                st.last_state[entity] = "up"

        # Minute-granularity bucket; arrival-order fallback for blank stamps.
        ts = e.timestamp or ""
        key = _SECONDS_RE.sub("", ts) if ts else f"seq-{self._seq // _ARRIVAL_BUCKET_SIZE}"
        st.buckets[key] = st.buckets.get(key, 0) + 1
        st.buckets.move_to_end(key)
        while len(st.buckets) > _MAX_BUCKETS_PER_HOST:
            st.buckets.popitem(last=False)
        self._seq += 1

    # ── report ────────────────────────────────────────────────────────────

    @staticmethod
    def _flap_count(st: _DeviceState) -> int:
        """Full flaps = completed down↔up round trips across all entities."""
        return sum(t // 2 for t in st.transitions.values())

    @staticmethod
    def _burst_ratio(st: _DeviceState) -> float:
        """Peak minute vs the device's own median minute (≥1.0)."""
        counts = sorted(st.buckets.values())
        if len(counts) < 3:
            return 1.0
        median = counts[len(counts) // 2] or 1
        return round(counts[-1] / median, 1)

    @staticmethod
    def _trend(st: _DeviceState) -> str:
        """Rising/stable/falling error activity across the window halves."""
        counts = list(st.buckets.values())
        if len(counts) < 4:
            return "stable"
        half = len(counts) // 2
        first, second = sum(counts[:half]) or 1, sum(counts[half:])
        ratio = second / first
        if ratio >= 1.5:
            return "rising"
        if ratio <= 0.67:
            return "falling"
        return "stable"

    @staticmethod
    def _score(st: _DeviceState, flaps: int, burst: float) -> int:
        score = 100
        score -= min(flaps * 6, 35)
        score -= min(st.criticals * 5, 25)
        score -= min(st.highs * 1, 15)
        if burst >= 10:
            score -= 20
        elif burst >= 5:
            score -= 12
        elif burst >= 3:
            score -= 6
        return max(0, score)

    @staticmethod
    def _risk(score: int, trend: str) -> str:
        if score < 50 or (score < 70 and trend == "rising"):
            return "high"
        if score < 70 or trend == "rising":
            return "medium"
        return "low"

    def report(self, top_n: int = 20) -> dict:
        """JSON-ready stability report: per-device scores, worst first."""
        devices: list[dict] = []
        for host, st in self._devices.items():
            flaps = self._flap_count(st)
            burst = self._burst_ratio(st)
            trend = self._trend(st)
            score = self._score(st, flaps, burst)
            worst_entity = max(st.transitions, key=st.transitions.get) if st.transitions else ""
            devices.append({
                "hostname": host,
                "score": score,
                "flaps": flaps,
                "flapping_entity": _ENTITY_LABELS.get(worst_entity, worst_entity),
                "criticals": st.criticals,
                "highs": st.highs,
                "events": st.total,
                "burst_ratio": burst,
                "trend": trend,
                "risk_24h": self._risk(score, trend),
            })
        devices.sort(key=lambda d: (d["score"], -d["flaps"]))

        if devices:
            # Weight by event volume so one noisy core drags more than a quiet leaf.
            total_events = sum(d["events"] for d in devices) or 1
            fabric = round(sum(d["score"] * d["events"] for d in devices) / total_events)
        else:
            fabric = 100

        return {
            "fabric_score": fabric,
            "device_count": len(devices),
            "devices": devices[:top_n],
            "recommendations": _recommendations(devices),
        }


def _recommendations(devices: list[dict]) -> list[str]:
    recs: list[str] = []
    for d in devices:
        if d["flaps"] >= 2 and d["flapping_entity"]:
            recs.append(
                f"{d['hostname']}: {d['flapping_entity']} flapped {d['flaps']}× — "
                f"dampen or fix the underlying link before it pages again"
            )
        if d["risk_24h"] == "high":
            recs.append(
                f"{d['hostname']}: high 24h risk (score {d['score']}, {d['trend']} trend) — "
                f"prioritize in the current shift"
            )
        if d["burst_ratio"] >= 5:
            recs.append(
                f"{d['hostname']}: event rate spiked {d['burst_ratio']}× above its median "
                f"minute — check for a rolling condition"
            )
        if len(recs) >= 8:
            break
    return recs[:8]
