"""Protocol-aware EVPN causality — bipartite underlay/overlay suppression.

Classifies fabric syslog into OSI-ish layers (physical → LAG → underlay →
VTEP → EVPN overlay), picks the lowest-layer root causes, and suppresses
higher-layer symptoms on the same or adjacent device inside a propagation
window. Cytoscape elements are opt-in for the topology overlay.

Telemetry fusion (optical / counter interlocking) is a follow-up — no
optical or interface-counter sources are present in-tree yet.
"""
from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any

_RFC3164_MONTHS = {
    name: idx
    for idx, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}


class ProtocolLayer(IntEnum):
    L1_PHYSICAL = 1
    L2_LAG_MLAG = 2
    L3_UNDERLAY = 3
    L4_VTEP_NVE = 4
    L5_OVERLAY_EVPN = 5
    UNKNOWN = 99


_LAYER_SIGNATURES: tuple[tuple[ProtocolLayer, re.Pattern[str], str], ...] = (
    (
        ProtocolLayer.L1_PHYSICAL,
        re.compile(
            r"LINEPROTO-5-UPDOWN.*down|LINK-3-UPDOWN.*down|SNMP_TRAP_LINK_DOWN|"
            r"OPTICAL_PWR_LOW|RX_LOS|FCS_ERR|CRC_ERR|TRANSCEIVER_FAULT|carrier\s+down",
            re.IGNORECASE,
        ),
        "Physical / link-down",
    ),
    (
        ProtocolLayer.L2_LAG_MLAG,
        re.compile(
            r"LACP.*(down|suspended|detached|timeout)|MLAG.*(inactive|down|peer-link)|"
            r"BUNDLE_MEMBER_DOWN|AE_BUNDLE_DOWN",
            re.IGNORECASE,
        ),
        "LAG / MLAG member down",
    ),
    (
        ProtocolLayer.L3_UNDERLAY,
        re.compile(
            r"BFDD_TRAP_SHOP_DOWN|BFD.*(Down|Expired|Timeout)|"
            r"OSPF.*(DOWN|NbrDown)|ISIS.*(ADJDOWN|Lost)|"
            r"(BGP-5-ADJCHANGE|RPD_BGP_NEIGHBOR_STATE_CHANGED|bgpd)"
            r"(?!.*EVPN).*(Down|Idle|Active|Notification)",
            re.IGNORECASE,
        ),
        "Underlay routing / BFD / IGP / BGP",
    ),
    (
        ProtocolLayer.L4_VTEP_NVE,
        re.compile(
            r"VTEP.*(down|unreachable)|VXLAN_TUNNEL_DOWN|"
            r"NVE.*(down|peer\s+lost)|ENCAP_NEXTHOP_UNREACHABLE",
            re.IGNORECASE,
        ),
        "VTEP / NVE / VXLAN tunnel down",
    ),
    (
        ProtocolLayer.L5_OVERLAY_EVPN,
        re.compile(
            r"EVPN.*(withdraw|down|mac-move|duplicate|flap)|"
            r"TYPE[-_]?[2345].*(withdraw|unreachable)|"
            r"MAC_MOVE_LIMIT|DUPLICATE_MAC|"
            r"BGP.*EVPN.*(Down|Notification)",
            re.IGNORECASE,
        ),
        "EVPN overlay withdraw / MAC-move",
    ),
)

_TRUTHY = frozenset({"1", "true", "yes", "on"})


def is_evpn_causal_enabled() -> bool:
    """True when ``AI_LOG_ANALYZER_EVPN_CAUSAL`` is set. Default off."""
    return os.environ.get("AI_LOG_ANALYZER_EVPN_CAUSAL", "").strip().lower() in _TRUTHY


_INTF_EXTRACT_RE = re.compile(
    r"\b(?:"
    r"TenGigabitEthernet|GigabitEthernet|FastEthernet|FortyGigE|HundredGigE|"
    r"Port-Channel|Management|Loopback|Ethernet|Vxlan|Vlan|"
    r"eth|swp|po|ae|vlan|"
    r"xe-|et-|ge-|"
    r"irb\.|lo0\."
    r")\d+(?:[/.:]\d+)*\b",
    re.IGNORECASE,
)
_VNI_EXTRACT_RE = re.compile(
    r"\b(?:vni|vxlan)[-:\s#]*(\d{2,8})\b",
    re.IGNORECASE,
)


def classify_message(message: str) -> tuple[ProtocolLayer, str]:
    """Return (layer, human summary) for a raw syslog body.

    Overlay EVPN (L5) is checked before underlay BGP (L3) so
    ``bgpd: BGP EVPN neighbor Down`` is not stolen by the L3 signature.
    """
    text = message or ""
    overlay_first = (
        ProtocolLayer.L1_PHYSICAL,
        ProtocolLayer.L2_LAG_MLAG,
        ProtocolLayer.L4_VTEP_NVE,
        ProtocolLayer.L5_OVERLAY_EVPN,
        ProtocolLayer.L3_UNDERLAY,
    )
    by_layer = {layer: (pattern, summary) for layer, pattern, summary in _LAYER_SIGNATURES}
    for layer in overlay_first:
        pattern, summary = by_layer[layer]
        if pattern.search(text):
            return layer, summary
    return ProtocolLayer.UNKNOWN, "Unclassified fabric event"


def extract_interface(message: str) -> str:
    match = _INTF_EXTRACT_RE.search(message or "")
    return match.group(0) if match else ""


def extract_vni(message: str) -> str:
    match = _VNI_EXTRACT_RE.search(message or "")
    return match.group(1) if match else ""


def _plane(layer: ProtocolLayer) -> str:
    """underlay (L1–L3) vs overlay (L4–L5). Exhaustive over ProtocolLayer."""
    if layer in (
        ProtocolLayer.L1_PHYSICAL,
        ProtocolLayer.L2_LAG_MLAG,
        ProtocolLayer.L3_UNDERLAY,
    ):
        return "underlay"
    if layer in (ProtocolLayer.L4_VTEP_NVE, ProtocolLayer.L5_OVERLAY_EVPN):
        return "overlay"
    if layer is ProtocolLayer.UNKNOWN:
        return "unknown"
    raise AssertionError(f"unhandled ProtocolLayer: {layer}")


def _layer_label(layer: ProtocolLayer) -> str:
    return layer.name


def _event_id(timestamp: str, device: str, raw_message: str) -> str:
    raw = f"{timestamp}|{device}|{raw_message}".encode()
    return hashlib.sha1(raw).hexdigest()[:12]


def _as_datetime(stamp: str) -> datetime | None:
    """ISO / RFC5424, FRR, and RFC3164 (yearless → 2026 sentinel)."""
    if not stamp:
        return None
    text = stamp.strip()
    iso = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(iso)
        if parsed.tzinfo is not None:
            return parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    except ValueError:
        pass
    collapsed = " ".join(text.split())
    for fmt in ("%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(collapsed, fmt)
        except ValueError:
            continue
    parts = collapsed.split()
    if len(parts) >= 3 and parts[0][:3] in _RFC3164_MONTHS:
        try:
            day = int(parts[1])
            time_part = parts[2].split(".")[0]
            hour, minute, sec = (int(p) for p in time_part.split(":"))
            return datetime(
                2026, _RFC3164_MONTHS[parts[0][:3]], day, hour, minute, sec,
            )
        except ValueError:
            return None
    return None


@dataclass
class FabricEvent:
    event_id: str
    timestamp: str
    device: str
    raw_message: str
    layer: ProtocolLayer
    summary: str
    interface: str = ""
    vni: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "device": self.device,
            "raw_message": self.raw_message,
            "layer": self.layer.name,
            "layer_value": int(self.layer),
            "summary": self.summary,
            "interface": self.interface,
            "vni": self.vni,
        }

    @property
    def instant(self) -> datetime | None:
        return _as_datetime(self.timestamp)


@dataclass
class CausalHypothesis:
    root_cause: FabricEvent
    suppressed_symptoms: list[FabricEvent] = field(default_factory=list)
    affected_devices: list[str] = field(default_factory=list)
    affected_vnis: list[str] = field(default_factory=list)
    confidence: float = 0.0
    rationale: str = ""

    @property
    def symptom_suppression_ratio(self) -> float:
        total = len(self.suppressed_symptoms) + 1
        return len(self.suppressed_symptoms) / total

    def to_cytoscape_elements(self) -> list[dict[str, Any]]:
        """Cytoscape elements: nodes ``device:LAYER``, causal_propagation edges.

        Overlay-plane edges (target layer ≥ L4) are dashed.
        """
        elements: list[dict[str, Any]] = []
        seen: set[str] = set()

        def _add_node(event: FabricEvent, role: str) -> str:
            node_id = f"{event.device}:{_layer_label(event.layer)}"
            if node_id not in seen:
                seen.add(node_id)
                elements.append({
                    "data": {
                        "id": node_id,
                        "label": f"{event.device} {_layer_label(event.layer)}",
                        "device": event.device,
                        "layer": _plane(event.layer),
                        "causal_role": role,
                        "summary": event.summary,
                    },
                    "classes": f"causal-node causal-{role} plane-{_plane(event.layer)}",
                })
            return node_id

        root_id = _add_node(self.root_cause, "root_cause")
        for idx, symptom in enumerate(self.suppressed_symptoms):
            dest = _add_node(symptom, "suppressed_symptom")
            dashed = symptom.layer >= ProtocolLayer.L4_VTEP_NVE
            elements.append({
                "data": {
                    "id": f"{root_id}->{dest}:{idx}",
                    "source": root_id,
                    "target": dest,
                    "kind": "causal_propagation",
                },
                "classes": (
                    "causal_propagation causal-dashed" if dashed
                    else "causal_propagation"
                ),
            })
        return elements

    def to_dict(self) -> dict[str, Any]:
        return {
            "root_cause": self.root_cause.to_dict(),
            "suppressed_symptoms": [s.to_dict() for s in self.suppressed_symptoms],
            "affected_devices": list(self.affected_devices),
            "affected_vnis": list(self.affected_vnis),
            "confidence": self.confidence,
            "rationale": self.rationale,
            "symptom_suppression_ratio": self.symptom_suppression_ratio,
            "cytoscape_elements": self.to_cytoscape_elements(),
        }


def _normalize_adjacency(
    adjacency_map: Mapping[str, Iterable[str]] | None,
) -> dict[str, set[str]]:
    adj: dict[str, set[str]] = {}
    if not adjacency_map:
        return adj
    for src, neighbors in adjacency_map.items():
        if not src:
            continue
        adj.setdefault(src, set())
        for dst in neighbors or []:
            if not dst or dst == src:
                continue
            adj.setdefault(src, set()).add(dst)
            adj.setdefault(dst, set()).add(src)
    return adj


def _link_ends(link: Any) -> tuple[str, str]:
    if isinstance(link, (tuple, list)) and len(link) >= 2:
        return str(link[0] or ""), str(link[1] or "")
    if not isinstance(link, dict):
        return "", ""
    a = link.get("a") or link.get("source") or link.get("src") or link.get("left") or ""
    b = link.get("b") or link.get("target") or link.get("dst") or link.get("right") or ""
    return str(a), str(b)


def adjacency_from_manifest(manifest: Mapping[str, Any] | None) -> dict[str, set[str]]:
    """Build an undirected adjacency map from a site / NetBox manifest.

    Preference: explicit ``adjacency`` → ``links`` / ``cables`` → Clos
    heuristic (every spine adjacent to every leaf) from ``devices``.
    """
    if not manifest:
        return {}
    raw_adj = manifest.get("adjacency")
    if isinstance(raw_adj, dict) and raw_adj:
        return _normalize_adjacency(raw_adj)

    adj: dict[str, set[str]] = {}
    for key in ("links", "cables"):
        for link in manifest.get(key) or []:
            left, right = _link_ends(link)
            if left and right and left != right:
                adj.setdefault(left, set()).add(right)
                adj.setdefault(right, set()).add(left)
    if adj:
        return adj

    spines: list[str] = []
    leafs: list[str] = []
    for device in manifest.get("devices") or []:
        if not isinstance(device, dict):
            continue
        host = str(device.get("hostname") or device.get("name") or "")
        if not host:
            continue
        role = str(device.get("role") or "").lower()
        if role in {"spine", "superspine"}:
            spines.append(host)
        elif role == "leaf":
            leafs.append(host)
    for spine in spines:
        for leaf in leafs:
            adj.setdefault(spine, set()).add(leaf)
            adj.setdefault(leaf, set()).add(spine)
    return adj


def fabric_event_from_raw(
    raw_message: str,
    *,
    timestamp: str = "",
    device: str = "",
) -> FabricEvent:
    layer, summary = classify_message(raw_message)
    return FabricEvent(
        event_id=_event_id(timestamp, device, raw_message),
        timestamp=timestamp,
        device=device,
        raw_message=raw_message,
        layer=layer,
        summary=summary,
        interface=extract_interface(raw_message),
        vni=extract_vni(raw_message),
    )


def _coerce_event(item: Any) -> FabricEvent | None:
    if isinstance(item, FabricEvent):
        return item
    if isinstance(item, str):
        line = item.strip()
        if not line:
            return None
        return fabric_event_from_raw(line)
    if item is None:
        return None
    timestamp = str(
        getattr(item, "timestamp", None)
        or getattr(item, "t", None)
        or ""
    )
    device = str(
        getattr(item, "hostname", None)
        or getattr(item, "device", None)
        or getattr(item, "host", None)
        or ""
    )
    message = str(
        getattr(item, "message", None)
        or getattr(item, "raw_message", None)
        or getattr(item, "sample_message", None)
        or getattr(item, "description", None)
        or ""
    )
    if not message:
        return None
    return fabric_event_from_raw(message, timestamp=timestamp, device=device)


def _seconds_apart(a: FabricEvent, b: FabricEvent) -> float | None:
    ta, tb = a.instant, b.instant
    if ta is None or tb is None:
        return None
    if ta.tzinfo is not None:
        ta = ta.astimezone(timezone.utc).replace(tzinfo=None)
    if tb.tzinfo is not None:
        tb = tb.astimezone(timezone.utc).replace(tzinfo=None)
    return abs((tb - ta).total_seconds())


def _score_hypothesis(
    root: FabricEvent,
    symptoms: Sequence[FabricEvent],
    adjacent_hits: int,
    window: float,
) -> tuple[float, str]:
    confidence = 0.40
    if root.layer is not ProtocolLayer.UNKNOWN:
        confidence += 0.15
    if symptoms:
        confidence += min(0.30, 0.06 * len(symptoms))
    if adjacent_hits:
        confidence += 0.10
    if symptoms:
        max_gap = max((s.layer - root.layer for s in symptoms), default=0)
        if max_gap >= 2:
            confidence += 0.10
    confidence = min(0.95, round(confidence, 3))

    names = ", ".join(sorted({s.device for s in symptoms})) or "none"
    rationale = (
        f"{root.device or 'unknown'} {root.summary} "
        f"({_layer_label(root.layer)}) is the lowest-layer event; "
        f"{len(symptoms)} higher-layer symptom(s) on {names} "
        f"within {int(window)}s were suppressed."
    )
    return confidence, rationale


class EVPNBipartiteCausalEngine:
    """Suppress overlay symptoms that follow an underlay root cause."""

    def __init__(
        self,
        adjacency_map: Mapping[str, Iterable[str]] | None = None,
        max_propagation_window_sec: float = 120,
    ) -> None:
        self.adjacency_map = _normalize_adjacency(adjacency_map)
        self.max_propagation_window_sec = float(max_propagation_window_sec)

    @classmethod
    def from_site_manifest(
        cls,
        manifest: Mapping[str, Any] | None,
        adjacency_map: Mapping[str, Iterable[str]] | None = None,
        max_propagation_window_sec: float = 120,
    ) -> EVPNBipartiteCausalEngine:
        """Build an engine from a site / NetBox manifest.

        ``adjacency_map`` wins when provided; otherwise the manifest's
        ``adjacency`` / ``links`` / Clos roles are used. An empty manifest
        still produces a working engine (same-device suppression only).
        """
        adj = (
            _normalize_adjacency(adjacency_map)
            if adjacency_map
            else adjacency_from_manifest(manifest)
        )
        return cls(adj, max_propagation_window_sec=max_propagation_window_sec)

    def neighbors(self, device: str) -> set[str]:
        return set(self.adjacency_map.get(device, ()))

    def is_adjacent(self, a: str, b: str) -> bool:
        if not a or not b:
            return False
        if a == b:
            return True
        return b in self.adjacency_map.get(a, ())

    def classify(self, message: str) -> tuple[ProtocolLayer, str]:
        return classify_message(message)

    def ingest(self, events: Iterable[Any]) -> list[FabricEvent]:
        out: list[FabricEvent] = []
        for item in events:
            coerced = _coerce_event(item)
            if coerced is not None:
                out.append(coerced)
        return out

    def analyze(self, events: Iterable[Any]) -> list[CausalHypothesis]:
        """Classify, pick lowest-layer roots, suppress higher-layer symptoms."""
        fabric = self.ingest(events)
        if not fabric:
            return []

        fabric.sort(key=lambda e: (e.instant or datetime.max, e.layer, e.device))
        claimed: set[str] = set()
        hypotheses: list[CausalHypothesis] = []

        candidates = [
            e for e in fabric
            if e.layer is not ProtocolLayer.UNKNOWN
        ]
        candidates.sort(key=lambda e: (int(e.layer), e.instant or datetime.max, e.device))

        for root in candidates:
            if root.event_id in claimed:
                continue
            symptoms: list[FabricEvent] = []
            adjacent_hits = 0
            for other in fabric:
                if other.event_id == root.event_id or other.event_id in claimed:
                    continue
                if other.layer is ProtocolLayer.UNKNOWN:
                    continue
                if other.layer <= root.layer:
                    continue
                if not self.is_adjacent(root.device, other.device) and other.device != root.device:
                    continue
                gap = _seconds_apart(root, other)
                if gap is None:
                    # Unparseable stamps: still suppress same-device higher layers.
                    if other.device != root.device:
                        continue
                elif gap > self.max_propagation_window_sec:
                    continue
                symptoms.append(other)
                if other.device != root.device:
                    adjacent_hits += 1

            if not symptoms and root.layer is ProtocolLayer.UNKNOWN:
                continue

            claimed.add(root.event_id)
            for symptom in symptoms:
                claimed.add(symptom.event_id)

            devices: list[str] = []
            seen_dev: set[str] = set()
            vnis: list[str] = []
            seen_vni: set[str] = set()
            for event in (root, *symptoms):
                if event.device and event.device not in seen_dev:
                    seen_dev.add(event.device)
                    devices.append(event.device)
                if event.vni and event.vni not in seen_vni:
                    seen_vni.add(event.vni)
                    vnis.append(event.vni)

            confidence, rationale = _score_hypothesis(
                root, symptoms, adjacent_hits, self.max_propagation_window_sec,
            )
            hypotheses.append(CausalHypothesis(
                root_cause=root,
                suppressed_symptoms=symptoms,
                affected_devices=devices,
                affected_vnis=vnis,
                confidence=confidence,
                rationale=rationale,
            ))

        hypotheses.sort(key=lambda h: (-h.confidence, int(h.root_cause.layer)))
        return hypotheses


def hypotheses_payload(hypotheses: Sequence[CausalHypothesis]) -> dict[str, Any]:
    """JSON-ready payload attached to AnalysisResult.evpn_causal."""
    elements: list[dict[str, Any]] = []
    for hyp in hypotheses:
        elements.extend(hyp.to_cytoscape_elements())
    return {
        "enabled": True,
        "hypotheses": [h.to_dict() for h in hypotheses],
        "cytoscape_elements": elements,
    }
