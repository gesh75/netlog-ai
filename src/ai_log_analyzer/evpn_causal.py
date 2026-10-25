"""Protocol-aware Bipartite Causal Inference Engine for CLOS / EVPN-VXLAN fabrics.

Maps syslog events across the 5-tier network protocol hierarchy:
  L1_PHYSICAL -> L2_LAG_MLAG -> L3_UNDERLAY -> L4_VTEP_NVE -> L5_OVERLAY_EVPN

Automatically suppresses downstream overlay symptoms when a lower-layer
root cause occurs on the same device or a topologically adjacent spine/leaf.
"""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Iterable, Mapping, Sequence
from contextvars import ContextVar
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
    """Strict bottom-up protocol dependency hierarchy."""

    L1_PHYSICAL = 1
    L2_LAG_MLAG = 2
    L3_UNDERLAY = 3
    L4_VTEP_NVE = 4
    L5_OVERLAY_EVPN = 5
    UNKNOWN = 99


_LAYER_SIGNATURES: list[tuple[ProtocolLayer, re.Pattern[str], str]] = [
    (
        ProtocolLayer.L1_PHYSICAL,
        re.compile(
            r"LINEPROTO-5-UPDOWN.*down|LINK-3-UPDOWN.*down|SNMP_TRAP_LINK_DOWN|"
            r"OPTICAL_PWR_LOW|RX_LOS|FCS_ERR|CRC_ERR|TRANSCEIVER_FAULT|carrier\s+down",
            re.IGNORECASE,
        ),
        "Physical link or optical transceiver fault",
    ),
    (
        ProtocolLayer.L2_LAG_MLAG,
        re.compile(
            r"LACP.*(?:down|suspended|detached|timeout)|MLAG.*(?:inactive|down|peer-link)|"
            r"BUNDLE_MEMBER_DOWN|AE_BUNDLE_DOWN",
            re.IGNORECASE,
        ),
        "Link aggregation (LACP/MLAG/ESI) degradation",
    ),
    (
        ProtocolLayer.L3_UNDERLAY,
        re.compile(
            r"BFDD_TRAP_SHOP_DOWN|BFD.*(?:Down|Expired|Timeout)|"
            r"OSPF.*(?:DOWN|NbrDown)|ISIS.*(?:ADJDOWN|Lost)|"
            r"(?:BGP-5-ADJCHANGE|RPD_BGP_NEIGHBOR_STATE_CHANGED|bgpd(?!.*EVPN)).*(?:Down|Idle|Active|Notification)",
            re.IGNORECASE,
        ),
        "Underlay routing or BFD session failure",
    ),
    (
        ProtocolLayer.L4_VTEP_NVE,
        re.compile(
            r"VTEP.*(?:down|unreachable)|VXLAN_TUNNEL_DOWN|NVE.*(?:down|peer\s+lost)|"
            r"ENCAP_NEXTHOP_UNREACHABLE",
            re.IGNORECASE,
        ),
        "VTEP NVE data-plane tunnel loss",
    ),
    (
        ProtocolLayer.L5_OVERLAY_EVPN,
        re.compile(
            r"EVPN.*(?:withdraw|down|mac-move|duplicate|flap)|"
            r"TYPE[-_]?[2345].*(?:withdraw|unreachable)|"
            r"MAC_MOVE_LIMIT|DUPLICATE_MAC|BGP.*EVPN.*(?:Down|Notification)",
            re.IGNORECASE,
        ),
        "Overlay EVPN control-plane symptom",
    ),
]

_INTF_EXTRACT_RE = re.compile(
    r"\b((?:TenGigabitEthernet|GigabitEthernet|FastEthernet|FortyGigE|HundredGigE|"
    r"Port-Channel|Management|Loopback|Ethernet|Vxlan|Vlan|"
    r"eth|swp|po|ae|vlan|"
    r"xe-|et-|ge-|"
    r"irb\.|lo0\.|nve)\d+(?:[/.:]\d+)*)\b",
    re.IGNORECASE,
)
_VNI_EXTRACT_RE = re.compile(
    r"\b(?:VNI|vni|vnid|vxlan)[=\s:#]*(\d{1,8})\b",
    re.IGNORECASE,
)

_TRUTHY = frozenset({"1", "true", "yes", "on"})


def is_evpn_causal_enabled() -> bool:
    """True when AI_LOG_ANALYZER_EVPN_CAUSAL is set. Default off."""
    return os.environ.get("AI_LOG_ANALYZER_EVPN_CAUSAL", "").strip().lower() in _TRUTHY


# Anchor for yearless (RFC3164) stamps while a batch is being coerced: the
# batch's first dated event (or now). Set by ingest() / analyze().
_STAMP_REF: ContextVar[datetime | None] = ContextVar("evpn_stamp_ref", default=None)


def _batch_reference(events: Sequence[Any]) -> datetime:
    from types import SimpleNamespace

    from ai_log_analyzer.causal import _reference_dt

    return _reference_dt(
        SimpleNamespace(timestamp=str(getattr(e, "timestamp", None) or getattr(e, "t", None) or ""))
        for e in events if not isinstance(e, str)
    )


def _as_datetime(stamp: Any) -> datetime | None:
    """Parse ISO, RFC5424, FRR, and RFC3164 timestamps into datetime.

    RFC3164 has no year: it is taken from the batch being processed (see
    ``_STAMP_REF``), else from the current time, with Dec / Jan rollover.
    """
    if stamp is None:
        return None
    if isinstance(stamp, datetime):
        return stamp
    if not isinstance(stamp, str):
        stamp = str(stamp)
    text = stamp.strip()
    if not text:
        return None
    iso = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(iso)
        if parsed.tzinfo is not None:
            return parsed
        return parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    collapsed = " ".join(text.split())
    for fmt in ("%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(collapsed, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    parts = collapsed.split()
    if len(parts) >= 3 and parts[0][:3] in _RFC3164_MONTHS:
        try:
            day = int(parts[1])
            time_part = parts[2].split(".")[0]
            hour, minute, sec = (int(p) for p in time_part.split(":"))
            from ai_log_analyzer.causal import _RFC3164_YEARLESS, _now, _restamp_yearless

            yearless = datetime(_RFC3164_YEARLESS, _RFC3164_MONTHS[parts[0][:3]], day, hour, minute, sec)
            return _restamp_yearless(yearless, _STAMP_REF.get() or _now()).replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _event_id(timestamp: Any, device: str, raw_message: str) -> str:
    raw = f"{timestamp}|{device}|{raw_message}".encode()
    return hashlib.sha1(raw).hexdigest()[:12]


def classify_message(message: str) -> tuple[ProtocolLayer, str]:
    """Return (layer, human summary) for a raw syslog body."""
    text = message or ""
    # Check L5 before L3 to avoid underlay BGP taking EVPN routes
    ordered = [
        ProtocolLayer.L1_PHYSICAL,
        ProtocolLayer.L2_LAG_MLAG,
        ProtocolLayer.L4_VTEP_NVE,
        ProtocolLayer.L5_OVERLAY_EVPN,
        ProtocolLayer.L3_UNDERLAY,
    ]
    by_layer = {layer: (pattern, desc) for layer, pattern, desc in _LAYER_SIGNATURES}
    for layer in ordered:
        pattern, desc = by_layer[layer]
        if pattern.search(text):
            return layer, desc
    return ProtocolLayer.UNKNOWN, "Unclassified network event"


def extract_interface(message: str) -> str:
    match = _INTF_EXTRACT_RE.search(message or "")
    return match.group(1) if match else ""


def extract_vni(message: str) -> str:
    match = _VNI_EXTRACT_RE.search(message or "")
    return match.group(1) if match else ""


@dataclass
class FabricEvent:
    """Normalized network event enriched with protocol layer metadata."""

    event_id: str
    timestamp: datetime
    device: str
    raw_message: str
    layer: ProtocolLayer = ProtocolLayer.UNKNOWN
    summary: str = ""
    interface: str | None = None
    vni: int | None = None

    @property
    def instant(self) -> datetime | None:
        if isinstance(self.timestamp, datetime):
            return self.timestamp
        return _as_datetime(self.timestamp)

    def to_dict(self) -> dict[str, Any]:
        ts = self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else str(self.timestamp)
        return {
            "event_id": self.event_id,
            "timestamp": ts,
            "device": self.device,
            "raw_message": self.raw_message,
            "layer": self.layer.name,
            "layer_value": int(self.layer),
            "summary": self.summary,
            "interface": self.interface or "",
            "vni": str(self.vni) if self.vni is not None else "",
        }


def fabric_event_from_raw(
    raw_message: str,
    *,
    timestamp: str | datetime = "",
    device: str = "",
) -> FabricEvent:
    layer, summary = classify_message(raw_message)
    intf = extract_interface(raw_message) or None
    vni_str = extract_vni(raw_message)
    vni_val = int(vni_str) if vni_str else None
    ts_dt = _as_datetime(timestamp) or datetime.now(timezone.utc)
    return FabricEvent(
        event_id=_event_id(timestamp, device, raw_message),
        timestamp=ts_dt,
        device=device,
        raw_message=raw_message,
        layer=layer,
        summary=summary,
        interface=intf,
        vni=vni_val,
    )


@dataclass
class CausalHypothesis:
    """Represents a resolved root-cause chain across underlay and overlay tiers."""

    root_cause: FabricEvent
    suppressed_symptoms: list[FabricEvent] = field(default_factory=list)
    affected_devices: set[str] = field(default_factory=set)
    affected_vnis: set[int] = field(default_factory=set)
    confidence: float = 0.0
    rationale: str = ""

    @property
    def symptom_suppression_ratio(self) -> float:
        total = 1 + len(self.suppressed_symptoms)
        return len(self.suppressed_symptoms) / total if total > 1 else 0.0

    def to_cytoscape_elements(self) -> list[dict[str, Any]]:
        """Serialize causal chain into Cytoscape.js elements for web/static/app.js."""
        elements: list[dict[str, Any]] = []
        seen_nodes: set[str] = set()

        def _add_node(ev: FabricEvent, role: str) -> None:
            node_id = f"{ev.device}:{ev.layer.name}"
            if node_id not in seen_nodes:
                seen_nodes.add(node_id)
                elements.append(
                    {
                        "data": {
                            "id": node_id,
                            "label": f"{ev.device}\n({ev.layer.name})",
                            "device": ev.device,
                            "layer": "underlay" if ev.layer <= ProtocolLayer.L3_UNDERLAY else "overlay",
                            "causal_role": role,
                            "summary": ev.summary,
                        },
                        "classes": f"causal-node causal-{role} plane-{'underlay' if ev.layer <= ProtocolLayer.L3_UNDERLAY else 'overlay'}",
                    }
                )

        _add_node(self.root_cause, "root_cause")
        root_node_id = f"{self.root_cause.device}:{self.root_cause.layer.name}"

        for sym in self.suppressed_symptoms:
            _add_node(sym, "symptom")
            sym_node_id = f"{sym.device}:{sym.layer.name}"
            if sym_node_id != root_node_id:
                elements.append(
                    {
                        "data": {
                            "id": f"edge-{root_node_id}->{sym_node_id}",
                            "source": root_node_id,
                            "target": sym_node_id,
                            "edge_type": "causal_propagation",
                            "line_style": "dashed" if sym.layer >= ProtocolLayer.L4_VTEP_NVE else "solid",
                        },
                        "classes": "causal_propagation causal-dashed" if sym.layer >= ProtocolLayer.L4_VTEP_NVE else "causal_propagation",
                    }
                )
        return elements

    def to_dict(self) -> dict[str, Any]:
        return {
            "root_cause": self.root_cause.to_dict() if hasattr(self.root_cause, "to_dict") else self.root_cause,
            "suppressed_symptoms": [
                s.to_dict() if hasattr(s, "to_dict") else s for s in self.suppressed_symptoms
            ],
            "affected_devices": sorted(list(self.affected_devices)),
            "affected_vnis": sorted(list(str(v) for v in self.affected_vnis)),
            "confidence": self.confidence,
            "rationale": self.rationale,
            "symptom_suppression_ratio": self.symptom_suppression_ratio,
            "cytoscape_elements": self.to_cytoscape_elements(),
        }


def _coerce_fabric_event(item: Any) -> FabricEvent | None:
    if isinstance(item, FabricEvent):
        if not isinstance(item.timestamp, datetime):
            item.timestamp = _as_datetime(item.timestamp) or datetime.now(timezone.utc)
        return item
    if isinstance(item, str):
        line = item.strip()
        if not line:
            return None
        return fabric_event_from_raw(line)
    if item is None:
        return None
    timestamp = getattr(item, "timestamp", None) or getattr(item, "t", None) or ""
    device = getattr(item, "hostname", None) or getattr(item, "device", None) or getattr(item, "host", None) or ""
    message = (
        getattr(item, "message", None)
        or getattr(item, "raw_message", None)
        or getattr(item, "sample_message", None)
        or getattr(item, "description", None)
        or ""
    )
    if not message:
        return None
    return fabric_event_from_raw(message, timestamp=timestamp, device=device)


def _link_ends(link: Any) -> tuple[str, str]:
    if isinstance(link, (tuple, list)) and len(link) >= 2:
        return str(link[0] or ""), str(link[1] or "")
    if not isinstance(link, dict):
        return "", ""
    a = link.get("source") or link.get("src") or link.get("a") or link.get("left") or ""
    b = link.get("target") or link.get("dst") or link.get("b") or link.get("right") or ""
    return str(a), str(b)


def adjacency_from_manifest(manifest: Mapping[str, Any] | None) -> dict[str, set[str]]:
    """Build an undirected adjacency map from a site / NetBox manifest."""
    adj: dict[str, set[str]] = {}
    if not manifest:
        return adj
    raw_adj = manifest.get("adjacency")
    if isinstance(raw_adj, dict) and raw_adj:
        for src, neighbors in raw_adj.items():
            if not src:
                continue
            adj.setdefault(src, set())
            for dst in neighbors or []:
                if dst and dst != src:
                    adj.setdefault(src, set()).add(dst)
                    adj.setdefault(dst, set()).add(src)
        return adj

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


class EVPNBipartiteCausalEngine:
    """Evaluates fabric events against L1-L5 dependencies and site topology."""

    def __init__(
        self,
        adjacency_map: dict[str, set[str]] | Mapping[str, Iterable[str]] | None = None,
        max_propagation_window_sec: float = 120.0,
    ) -> None:
        adj: dict[str, set[str]] = {}
        if adjacency_map:
            for k, vs in adjacency_map.items():
                adj.setdefault(k, set())
                for v in vs or []:
                    if v and v != k:
                        adj[k].add(v)
                        adj.setdefault(v, set()).add(k)
        self.adjacency_map: dict[str, set[str]] = adj
        self.max_propagation_window_sec = float(max_propagation_window_sec)
        self.max_window = float(max_propagation_window_sec)

    @classmethod
    def from_site_manifest(
        cls,
        manifest: Mapping[str, Any] | None,
        adjacency_map: Mapping[str, Iterable[str]] | None = None,
        max_propagation_window_sec: float = 120.0,
    ) -> EVPNBipartiteCausalEngine:
        """Build adjacency graph directly from a netlog-ai site manifest."""
        if adjacency_map:
            return cls(adjacency_map=adjacency_map, max_propagation_window_sec=max_propagation_window_sec)
        adj = adjacency_from_manifest(manifest)
        return cls(adjacency_map=adj, max_propagation_window_sec=max_propagation_window_sec)

    def is_adjacent(self, a: str, b: str) -> bool:
        if not a or not b:
            return False
        if a == b:
            return True
        return b in self.adjacency_map.get(a, set())

    def neighbors(self, device: str) -> set[str]:
        return set(self.adjacency_map.get(device, set()))

    def classify(self, message: str) -> tuple[ProtocolLayer, str]:
        return classify_message(message)

    @staticmethod
    def classify_event(
        event_id: str, timestamp: datetime | str, device: str, raw_message: str
    ) -> FabricEvent:
        """Classify a log line into its protocol layer and extract interface/VNI metadata."""
        matched_layer = ProtocolLayer.UNKNOWN
        summary = "Unclassified network event"

        # Check L5 before L3 to avoid underlay BGP taking EVPN routes
        ordered = [
            ProtocolLayer.L1_PHYSICAL,
            ProtocolLayer.L2_LAG_MLAG,
            ProtocolLayer.L4_VTEP_NVE,
            ProtocolLayer.L5_OVERLAY_EVPN,
            ProtocolLayer.L3_UNDERLAY,
        ]
        by_layer = {layer: (pattern, desc) for layer, pattern, desc in _LAYER_SIGNATURES}
        for layer in ordered:
            pattern, desc = by_layer[layer]
            if pattern.search(raw_message):
                matched_layer = layer
                summary = desc
                break

        intf_match = _INTF_EXTRACT_RE.search(raw_message)
        vni_match = _VNI_EXTRACT_RE.search(raw_message)

        ts_dt = _as_datetime(timestamp) or datetime.now(timezone.utc)

        return FabricEvent(
            event_id=event_id,
            timestamp=ts_dt,
            device=device,
            raw_message=raw_message,
            layer=matched_layer,
            summary=summary,
            interface=intf_match.group(1) if intf_match else None,
            vni=int(vni_match.group(1)) if vni_match else None,
        )

    def _is_topologically_coupled(self, root_dev: str, sym_dev: str, sym_layer: ProtocolLayer) -> bool:
        if root_dev == sym_dev:
            return True
        if sym_dev in self.adjacency_map.get(root_dev, set()):
            return True
        # VTEP and EVPN overlay events can propagate 2 hops across a Spine-Leaf CLOS fabric
        if sym_layer >= ProtocolLayer.L4_VTEP_NVE:
            root_neighbors = self.adjacency_map.get(root_dev, set())
            for intermediate in root_neighbors:
                if sym_dev in self.adjacency_map.get(intermediate, set()):
                    return True
        return False

    def ingest(self, events: Iterable[Any]) -> list[FabricEvent]:
        out: list[FabricEvent] = []
        batch = list(events)
        token = _STAMP_REF.set(_batch_reference(batch))
        try:
            for item in batch:
                coerced = _coerce_fabric_event(item)
                if coerced is not None:
                    out.append(coerced)
        finally:
            _STAMP_REF.reset(token)
        return out

    def analyze(self, events: Iterable[Any]) -> list[CausalHypothesis]:
        """Group fabric events into root-cause hypotheses ordered by confidence."""
        fabric = [e for e in self.ingest(events) if e.layer != ProtocolLayer.UNKNOWN]

        if not fabric:
            return []

        # Sort primarily by timestamp, secondarily by lowest protocol layer (L1 before L3)
        ordered = sorted(
            fabric,
            key=lambda e: (
                e.timestamp if isinstance(e.timestamp, datetime) else (_as_datetime(e.timestamp) or datetime.max),
                int(e.layer),
            ),
        )
        claimed_symptom_ids: set[str] = set()
        hypotheses: list[CausalHypothesis] = []

        for idx, candidate in enumerate(ordered):
            if candidate.event_id in claimed_symptom_ids:
                continue

            symptoms: list[FabricEvent] = []
            affected_devs: set[str] = {candidate.device}
            affected_vnis: set[int] = {candidate.vni} if candidate.vni else set()

            cand_dt = candidate.timestamp if isinstance(candidate.timestamp, datetime) else _as_datetime(candidate.timestamp)

            for later in ordered[idx + 1 :]:
                if later.event_id in claimed_symptom_ids:
                    continue

                later_dt = later.timestamp if isinstance(later.timestamp, datetime) else _as_datetime(later.timestamp)
                delta_sec = 0.0
                if cand_dt and later_dt:
                    delta_sec = (later_dt - cand_dt).total_seconds()
                    if delta_sec < 0 or delta_sec > self.max_window:
                        continue

                # A lower-layer failure (e.g. L1) explains strictly higher-layer events (L2..L5)
                # or peer L1/L3 events on the opposite end of the same link
                is_higher_layer = later.layer > candidate.layer
                is_peer_link_drop = (
                    later.layer == candidate.layer
                    and later.device in self.adjacency_map.get(candidate.device, set())
                    and delta_sec <= 5.0
                )

                if (is_higher_layer or is_peer_link_drop) and self._is_topologically_coupled(
                    candidate.device, later.device, later.layer
                ):
                    symptoms.append(later)
                    claimed_symptom_ids.add(later.event_id)
                    affected_devs.add(later.device)
                    if later.vni:
                        affected_vnis.add(later.vni)

            # Calculate confidence based on layer depth and corroborated downstream symptoms.
            # Heuristic ordinal score: these constants are not calibrated against
            # labelled incidents. Read it as "higher ranks above lower", never as a
            # probability; the numbers are only meaningful relative to each other.
            base_conf = 0.65 if candidate.layer == ProtocolLayer.L1_PHYSICAL else 0.55
            symptom_boost = min(0.30, len(symptoms) * 0.08)
            layer_span_boost = (
                0.05
                if any(s.layer >= ProtocolLayer.L4_VTEP_NVE for s in symptoms)
                else 0.0
            )
            confidence = round(min(0.99, base_conf + symptom_boost + layer_span_boost), 2)

            rationale = (
                f"{candidate.layer.name} event on {candidate.device}"
                + (f" ({candidate.interface})" if candidate.interface else "")
                + f" triggered {len(symptoms)} downstream symptom(s) across "
                f"{len(affected_devs)} device(s)."
            )

            hypotheses.append(
                CausalHypothesis(
                    root_cause=candidate,
                    suppressed_symptoms=symptoms,
                    affected_devices=affected_devs,
                    affected_vnis=affected_vnis,
                    confidence=confidence,
                    rationale=rationale,
                )
            )

        return sorted(
            hypotheses,
            key=lambda h: (h.confidence, len(h.suppressed_symptoms)),
            reverse=True,
        )


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
