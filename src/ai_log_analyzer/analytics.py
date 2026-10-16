"""Deterministic deep network analytics.

Three stdlib-only views over parsed logs, topology, and config diffs:

* RFC 2439 exponential flap dampening and inter-arrival jitter
* Undirected blast-radius / articulation-point (SPOF) scoring
* Config-line to finding drift correlation

No graph or ML libraries. Callers pass ``Topology`` / ``TopologyGraph``,
``ClassifiedEvent``, ``ActionItem``, ``Finding``, or plain dicts.
"""
from __future__ import annotations

import re
import statistics
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from ai_log_analyzer.diff import ConfigDiff
from ai_log_analyzer.topology import Topology, TopologyGraph

_FLAP_SUBSTRINGS = (
    "flap", "adjacency", "established", "err-disable", "carrier",
    "bfd", "bgp", "ospf", "lacp",
)
_FLAP_WORDS = re.compile(r"\b(up|down|idle|reset)\b", re.IGNORECASE)
_INTF_RE = re.compile(
    r"\b("
    r"(?:Ethernet|GigabitEthernet|TenGigabitEthernet|TenGigE|HundredGigE|"
    r"Bundle-Ether|Port-channel|Port-Channel)"
    r"\d+(?:/\d+)*"
    r"|(?:ge|xe|et|ae|lo|irb)-\d+/\d+/\d+(?:\.\d+)?"
    r")\b",
    re.IGNORECASE,
)
_PEER_RE = re.compile(
    r"\b(?:neighbor|peer)\s+(\d{1,3}(?:\.\d{1,3}){3})\b",
    re.IGNORECASE,
)
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_LINE_RE = re.compile(
    r"^(?:(?P<iso>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:?\d{2})?)"
    r"|(?P<syslog>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}))\s+"
    r"(?P<host>\S+)\s+(?P<msg>.*)$"
)
_DEGRADED = {"critical", "high", "error"}
_RISK_ORDER = {
    "CRITICAL_SPOF": 0,
    "LATENT_SPOF": 1,
    "DEGRADED_REDUNDANT": 2,
    "HEALTHY": 3,
}
_DRIFT_GROUPS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("bgp", re.compile(r"\bbgp\b|\bneighbor\b|\bremote-as\b|\bpeer-as\b", re.IGNORECASE)),
    ("mtu", re.compile(r"\bmtu\b", re.IGNORECASE)),
    ("vlan", re.compile(r"\bvlan\b|\bvni\b|\bvxlan\b", re.IGNORECASE)),
    ("acl", re.compile(r"\bacl\b|\bprefix-list\b|\baccess-list\b", re.IGNORECASE)),
    ("ospf", re.compile(r"\bospf\b|\barea\b", re.IGNORECASE)),
    ("interface", re.compile(r"\bshutdown\b|\bspeed\b|\binterface\b", re.IGNORECASE)),
)


@dataclass
class Finding:
    """Normalized anomaly used by the analytics functions.

    Built from ``ClassifiedEvent`` (hostname/message/severity), an
    ``ActionItem``, or a dict with the same keys.
    """

    device: str
    severity: str
    message: str
    timestamp: str = ""
    category: str = ""
    entity: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "device": self.device,
            "severity": self.severity,
            "message": self.message,
            "timestamp": self.timestamp,
            "category": self.category,
            "entity": self.entity,
        }


@dataclass
class FlapEntityMetrics:
    device: str
    entity_id: str
    event_count: int
    peak_penalty: float
    current_penalty: float
    state: str
    pattern: str
    intervals_sec: list[float] = field(default_factory=list)
    coefficient_of_variation: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "device": self.device,
            "entity_id": self.entity_id,
            "event_count": self.event_count,
            "peak_penalty": self.peak_penalty,
            "current_penalty": self.current_penalty,
            "state": self.state,
            "pattern": self.pattern,
            "intervals_sec": list(self.intervals_sec),
            "coefficient_of_variation": self.coefficient_of_variation,
        }


@dataclass
class FlapAnalysisReport:
    entities: list[FlapEntityMetrics] = field(default_factory=list)
    dampened_count: int = 0
    active_churn_count: int = 0
    most_unstable_entity: str | None = None
    recommended_dampening_cli: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entities": [e.to_dict() for e in self.entities],
            "dampened_count": self.dampened_count,
            "active_churn_count": self.active_churn_count,
            "most_unstable_entity": self.most_unstable_entity,
            "recommended_dampening_cli": {
                vendor: list(lines) for vendor, lines in self.recommended_dampening_cli.items()
            },
        }


@dataclass
class BlastRadiusNode:
    device: str
    is_degraded: bool
    is_articulation_point: bool
    degree: int
    direct_neighbors_impacted: list[str]
    redundancy_loss_pct: float
    risk_tier: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "device": self.device,
            "is_degraded": self.is_degraded,
            "is_articulation_point": self.is_articulation_point,
            "degree": self.degree,
            "direct_neighbors_impacted": list(self.direct_neighbors_impacted),
            "redundancy_loss_pct": self.redundancy_loss_pct,
            "risk_tier": self.risk_tier,
        }


@dataclass
class BlastRadiusReport:
    nodes: list[BlastRadiusNode] = field(default_factory=list)
    articulation_points: list[str] = field(default_factory=list)
    critical_spofs: list[str] = field(default_factory=list)
    blast_radius_score: float = 0.0
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "articulation_points": list(self.articulation_points),
            "critical_spofs": list(self.critical_spofs),
            "blast_radius_score": self.blast_radius_score,
            "summary": self.summary,
        }


@dataclass
class ConfigDriftHit:
    device: str
    finding_message: str
    changed_line: str
    confidence: float
    explanation: str
    matched_keywords: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "device": self.device,
            "finding_message": self.finding_message,
            "changed_line": self.changed_line,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "matched_keywords": list(self.matched_keywords),
        }


@dataclass
class ConfigDriftCorrelationReport:
    hits: list[ConfigDriftHit] = field(default_factory=list)
    correlated_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "hits": [h.to_dict() for h in self.hits],
            "correlated_count": self.correlated_count,
        }


def analyze_flap_dynamics(
    events: Iterable[Any],
    *,
    flap_penalty: float = 1000.0,
    half_life_sec: float = 900.0,
    suppress_threshold: float = 2000.0,
    reuse_threshold: float = 750.0,
) -> FlapAnalysisReport:
    """RFC 2439-style exponential penalty per (device, entity)."""
    if half_life_sec <= 0:
        raise ValueError("half_life_sec must be positive")
    grouped = _group_transitions(events)
    entities: list[FlapEntityMetrics] = []
    for (device, entity_id), stamps in grouped.items():
        entities.append(_score_entity(
            device, entity_id, stamps,
            flap_penalty=flap_penalty,
            half_life_sec=half_life_sec,
            suppress_threshold=suppress_threshold,
            reuse_threshold=reuse_threshold,
        ))
    entities.sort(key=lambda e: (-e.peak_penalty, e.device, e.entity_id))
    top = entities[0] if entities else None
    label = f"{top.device}:{top.entity_id}" if top else None
    return FlapAnalysisReport(
        entities=entities,
        dampened_count=sum(1 for e in entities if e.state == "DAMPENED_STORM"),
        active_churn_count=sum(1 for e in entities if e.state == "ACTIVE_CHURN"),
        most_unstable_entity=label,
        recommended_dampening_cli=_dampening_cli(top.entity_id if top else "Ethernet1"),
    )


def analyze_blast_radius(
    topology: TopologyGraph | Mapping[str, Any],
    findings: list[Any],
) -> BlastRadiusReport:
    """Score cut vertices and degraded neighbors on an undirected topology."""
    adj, roles = _adjacency(topology)
    if not adj:
        return BlastRadiusReport(summary="Topology has no devices.")
    cuts = _articulation_points(adj)
    degraded = _degraded_devices(findings, adj)
    nodes = [_blast_node(name, adj, cuts, degraded) for name in sorted(adj)]
    nodes.sort(key=lambda n: (_RISK_ORDER.get(n.risk_tier, 9), n.device))
    aps = sorted(cuts)
    critical = sorted(n.device for n in nodes if n.risk_tier == "CRITICAL_SPOF")
    score = _blast_score(nodes, findings, roles)
    summary = (
        f"Blast radius score {score:.1f}. "
        f"{len(aps)} articulation point(s), {len(critical)} critical SPOF(s)."
    )
    return BlastRadiusReport(
        nodes=nodes,
        articulation_points=aps,
        critical_spofs=critical,
        blast_radius_score=score,
        summary=summary,
    )


def correlate_config_drift(
    config_diff: ConfigDiff | Mapping[str, Any] | None,
    findings: list[Any],
) -> ConfigDriftCorrelationReport:
    """Match changed BGP/MTU/VLAN/ACL/OSPF/interface lines to findings."""
    lines = _diff_lines(config_diff)
    if not lines or not findings:
        return ConfigDriftCorrelationReport()
    hits: list[ConfigDriftHit] = []
    for finding in _iter_findings(findings):
        hit = _best_drift_hit(finding, lines, _diff_hostname(config_diff))
        if hit is not None:
            hits.append(hit)
    hits.sort(key=lambda h: (-h.confidence, h.device))
    return ConfigDriftCorrelationReport(hits=hits, correlated_count=len(hits))


def build_device_overlays(
    blast: BlastRadiusReport | None,
    flap: FlapAnalysisReport | None,
    change_hits: list[Mapping[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    """Per-device badges consumed by the Cytoscape overlay."""
    overlays: dict[str, dict[str, Any]] = {}
    if blast is not None:
        for node in blast.nodes:
            overlays[node.device] = {
                "is_spof": node.is_articulation_point,
                "risk_tier": node.risk_tier,
                "active_change": None,
                "change_confidence": 0.0,
                "dampened_flaps": 0,
            }
    if flap is not None:
        for entity in flap.entities:
            if entity.state != "DAMPENED_STORM":
                continue
            slot = overlays.setdefault(entity.device, {
                "is_spof": False,
                "risk_tier": "HEALTHY",
                "active_change": None,
                "change_confidence": 0.0,
                "dampened_flaps": 0,
            })
            slot["dampened_flaps"] = int(slot["dampened_flaps"]) + 1
    for hit in change_hits or []:
        device = str(hit.get("device") or "")
        confidence = float(hit.get("confidence") or 0.0)
        if not device or confidence < 0.5:
            continue
        slot = overlays.setdefault(device, {
            "is_spof": False,
            "risk_tier": "HEALTHY",
            "active_change": None,
            "change_confidence": 0.0,
            "dampened_flaps": 0,
        })
        if confidence >= float(slot["change_confidence"]):
            slot["active_change"] = hit.get("change_number")
            slot["change_confidence"] = confidence
    return overlays


# ── flap helpers ─────────────────────────────────────────────────────────────

def _group_transitions(events: Iterable[Any]) -> dict[tuple[str, str], list[datetime]]:
    grouped: dict[tuple[str, str], list[datetime]] = {}
    for index, row in enumerate(_iter_rows(events)):
        device, message, stamp = row
        if not _is_transition(message):
            continue
        when = _parse_ts(stamp, index)
        key = (device or "unknown", _entity_id(message))
        grouped.setdefault(key, []).append(when)
    for stamps in grouped.values():
        stamps.sort()
    return grouped


def _iter_rows(events: Iterable[Any]) -> Iterable[tuple[str, str, str]]:
    for item in events:
        if isinstance(item, str):
            yield _row_from_text(item)
            continue
        if isinstance(item, Finding):
            text = item.message if item.entity == "" else f"{item.entity} {item.message}"
            yield (item.device, text, item.timestamp)
            continue
        if isinstance(item, Mapping):
            device = str(item.get("device") or item.get("hostname") or item.get("host") or "")
            message = str(item.get("message") or item.get("sample_message") or item.get("description") or "")
            yield (device, message, str(item.get("timestamp") or ""))
            continue
        device = str(getattr(item, "device", "") or getattr(item, "hostname", "") or "")
        message = str(getattr(item, "message", "") or getattr(item, "sample_message", "") or "")
        yield (device, message, str(getattr(item, "timestamp", "") or ""))


def _row_from_text(line: str) -> tuple[str, str, str]:
    match = _LINE_RE.match(line.strip())
    if not match:
        return ("", line, "")
    stamp = match.group("iso") or match.group("syslog") or ""
    return (match.group("host") or "", match.group("msg") or "", stamp)


def _is_transition(text: str) -> bool:
    low = text.lower()
    if any(token in low for token in _FLAP_SUBSTRINGS):
        return True
    return _FLAP_WORDS.search(low) is not None


def _entity_id(message: str) -> str:
    intf = _INTF_RE.search(message)
    if intf:
        return intf.group(1)
    peer = _PEER_RE.search(message)
    if peer:
        return peer.group(1)
    if re.search(r"\bbgp\b", message, re.IGNORECASE):
        ip = _IP_RE.search(message)
        if ip:
            return ip.group(1)
    low = message.lower()
    for proto in ("bfd", "bgp", "ospf", "lacp"):
        if proto in low:
            return proto
    return "session"


def _parse_ts(value: str, index: int) -> datetime:
    text = (value or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    if text:
        try:
            return _as_utc(datetime.fromisoformat(text))
        except ValueError:
            pass
        for fmt, sample in (
            ("%Y-%m-%d %H:%M:%S", text),
            ("%Y %b %d %H:%M:%S", f"2026 {text}"),
        ):
            try:
                parsed = datetime.strptime(sample, fmt)
            except ValueError:
                continue
            return _as_utc(parsed)
    return _as_utc(datetime(2026, 1, 1) + timedelta(seconds=index))


def _as_utc(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _score_entity(
    device: str,
    entity_id: str,
    stamps: list[datetime],
    *,
    flap_penalty: float,
    half_life_sec: float,
    suppress_threshold: float,
    reuse_threshold: float,
) -> FlapEntityMetrics:
    penalty = 0.0
    peak = 0.0
    intervals: list[float] = []
    previous: datetime | None = None
    for moment in stamps:
        delta = 0.0 if previous is None else max(0.0, (moment - previous).total_seconds())
        if previous is not None:
            intervals.append(delta)
        penalty = penalty * (0.5 ** (delta / half_life_sec)) + flap_penalty
        peak = max(peak, penalty)
        previous = moment
    pattern, cv = _jitter(stamps, intervals)
    return FlapEntityMetrics(
        device=device,
        entity_id=entity_id,
        event_count=len(stamps),
        peak_penalty=round(peak, 4),
        current_penalty=round(penalty, 4),
        state=_flap_state(peak, suppress_threshold, reuse_threshold),
        pattern=pattern,
        intervals_sec=[round(v, 4) for v in intervals],
        coefficient_of_variation=None if cv is None else round(cv, 4),
    )


def _jitter(stamps: list[datetime], intervals: list[float]) -> tuple[str, float | None]:
    if len(stamps) < 3 or len(intervals) < 2:
        return "INSUFFICIENT_DATA", None
    mean = statistics.fmean(intervals)
    sigma = statistics.stdev(intervals)
    cv = 0.0 if mean == 0 else sigma / mean
    label = "PERIODIC_TIMER_DRIVEN" if cv < 0.25 else "BURSTY_PHYSICAL_NOISE"
    return label, cv


def _flap_state(peak: float, suppress: float, reuse: float) -> str:
    if peak >= suppress:
        return "DAMPENED_STORM"
    if peak >= reuse:
        return "ACTIVE_CHURN"
    return "ISOLATED_TRANSITION"


def _dampening_cli(entity: str) -> dict[str, list[str]]:
    target = entity or "Ethernet1"
    return {
        "arista_eos": [
            f"interface {target}",
            "   dampening",
            "router bgp",
            "   bgp dampening 15 750 2000 60",
        ],
        "juniper_junos": [
            "set policy-options damping damp-flap half-life 15 max-suppress 60 reuse 750 suppress 2000",
            "set protocols bgp damping",
            f"set interfaces {target} hold-time up 2000 down 0",
        ],
        "cisco_iosxr": [
            "router bgp",
            " bgp dampening 15 750 2000 60",
            f"interface {target}",
            " dampening",
        ],
    }


# ── blast-radius helpers ─────────────────────────────────────────────────────

def _adjacency(
    topology: TopologyGraph | Mapping[str, Any],
) -> tuple[dict[str, set[str]], dict[str, str]]:
    names, roles, edges = _topology_parts(topology)
    adj: dict[str, set[str]] = {name: set() for name in names if name}
    for left, right in edges:
        if not left or not right or left == right:
            continue
        adj.setdefault(left, set()).add(right)
        adj.setdefault(right, set()).add(left)
    return adj, roles


def _topology_parts(
    topology: TopologyGraph | Mapping[str, Any],
) -> tuple[list[str], dict[str, str], list[tuple[str, str]]]:
    if isinstance(topology, Topology):
        names = [node.id for node in topology.nodes]
        roles = {node.id: node.role or node.tier for node in topology.nodes}
        edges = [(edge.source, edge.target) for edge in topology.edges]
        return names, roles, edges
    raw_nodes = list(topology.get("nodes") or topology.get("devices") or [])
    names: list[str] = []
    roles: dict[str, str] = {}
    for node in raw_nodes:
        if isinstance(node, str):
            names.append(node)
            continue
        if isinstance(node, Mapping):
            name = str(node.get("id") or node.get("name") or node.get("device") or "")
            if name:
                names.append(name)
                roles[name] = str(node.get("role") or node.get("tier") or "")
    raw_edges = list(topology.get("edges") or topology.get("links") or [])
    edges: list[tuple[str, str]] = []
    for edge in raw_edges:
        pair = _edge_pair(edge)
        if pair is not None:
            edges.append(pair)
    return names, roles, edges


def _edge_pair(edge: Any) -> tuple[str, str] | None:
    if isinstance(edge, Mapping):
        left = edge.get("source") or edge.get("src") or edge.get("a")
        right = edge.get("target") or edge.get("dst") or edge.get("b")
        if left and right:
            return str(left), str(right)
        return None
    if isinstance(edge, (list, tuple)) and len(edge) == 2:
        return str(edge[0]), str(edge[1])
    return None


def _articulation_points(adj: dict[str, set[str]]) -> set[str]:
    """Tarjan DFS cut vertices. Pure Python, deterministic neighbor order."""
    disc: dict[str, int] = {}
    low: dict[str, int] = {}
    parent: dict[str, str | None] = {}
    cuts: set[str] = set()
    timer = 0

    def dfs(node: str) -> None:
        nonlocal timer
        timer += 1
        disc[node] = low[node] = timer
        children = 0
        for nxt in sorted(adj.get(node, ())):
            if nxt not in disc:
                parent[nxt] = node
                children += 1
                dfs(nxt)
                low[node] = min(low[node], low[nxt])
                _mark_cut(node, nxt, children, parent, disc, low, cuts)
            elif nxt != parent.get(node):
                low[node] = min(low[node], disc[nxt])

    for start in sorted(adj):
        if start not in disc:
            parent[start] = None
            dfs(start)
    return cuts


def _mark_cut(
    node: str,
    nxt: str,
    children: int,
    parent: dict[str, str | None],
    disc: dict[str, int],
    low: dict[str, int],
    cuts: set[str],
) -> None:
    if parent.get(node) is None and children > 1:
        cuts.add(node)
    if parent.get(node) is not None and low[nxt] >= disc[node]:
        cuts.add(node)


def _degraded_devices(findings: list[Any], adj: dict[str, set[str]]) -> set[str]:
    index = {name.lower(): name for name in adj}
    degraded: set[str] = set()
    for finding in _iter_findings(findings):
        if finding.severity.lower() not in _DEGRADED:
            continue
        canonical = index.get(finding.device.lower(), finding.device)
        if canonical in adj:
            degraded.add(canonical)
    return degraded


def _iter_findings(findings: list[Any]) -> Iterable[Finding]:
    for item in findings:
        yield from _coerce_finding(item)


def _coerce_finding(item: Any) -> Iterable[Finding]:
    if isinstance(item, Finding):
        yield item
        return
    if isinstance(item, Mapping):
        devices = _mapping_devices(item)
        message = str(item.get("message") or item.get("description") or item.get("sample_message") or "")
        severity = str(item.get("severity") or item.get("level") or "info")
        stamp = str(item.get("timestamp") or "")
        category = str(item.get("category") or "")
        for device in devices:
            yield Finding(device=device, severity=severity, message=message, timestamp=stamp, category=category)
        return
    devices = [str(d) for d in getattr(item, "devices", []) or []]
    if not devices:
        one = getattr(item, "device", None) or getattr(item, "hostname", None)
        devices = [str(one)] if one else []
    message = str(
        getattr(item, "message", "")
        or getattr(item, "description", "")
        or getattr(item, "sample_message", "")
        or ""
    )
    severity = str(getattr(item, "severity", "") or "info")
    stamp = str(getattr(item, "timestamp", "") or "")
    category = str(getattr(item, "category", "") or "")
    for device in devices:
        yield Finding(device=device, severity=severity, message=message, timestamp=stamp, category=category)


def _mapping_devices(item: Mapping[str, Any]) -> list[str]:
    single = item.get("device") or item.get("hostname") or item.get("host")
    if single:
        return [str(single)]
    return [str(device) for device in item.get("devices") or [] if device]


def _blast_node(
    name: str,
    adj: dict[str, set[str]],
    cuts: set[str],
    degraded: set[str],
) -> BlastRadiusNode:
    neighbors = sorted(adj.get(name, ()))
    degree = len(neighbors)
    lost = sum(1 for hop in neighbors if hop in degraded)
    loss = 0.0 if degree == 0 else round(100.0 * lost / degree, 2)
    is_cut = name in cuts
    is_bad = name in degraded
    return BlastRadiusNode(
        device=name,
        is_degraded=is_bad,
        is_articulation_point=is_cut,
        degree=degree,
        direct_neighbors_impacted=neighbors,
        redundancy_loss_pct=loss,
        risk_tier=_risk_tier(is_bad, is_cut),
    )


def _risk_tier(is_degraded: bool, is_cut: bool) -> str:
    if is_degraded and is_cut:
        return "CRITICAL_SPOF"
    if is_cut:
        return "LATENT_SPOF"
    if is_degraded:
        return "DEGRADED_REDUNDANT"
    return "HEALTHY"


def _blast_score(
    nodes: list[BlastRadiusNode],
    findings: list[Any],
    roles: dict[str, str],
) -> float:
    total = max(len(nodes), 1)
    affected: set[str] = set()
    spine_hit = False
    for node in nodes:
        if not node.is_degraded:
            continue
        affected.add(node.device)
        affected.update(node.direct_neighbors_impacted)
        role = f"{node.device} {roles.get(node.device, '')}".lower()
        if node.is_articulation_point or "spine" in role:
            spine_hit = True
    fraction = len(affected) / total
    critical_findings = sum(
        1 for finding in _iter_findings(findings) if finding.severity.lower() in _DEGRADED
    )
    density = min(1.0, critical_findings / total)
    score = 40.0 * fraction + (35.0 if spine_hit else 0.0) + 25.0 * density
    return round(min(100.0, max(0.0, score)), 2)


# ── config-drift helpers ─────────────────────────────────────────────────────

def _diff_lines(config_diff: ConfigDiff | Mapping[str, Any] | None) -> list[str]:
    if config_diff is None:
        return []
    if isinstance(config_diff, ConfigDiff):
        return [line for line in config_diff.changed_lines() if line.strip()]
    if isinstance(config_diff, Mapping):
        explicit = list(config_diff.get("changed_lines") or [])
        explicit += list(config_diff.get("added") or [])
        explicit += list(config_diff.get("removed") or [])
        if explicit:
            return [str(line) for line in explicit if str(line).strip()]
        before = str(config_diff.get("before") or "")
        after = str(config_diff.get("after") or "")
        return ConfigDiff(before=before, after=after).changed_lines()
    return []


def _diff_hostname(config_diff: ConfigDiff | Mapping[str, Any] | None) -> str:
    if isinstance(config_diff, ConfigDiff):
        return config_diff.hostname
    if isinstance(config_diff, Mapping):
        return str(config_diff.get("hostname") or "")
    return ""


def _best_drift_hit(finding: Finding, lines: list[str], hostname: str) -> ConfigDriftHit | None:
    best: ConfigDriftHit | None = None
    for line in lines:
        keywords = _shared_keywords(finding.message, line)
        entity = _entity_id(finding.message)
        if entity.lower() in line.lower() and entity.lower() not in {k.lower() for k in keywords}:
            keywords = [*keywords, entity]
        if not keywords:
            continue
        confidence = _drift_confidence(finding, line, keywords, hostname)
        explanation = (
            f"Changed line shares {', '.join(keywords)} with a {finding.severity} finding "
            f"on {finding.device or 'unknown'}."
        )
        hit = ConfigDriftHit(
            device=finding.device,
            finding_message=finding.message,
            changed_line=line,
            confidence=confidence,
            explanation=explanation,
            matched_keywords=keywords,
        )
        if best is None or hit.confidence > best.confidence:
            best = hit
    return best


def _shared_keywords(message: str, line: str) -> list[str]:
    blob = f"{message}\n{line}"
    return [name for name, pattern in _DRIFT_GROUPS if pattern.search(blob) and pattern.search(message) and pattern.search(line)]


def _drift_confidence(finding: Finding, line: str, keywords: list[str], hostname: str) -> float:
    score = 0.45
    if len(keywords) > 1:
        score += 0.1
    entity = _entity_id(finding.message)
    generic = {"session", "bgp", "ospf", "bfd", "lacp"}
    if entity.lower() not in generic and entity.lower() in line.lower():
        score += 0.25
    device = finding.device.lower()
    host = hostname.lower()
    if device and (device in line.lower() or host == device):
        score += 0.2
    return round(min(1.0, score), 4)
