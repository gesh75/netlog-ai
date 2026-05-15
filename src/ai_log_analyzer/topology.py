"""Topology extractor — derive device/link/role graph from sanitized configs.

Pure regex/text parsing (no LLM). Produces a JSON graph suitable for D3,
Mermaid, or Graphviz rendering.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable


@dataclass
class Node:
    id: str
    label: str
    role: str            # firewall | router | switch | unknown
    platform: str        # junos | eos | frr | unknown
    has_bgp: bool = False
    has_ospf: bool = False
    has_evpn: bool = False
    has_vxlan: bool = False
    isp_uplink: bool = False
    finding_severity: str = ""  # critical | high | medium | "" — set by overlay

    def to_dict(self) -> dict:
        return {
            "id": self.id, "label": self.label,
            "role": self.role, "platform": self.platform,
            "has_bgp": self.has_bgp, "has_ospf": self.has_ospf,
            "has_evpn": self.has_evpn, "has_vxlan": self.has_vxlan,
            "isp_uplink": self.isp_uplink,
            "finding_severity": self.finding_severity,
        }


@dataclass
class Edge:
    source: str
    target: str
    label: str = ""
    kind: str = "physical"  # physical | bgp | lacp | mlag | ospf

    def to_dict(self) -> dict:
        return {"source": self.source, "target": self.target,
                "label": self.label, "kind": self.kind}


@dataclass
class Topology:
    site_id: str
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "site_id": self.site_id,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Per-device analyzers
# ─────────────────────────────────────────────────────────────────────────────

# Site portion accepts dashes so multi-token site names like `peer-a-fw-01`,
# `dc-east-fw-01`, or `demo-east-fw-01` parse correctly. Lazy match so the
# func/num at the end always win the suffix.
_HOST_RE = re.compile(r"^(?P<site>[a-z0-9][a-z0-9-]*?)-(?P<func>fw|rt|sw|edr|acs)-(?P<num>\d+[a-z]?)$", re.I)
_INTERFACE_DESC_RE = re.compile(
    r'(?:description\s+|description:\s+|description\s+")'
    r'([^"\n;]+?)["\n;]', re.I
)
_NEIGHBOR_BGP_JUNOS = re.compile(r"neighbor\s+(\S+)\s*\{[^}]*?peer-as\s+(\d+)", re.S)
_NEIGHBOR_BGP_EOS = re.compile(r"neighbor\s+(\S+)\s+remote-as\s+(\d+)", re.I)


def _detect_role_from_hostname(hostname: str) -> tuple[str, str]:
    m = _HOST_RE.match(hostname.lower())
    if not m:
        return "unknown", ""
    func = m.group("func")
    role = {"fw": "firewall", "rt": "router", "sw": "switch",
            "edr": "edr", "acs": "storage"}.get(func, "unknown")
    return role, m.group("site")


def _has(text: str, keywords: tuple[str, ...]) -> bool:
    lt = text.lower()
    return any(k in lt for k in keywords)


def _detect_isp_uplink(text: str) -> bool:
    # Common ISP / transit markers in description fields
    isp_markers = (
        "isp", "telia", "arelion", "lumen", "cogent", "ntt", "gtt",
        "leaseweb", "level3", "centurylink", "tata", "verizon", "att",
        "deutsche telekom", "vodafone", "optus", "telstra", "tpg",
    )
    for m in _INTERFACE_DESC_RE.finditer(text):
        desc = m.group(1).lower()
        if any(kw in desc for kw in isp_markers):
            return True
    return False


def _extract_neighbors(text: str, platform: str) -> list[str]:
    """Return list of (peer_ip, remote_as) tuples found in BGP config."""
    out: list[str] = []
    if platform == "junos":
        for m in _NEIGHBOR_BGP_JUNOS.finditer(text):
            out.append(m.group(1))
    elif platform in ("eos", "frr"):
        for m in _NEIGHBOR_BGP_EOS.finditer(text):
            out.append(m.group(1))
    return out


def _interface_descriptions(text: str) -> list[str]:
    return [m.group(1).strip() for m in _INTERFACE_DESC_RE.finditer(text)]


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────────

def build_topology(site_id: str, devices: list[dict]) -> Topology:
    """Build a Topology from a site bundle's device list.

    Each device dict: {hostname, config_text, platform}

    Uses multi-signal edge inference (description hostnames, BGP peer IPs,
    MLAG peer-address, subnet co-membership, HA-pair naming) — see
    `topology_infer.py` for the full rule set.
    """
    from ai_log_analyzer import topology_infer

    topo = Topology(site_id=site_id)
    facts_by_host: dict[str, "topology_infer.DeviceFacts"] = {}

    # Pass 1 — create nodes + extract facts
    for d in devices:
        hostname = d["hostname"]
        text = d.get("config_text", "")
        platform = (d.get("platform") or "").lower() or _guess_platform(text)
        role, _ = _detect_role_from_hostname(hostname)

        n = Node(
            id=hostname, label=hostname, role=role, platform=platform,
            has_bgp=_has(text, ("router bgp", "protocols bgp", "neighbor ")),
            has_ospf=_has(text, ("router ospf", "protocols ospf")),
            has_evpn=_has(text, ("evpn", " l2vpn evpn")),
            has_vxlan=_has(text, ("vxlan", "vni ")),
            isp_uplink=_detect_isp_uplink(text),
        )
        topo.nodes.append(n)
        facts_by_host[hostname] = topology_infer.extract_facts(hostname, platform, text)

    # Pass 2 — multi-signal edge inference (BGP IPs, MLAG, descriptions, subnets, HA pairs)
    inferred = topology_infer.infer_edges(facts_by_host)
    for ie in inferred:
        topo.edges.append(Edge(
            source=ie.source, target=ie.target,
            label=ie.evidence[:80], kind=_kind_for_rule(ie.rule),
        ))

    return topo


def _kind_for_rule(rule: str) -> str:
    """Map an inference rule name to an edge kind for rendering."""
    if rule == "bgp-neighbor":          return "bgp"
    if rule == "mlag-peer":              return "mlag"
    if rule == "ha-pair-naming":         return "ha"
    if rule == "subnet-co-membership":   return "subnet"
    return "physical"


def _guess_platform(text: str) -> str:
    t = text[:5000].lower()
    if "set system" in t or "junos" in t or "interfaces {" in t:
        return "junos"
    if "! command: show running-config" in t or "eos-4." in t or "switchport mode" in t:
        return "eos"
    if "frr version" in t or "vtysh" in t:
        return "frr"
    return "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Finding overlay
# ─────────────────────────────────────────────────────────────────────────────

def overlay_findings(topo: Topology, findings: list[dict]) -> Topology:
    """Annotate each node with the worst severity from findings it's mentioned in."""
    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "": 0}
    for node in topo.nodes:
        worst = ""
        for f in findings:
            affected = f.get("affected_devices") or []
            if node.id in affected:
                sev = (f.get("severity") or "").lower()
                if sev_order.get(sev, 0) > sev_order.get(worst, 0):
                    worst = sev
        node.finding_severity = worst
    return topo


# ─────────────────────────────────────────────────────────────────────────────
# Diagram serializers
# ─────────────────────────────────────────────────────────────────────────────

def to_mermaid(topo: Topology) -> str:
    """Render as a Mermaid `graph TD` block."""
    lines = [f"%% Topology: {topo.site_id}", "graph TD"]
    # Group roles for clarity
    for n in topo.nodes:
        shape_l, shape_r = _mermaid_shape(n.role)
        label = n.label.replace('"', "'")
        roles_tags = []
        if n.has_bgp: roles_tags.append("BGP")
        if n.has_ospf: roles_tags.append("OSPF")
        if n.has_evpn: roles_tags.append("EVPN")
        if n.has_vxlan: roles_tags.append("VXLAN")
        if n.isp_uplink: roles_tags.append("ISP")
        tags = f"<br/>{','.join(roles_tags)}" if roles_tags else ""
        lines.append(f'    {_mm_id(n.id)}{shape_l}"{label}{tags}"{shape_r}')
    for e in topo.edges:
        connector = "---" if e.kind == "physical" else "-.->"
        edge_label = f"|{e.label[:30]}|" if e.label else ""
        lines.append(f"    {_mm_id(e.source)} {connector}{edge_label} {_mm_id(e.target)}")
    # Style nodes with findings
    for n in topo.nodes:
        if n.finding_severity:
            color = {"critical": "#f85149", "high": "#ff7b72",
                     "medium": "#d29922", "low": "#79c0ff"}.get(n.finding_severity, "#666")
            lines.append(f"    style {_mm_id(n.id)} fill:{color},color:#fff,stroke:#333")
    return "\n".join(lines)


def _mermaid_shape(role: str) -> tuple[str, str]:
    return {
        "firewall": ("[(", ")]"),  # hexagon-like
        "router":   ("([", "])"),   # stadium
        "switch":   ("[", "]"),     # rectangle
    }.get(role, ("[", "]"))


def _mm_id(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", name)


def to_graphviz(topo: Topology) -> str:
    """Render as a Graphviz `digraph` block."""
    lines = [f'digraph "{topo.site_id}" {{',
             '    rankdir=TB;',
             '    node [fontname="Helvetica", fontsize=10];',
             '    edge [fontname="Helvetica", fontsize=8];']
    shapes = {"firewall": "octagon", "router": "ellipse", "switch": "box"}
    sev_colors = {"critical": "#f85149", "high": "#ff7b72",
                  "medium": "#d29922", "low": "#79c0ff", "": "#21262d"}
    for n in topo.nodes:
        shape = shapes.get(n.role, "box")
        color = sev_colors[n.finding_severity or ""]
        tags = []
        if n.has_bgp: tags.append("BGP")
        if n.has_ospf: tags.append("OSPF")
        if n.has_evpn: tags.append("EVPN")
        if n.has_vxlan: tags.append("VXLAN")
        if n.isp_uplink: tags.append("ISP")
        sub = f"\\n{', '.join(tags)}" if tags else ""
        lines.append(
            f'    "{n.id}" [shape={shape}, style=filled, '
            f'fillcolor="{color}", fontcolor=white, label="{n.label}{sub}"];'
        )
    for e in topo.edges:
        style = "solid" if e.kind == "physical" else "dashed"
        lines.append(
            f'    "{e.source}" -> "{e.target}" '
            f'[label="{e.label[:30]}", style={style}, dir=none, color="#666"];'
        )
    lines.append("}")
    return "\n".join(lines)
