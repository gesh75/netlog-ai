"""Topology extractor — derive device/link/role graph from sanitized configs.

Pure regex/text parsing (no LLM). Produces a JSON graph suitable for D3,
Mermaid, or Graphviz rendering.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_log_analyzer import topology_infer


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
    # Manifest-derived hints — surfaced to the renderer for tiered layouts and
    # POP grouping. All optional; renderer falls back to role if tier is empty.
    tier: str = ""       # spine | leaf | superspine | core | edge | dist | fw | rt | sw
    pop: str = ""        # region/site code, e.g. "de-fra", "uk-lon" — drives compound nodes
    rack: str = ""       # optional rack id, used for sub-grouping inside a POP
    asn: int | None = None
    # Protocol identity surfaced for node tooltips
    router_id: str = ""
    vtep_ip: str = ""
    bgp_afs: list[str] = field(default_factory=list)
    l2_vnis: list[int] = field(default_factory=list)
    l3_vnis: list[int] = field(default_factory=list)
    vrfs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "label": self.label,
            "role": self.role, "platform": self.platform,
            "has_bgp": self.has_bgp, "has_ospf": self.has_ospf,
            "has_evpn": self.has_evpn, "has_vxlan": self.has_vxlan,
            "isp_uplink": self.isp_uplink,
            "finding_severity": self.finding_severity,
            "tier": self.tier, "pop": self.pop, "rack": self.rack,
            "asn": self.asn,
            "router_id": self.router_id, "vtep_ip": self.vtep_ip,
            "bgp_afs": list(self.bgp_afs),
            "l2_vnis": list(self.l2_vnis), "l3_vnis": list(self.l3_vnis),
            "vrfs": list(self.vrfs),
        }


# Canonical layer set, exposed via /api/topology so the frontend can render
# chips in the same order regardless of which layers a given edge appears on.
# Per user feedback (2026-05-25): L1+L3 collapse into a single PHYSICAL layer;
# EVPN folds into BGP as an address-family rather than a standalone chip.
LAYER_ORDER: tuple[str, ...] = ("physical", "bgp", "ospf", "vxlan")


@dataclass
class Edge:
    source: str
    target: str
    label: str = ""
    kind: str = "physical"  # physical | bgp | mlag | ha | subnet
    # Per-layer overlay membership. Every inferred edge is "physical".
    # Higher layers are added when both endpoints carry that protocol.
    layers: list[str] = field(default_factory=list)
    subnet: str = ""               # shared /28..31 if any
    # Physical-layer detail
    src_iface: str = ""
    dst_iface: str = ""
    src_ip: str = ""               # CIDR on src interface
    dst_ip: str = ""               # CIDR on dst interface
    description: str = ""          # interface description (best end first)
    src_speed: str = ""            # per-end speed, e.g. "100G" / "10G" / "1G" ("" = unknown)
    dst_speed: str = ""
    speed: str = ""                # normalized link speed for label (min of both ends)
    # BGP-layer detail
    src_asn: int | None = None
    dst_asn: int | None = None
    bgp_type: str = ""             # "ebgp" | "ibgp" | ""
    bgp_afs: list[str] = field(default_factory=list)  # intersection of both sides' AFs
    bgp_vrf: str = "default"
    src_bgp_ip: str = ""           # neighbor IP from src's POV (points at dst's BGP IP)
    dst_bgp_ip: str = ""           # neighbor IP from dst's POV (points at src's BGP IP)
    # OSPF-layer detail
    ospf_area: str = ""
    ospf_hello: int | None = None
    ospf_dead: int | None = None
    ospf_cost: int | None = None
    ospf_network_type: str = ""
    src_router_id: str = ""
    dst_router_id: str = ""
    # VXLAN-layer detail
    src_vtep: str = ""
    dst_vtep: str = ""
    l2_vnis: list[int] = field(default_factory=list)  # union of both sides' L2VNIs
    l3_vnis: list[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "source": self.source, "target": self.target,
            "label": self.label, "kind": self.kind,
            "layers": list(self.layers),
            "subnet": self.subnet,
            "src_iface": self.src_iface, "dst_iface": self.dst_iface,
            "src_ip": self.src_ip, "dst_ip": self.dst_ip,
            "description": self.description,
            "src_speed": self.src_speed, "dst_speed": self.dst_speed,
            "speed": self.speed,
            "src_asn": self.src_asn, "dst_asn": self.dst_asn,
            "bgp_type": self.bgp_type, "bgp_afs": list(self.bgp_afs),
            "bgp_vrf": self.bgp_vrf,
            "src_bgp_ip": self.src_bgp_ip, "dst_bgp_ip": self.dst_bgp_ip,
            "ospf_area": self.ospf_area,
            "ospf_hello": self.ospf_hello, "ospf_dead": self.ospf_dead,
            "ospf_cost": self.ospf_cost,
            "ospf_network_type": self.ospf_network_type,
            "src_router_id": self.src_router_id, "dst_router_id": self.dst_router_id,
            "src_vtep": self.src_vtep, "dst_vtep": self.dst_vtep,
            "l2_vnis": list(self.l2_vnis), "l3_vnis": list(self.l3_vnis),
        }


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
            "layers": list(LAYER_ORDER),
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
    `topology_infer.py` for the full rule set. Edges are then enriched with
    protocol-specific detail (interface names, IPs, AS, OSPF area, VNIs) so
    the UI can render meaningful per-layer labels and tooltips.
    """
    from ai_log_analyzer import topology_infer

    topo = Topology(site_id=site_id)
    facts_by_host: dict[str, topology_infer.DeviceFacts] = {}
    node_by_id: dict[str, Node] = {}

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
        node_by_id[hostname] = n
        f = topology_infer.extract_facts(hostname, platform, text)
        facts_by_host[hostname] = f
        # Project facts onto the node so the frontend gets a single contract.
        if f.local_asn is not None and n.asn is None:
            n.asn = f.local_asn
        n.router_id = f.router_id
        n.vtep_ip = f.vtep_ip
        n.bgp_afs = list(f.bgp_afs)
        n.l2_vnis = list(f.l2_vnis)
        n.l3_vnis = list(f.l3_vnis)
        n.vrfs = list(f.vrfs)
        if f.has_evpn_signaling:
            n.has_evpn = True

    # Pass 2 — multi-signal edge inference (BGP IPs, MLAG, descriptions, subnets, HA pairs)
    inferred = topology_infer.infer_edges(facts_by_host)
    for ie in inferred:
        kind = _kind_for_rule(ie.rule)
        a_facts = facts_by_host.get(ie.source)
        b_facts = facts_by_host.get(ie.target)
        a_node = node_by_id.get(ie.source)
        b_node = node_by_id.get(ie.target)

        edge = Edge(
            source=ie.source, target=ie.target,
            label=ie.evidence[:80], kind=kind,
        )
        # Shared subnet (drives L3 label and the L1 IP detail).
        subnet = _shared_subnet(a_facts, b_facts)
        if subnet:
            edge.subnet = subnet

        # Physical-layer detail: pick the interfaces that own that subnet.
        if a_facts and b_facts and subnet:
            for iname, info in a_facts.interfaces.items():
                if info.ip and _ip_in_subnet(info.ip, subnet):
                    edge.src_iface = iname
                    edge.src_ip = info.ip
                    if info.description:
                        edge.description = info.description
                    if info.speed:
                        edge.src_speed = info.speed
                    break
            for iname, info in b_facts.interfaces.items():
                if info.ip and _ip_in_subnet(info.ip, subnet):
                    edge.dst_iface = iname
                    edge.dst_ip = info.ip
                    if info.description and not edge.description:
                        edge.description = info.description
                    if info.speed:
                        edge.dst_speed = info.speed
                    break
        # Link speed = the lower of the two ends (or whichever side has one).
        # Both ends should normally match; mismatches indicate a misconfig.
        edge.speed = _link_speed(edge.src_speed, edge.dst_speed)
        # Fallback: pull description from the inference evidence (which is
        # often the hostname-in-description rule).
        if not edge.description and "description:" in (ie.evidence or "").lower():
            after = ie.evidence.split("description:", 1)[1].strip().strip("'\"")
            edge.description = after[:80]

        # BGP-layer detail
        src_asn, dst_asn = _peering_asn_pair(a_facts, b_facts)
        edge.src_asn = src_asn
        edge.dst_asn = dst_asn
        if src_asn is not None and dst_asn is not None:
            edge.bgp_type = "ebgp" if src_asn != dst_asn else "ibgp"
        # BGP neighbor IPs as configured (often differ from interface IPs in labs
        # where peering rides docker overlay subnets).
        edge.src_bgp_ip, edge.dst_bgp_ip = _bgp_neighbor_ips(a_facts, b_facts)
        # AFs = union of both sides' enabled AFs (proxy for what the session carries)
        if a_facts and b_facts:
            seen: set[str] = set()
            for af in (a_facts.bgp_afs + b_facts.bgp_afs):
                if af not in seen:
                    seen.add(af)
                    edge.bgp_afs.append(af)

        # OSPF-layer detail (only meaningful if both ends speak OSPF)
        if a_node and b_node and a_node.has_ospf and b_node.has_ospf:
            edge.src_router_id = a_facts.router_id if a_facts else ""
            edge.dst_router_id = b_facts.router_id if b_facts else ""
            # Pick area/timers/cost from whichever interface owns the shared subnet
            # (falls back to the first OSPF-enabled interface).
            edge.ospf_area, edge.ospf_hello, edge.ospf_dead, edge.ospf_cost, edge.ospf_network_type = (
                _ospf_iface_detail(a_facts, subnet) if a_facts else ("", None, None, None, "")
            )

        # VXLAN-layer detail
        if a_node and b_node and (a_node.has_vxlan or a_node.has_evpn) and (b_node.has_vxlan or b_node.has_evpn):
            if a_facts:
                edge.src_vtep = a_facts.vtep_ip or a_facts.router_id
            if b_facts:
                edge.dst_vtep = b_facts.vtep_ip or b_facts.router_id
            # Union of VNIs (we don't yet model per-edge VNI scope, so show both sides' set)
            edge.l2_vnis = sorted(set((a_facts.l2_vnis if a_facts else []) +
                                      (b_facts.l2_vnis if b_facts else [])))
            edge.l3_vnis = sorted(set((a_facts.l3_vnis if a_facts else []) +
                                      (b_facts.l3_vnis if b_facts else [])))

        # Layer membership
        edge.layers = _layers_for_edge(edge, a_node, b_node)
        topo.edges.append(edge)

    return topo


def _ip_in_subnet(cidr_ip: str, subnet: str) -> bool:
    import ipaddress

    try:
        iface = ipaddress.ip_interface(cidr_ip)
        net = ipaddress.ip_network(subnet)
        return iface.ip in net
    except (ipaddress.AddressValueError, ValueError):
        return False


def _link_speed(a: str, b: str) -> str:
    """Combine two endpoint speeds into a single link speed.

    - If both ends agree → return that speed.
    - If only one end is known → return it.
    - If both are known but differ → return the lower (the actual link rate
      is bounded by the slower side, and a mismatch is itself a red flag).
    - If neither is known → return "".
    """
    if not a and not b:
        return ""
    if not a:
        return b
    if not b:
        return a
    if a == b:
        return a
    return min(a, b, key=_speed_to_mbps)


def _speed_to_mbps(s: str) -> int:
    """Parse a normalized speed string ("100G", "10G", "1G", "100M") to Mbps."""
    if not s:
        return 0
    try:
        unit = s[-1].upper()
        n = int(s[:-1])
    except (TypeError, ValueError):
        return 0
    if unit == "G":
        return n * 1000
    if unit == "M":
        return n
    return 0


def _ospf_iface_detail(facts, subnet: str) -> tuple[str, int | None, int | None, int | None, str]:
    """Find OSPF area/timers/cost for the interface on `subnet`, else first OSPF iface."""
    if not facts:
        return ("", None, None, None, "")
    # First try: interface that owns the shared subnet
    if subnet:
        for info in facts.interfaces.values():
            if info.ip and _ip_in_subnet(info.ip, subnet) and info.ospf_area:
                return (info.ospf_area, info.ospf_hello, info.ospf_dead, info.ospf_cost, info.ospf_network_type)
    # Fallback: any interface with OSPF area set
    for info in facts.interfaces.values():
        if info.ospf_area:
            return (info.ospf_area, info.ospf_hello, info.ospf_dead, info.ospf_cost, info.ospf_network_type)
    return ("", None, None, None, "")


def _shared_subnet(
    a: "topology_infer.DeviceFacts | None",
    b: "topology_infer.DeviceFacts | None",
) -> str:
    """Return the /28-/31 subnet shared by both devices, or '' if none."""
    if a is None or b is None:
        return ""
    import ipaddress

    a_nets: set[str] = set()
    for cidr in a.interface_ips:
        try:
            net = ipaddress.ip_interface(cidr).network
        except (ipaddress.AddressValueError, ValueError):
            continue
        if isinstance(net, ipaddress.IPv4Network) and 28 <= net.prefixlen <= 31:
            a_nets.add(str(net))
    for cidr in b.interface_ips:
        try:
            net = ipaddress.ip_interface(cidr).network
        except (ipaddress.AddressValueError, ValueError):
            continue
        if isinstance(net, ipaddress.IPv4Network) and str(net) in a_nets:
            return str(net)
    return ""


def _bgp_neighbor_ips(
    a: "topology_infer.DeviceFacts | None",
    b: "topology_infer.DeviceFacts | None",
) -> tuple[str, str]:
    """Return (a_peer_ip_to_b, b_peer_ip_to_a) — i.e. the BGP neighbor IPs as
    they appear in each side's config, pointing at the other.

    - From A's side, the IP it lists as the BGP neighbor that resolves to B's AS.
    - From B's side, the IP it lists for A's AS.

    Falls back to interface IPs if no explicit neighbor IP matches.
    """
    if a is None or b is None:
        return ("", "")
    a_to_b = ""
    b_to_a = ""
    if b.local_asn is not None:
        for peer_ip, asn in a.bgp_peer_asn.items():
            if asn == b.local_asn:
                a_to_b = peer_ip
                break
    if a.local_asn is not None:
        for peer_ip, asn in b.bgp_peer_asn.items():
            if asn == a.local_asn:
                b_to_a = peer_ip
                break
    return (a_to_b, b_to_a)


def _peering_asn_pair(
    a: "topology_infer.DeviceFacts | None",
    b: "topology_infer.DeviceFacts | None",
) -> tuple[int | None, int | None]:
    """Return (a.local_asn, b.local_asn) when there is a BGP peering between them.

    Two signals — either is enough:
      1. IP match: A's interface owns an IP that B lists as a BGP neighbor (or vice-versa).
      2. ASN match: A names B's local_asn in any `neighbor X remote-as <asn>` line
         (and vice-versa). This catches FRR-style lab setups where the BGP
         peering IPs are docker overlay addresses that don't appear in the
         interface configs.
    """
    if a is None or b is None:
        return (None, None)

    a_owns_b_peer = any(_ip_owned_local(p, a.interface_ips) for p in b.bgp_neighbors)
    b_owns_a_peer = any(_ip_owned_local(p, b.interface_ips) for p in a.bgp_neighbors)
    asn_match = (
        b.local_asn is not None and b.local_asn in a.bgp_peer_asn.values()
    ) or (
        a.local_asn is not None and a.local_asn in b.bgp_peer_asn.values()
    )
    if a_owns_b_peer or b_owns_a_peer or asn_match:
        return (a.local_asn, b.local_asn)
    return (None, None)


def _ip_owned_local(query: str, owned_cidrs: list[str]) -> bool:
    import ipaddress

    try:
        q = ipaddress.ip_address(query)
    except (ipaddress.AddressValueError, ValueError):
        return False
    for cidr in owned_cidrs:
        try:
            if q == ipaddress.ip_interface(cidr).ip:
                return True
        except (ipaddress.AddressValueError, ValueError):
            continue
    return False


def _layers_for_edge(edge: Edge, src: Node | None, dst: Node | None) -> list[str]:
    """Decide which overlay layers this edge appears on.

    4-layer taxonomy: physical / bgp / ospf / vxlan. EVPN is reflected in
    the BGP layer's address-family list (`bgp_afs` contains `l2vpn-evpn`)
    rather than a separate chip.
    """
    layers: list[str] = ["physical"]
    if edge.kind == "bgp" or (edge.src_asn is not None and edge.dst_asn is not None):
        layers.append("bgp")
    if src and dst:
        if src.has_ospf and dst.has_ospf:
            layers.append("ospf")
        # VXLAN layer fires if either side has VXLAN config OR both sides do EVPN
        # (the latter implies an overlay even when VXLAN VNIs aren't on disk yet)
        if (src.has_vxlan and dst.has_vxlan) or (src.has_evpn and dst.has_evpn):
            layers.append("vxlan")
    return layers


def apply_manifest_metadata(topo: Topology, manifest: dict) -> Topology:
    """Enrich nodes with `tier`, `pop`, `rack`, `asn` from the bundle manifest.

    Different bundles annotate their devices differently — DCN-LAB uses
    `role` (core/edge/dist) + `pop`, CLAB-CLOS-EVPN uses `role` (spine/leaf)
    + `rack`. We normalize both into the same Node fields so the renderer
    has a single contract.
    """
    by_host = {d.get("hostname"): d for d in manifest.get("devices", []) if d.get("hostname")}
    for n in topo.nodes:
        d = by_host.get(n.id)
        if not d:
            continue
        # Tier: prefer explicit role string (spine/leaf/core/edge/dist), else
        # fall back to function_code (fw/rt/sw).
        tier = (d.get("role") or "").strip().lower()
        if not tier:
            tier = (d.get("function_code") or "").strip().lower()
        if tier:
            n.tier = tier
        if d.get("pop"):
            n.pop = str(d["pop"]).strip().lower()
        if d.get("rack"):
            n.rack = str(d["rack"]).strip().lower()
        if d.get("asn") and n.asn is None:
            try:
                n.asn = int(d["asn"])
            except (TypeError, ValueError):
                pass

    # Site-level link-speed default — applied to edges where neither endpoint
    # had an explicit speed parsed from config. Useful for clab/docker labs
    # where configs don't carry ``speed Xg``. Both string forms accepted:
    # ``"default_link_speed": "10G"`` or per-edge later via a links[] map.
    default_speed = (manifest.get("default_link_speed") or "").strip()
    if default_speed:
        for e in topo.edges:
            if not e.speed:
                e.speed = default_speed
                if not e.src_speed:
                    e.src_speed = default_speed
                if not e.dst_speed:
                    e.dst_speed = default_speed
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
