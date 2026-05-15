"""Multi-signal edge inference — derive who-talks-to-whom from configs alone.

Signals (in priority order, strongest first):
  1. Interface description naming a known sibling hostname (exact-or-prefix match)
  2. MLAG peer-address / peer-link → exact peer
  3. BGP neighbor IP matching another device's interface IP
  4. Subnet co-membership (/30 / /31 / /29) → likely directly connected
  5. Junos chassis-cluster fab0/fab1 / control-link → HA partner inference

Each edge gets a `confidence` score and the rule that produced it so the UI
can show how certain we are.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

# ─────────────────────────────────────────────────────────────────────────────
# Config feature extraction (per device)
# ─────────────────────────────────────────────────────────────────────────────

# Junos style: `set interfaces ge-0/0/0 unit 0 family inet address 10.1.1.1/30`
_JUNOS_IF_ADDR = re.compile(
    r"set\s+interfaces\s+(?P<iface>\S+)\s+unit\s+\d+\s+family\s+inet\s+address\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})",
    re.I,
)
# Junos hierarchical: `address 10.1.1.1/30;` inside `family inet { }`
_JUNOS_IF_HIER = re.compile(r"address\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\s*;", re.I)

# EOS style: `ip address 10.1.1.1/30`
_EOS_IF_ADDR = re.compile(r"^\s*ip\s+address\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})", re.M)

# BGP neighbor IPs (vendor-agnostic; matches both Junos and EOS forms)
_BGP_NEIGHBOR = re.compile(
    r"(?:neighbor|peer)\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?:\s+remote-as|\s+peer-as|\s+;|\s*\{)",
    re.I,
)

# MLAG peer-address (EOS)
_MLAG_PEER = re.compile(r"\bpeer-address\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})", re.I)

# Interface description — captures the description text
_DESCRIPTION = re.compile(r'description\s+["\']?([^"\';\n]+?)["\']?\s*[;\n]', re.I)

# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class DeviceFacts:
    """Structured facts about one device, extracted purely from its config."""
    hostname: str
    platform: str
    interface_ips: list[str]      # CIDR strings, e.g. ["10.1.1.1/30", ...]
    bgp_neighbors: list[str]      # bare IPs
    mlag_peers: list[str]         # bare IPs
    descriptions: list[str]
    has_chassis_cluster: bool     # Junos HA partner indicator

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname, "platform": self.platform,
            "interface_ips": self.interface_ips,
            "bgp_neighbors": self.bgp_neighbors,
            "mlag_peers": self.mlag_peers,
            "descriptions": self.descriptions,
            "has_chassis_cluster": self.has_chassis_cluster,
        }


def extract_facts(hostname: str, platform: str, config_text: str) -> DeviceFacts:
    """Pull all the topology-relevant facts from one config blob."""
    plat = (platform or "").lower()
    ips: list[str] = []

    if plat in ("junos", "junos-srx", "junos-mx", "junos-ex"):
        ips.extend(m.group("ip") for m in _JUNOS_IF_ADDR.finditer(config_text))
        ips.extend(m.group("ip") for m in _JUNOS_IF_HIER.finditer(config_text))
    elif plat in ("eos", "arista", "frr", "ios"):
        ips.extend(m.group("ip") for m in _EOS_IF_ADDR.finditer(config_text))
    else:
        # Try both
        ips.extend(m.group("ip") for m in _JUNOS_IF_ADDR.finditer(config_text))
        ips.extend(m.group("ip") for m in _EOS_IF_ADDR.finditer(config_text))

    # Dedup while preserving order, filter out obviously invalid
    seen: set[str] = set()
    uniq_ips: list[str] = []
    for ip in ips:
        if ip not in seen and _is_real_ip(ip):
            seen.add(ip)
            uniq_ips.append(ip)

    bgp_peers = list(dict.fromkeys(
        m.group("ip") for m in _BGP_NEIGHBOR.finditer(config_text)
        if _is_real_ip(m.group("ip"))
    ))
    mlag = list(dict.fromkeys(
        m.group("ip") for m in _MLAG_PEER.finditer(config_text)
        if _is_real_ip(m.group("ip"))
    ))
    descs = [m.group(1).strip() for m in _DESCRIPTION.finditer(config_text)]
    has_cluster = bool(re.search(r"chassis\s+cluster", config_text, re.I))

    return DeviceFacts(
        hostname=hostname, platform=plat,
        interface_ips=uniq_ips, bgp_neighbors=bgp_peers,
        mlag_peers=mlag, descriptions=descs,
        has_chassis_cluster=has_cluster,
    )


def _is_real_ip(s: str) -> bool:
    try:
        ipaddress.ip_interface(s) if "/" in s else ipaddress.ip_address(s)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Edge inference (across devices)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class InferredEdge:
    source: str
    target: str
    rule: str            # how we found it
    confidence: float    # 0..1
    evidence: str        # short human-readable detail

    def to_dict(self) -> dict:
        return {"source": self.source, "target": self.target,
                "rule": self.rule, "confidence": self.confidence,
                "evidence": self.evidence}


def infer_edges(facts_by_host: dict[str, DeviceFacts]) -> list[InferredEdge]:
    """Apply all inference rules and return a deduplicated edge list.

    Higher-confidence edges override lower-confidence ones for the same pair.
    """
    edges: dict[tuple[str, str], InferredEdge] = {}

    def upsert(a: str, b: str, rule: str, conf: float, ev: str) -> None:
        key = tuple(sorted([a, b]))  # type: ignore[assignment]
        if key not in edges or edges[key].confidence < conf:
            edges[key] = InferredEdge(source=key[0], target=key[1],
                                       rule=rule, confidence=conf, evidence=ev)

    hosts = list(facts_by_host.keys())
    all_facts = list(facts_by_host.values())

    # ─── Rule 1: interface description names a sibling hostname ──────────────
    for f in all_facts:
        for desc in f.descriptions:
            d_lc = desc.lower()
            for other in hosts:
                if other == f.hostname:
                    continue
                # exact substring match
                if other.lower() in d_lc:
                    upsert(f.hostname, other, "description-hostname", 0.95,
                           f"{f.hostname} description: '{desc[:50]}'")
                    continue
                # short-form match (e.g. "sw-03b" inside config for "demo-east-sw-03b")
                parts = other.split("-", 1)
                if len(parts) == 2 and parts[1].lower() in d_lc.split():
                    upsert(f.hostname, other, "description-shortform", 0.7,
                           f"{f.hostname} description: '{desc[:50]}'")

    # ─── Rule 2: MLAG peer-address → match to interface IP elsewhere ─────────
    for f in all_facts:
        for peer_ip in f.mlag_peers:
            for g in all_facts:
                if g.hostname == f.hostname:
                    continue
                if _ip_owned_by(peer_ip, g.interface_ips):
                    upsert(f.hostname, g.hostname, "mlag-peer", 1.0,
                           f"{f.hostname} MLAG peer-address {peer_ip} owned by {g.hostname}")

    # ─── Rule 3: BGP neighbor IP owned by another device ─────────────────────
    for f in all_facts:
        for n_ip in f.bgp_neighbors:
            for g in all_facts:
                if g.hostname == f.hostname:
                    continue
                if _ip_owned_by(n_ip, g.interface_ips):
                    upsert(f.hostname, g.hostname, "bgp-neighbor", 0.95,
                           f"{f.hostname} BGP neighbor {n_ip} → {g.hostname}")

    # ─── Rule 4: subnet co-membership on small subnets ───────────────────────
    # Build subnet → [hosts] map for /28-/31 prefixes
    subnet_owners: dict[str, set[str]] = {}
    for f in all_facts:
        for ip_str in f.interface_ips:
            try:
                iface = ipaddress.ip_interface(ip_str)
            except (ipaddress.AddressValueError, ValueError):
                continue
            net = iface.network
            if not isinstance(net, ipaddress.IPv4Network):
                continue
            if net.prefixlen >= 28 and net.prefixlen <= 31:
                subnet_owners.setdefault(str(net), set()).add(f.hostname)

    for net, owners in subnet_owners.items():
        if len(owners) < 2:
            continue
        owners_l = sorted(owners)
        for i in range(len(owners_l)):
            for j in range(i + 1, len(owners_l)):
                a, b = owners_l[i], owners_l[j]
                upsert(a, b, "subnet-co-membership", 0.85,
                       f"Both on {net} (/{ipaddress.ip_network(net).prefixlen})")

    # ─── Rule 5: Junos chassis-cluster HA partner inference ──────────────────
    # When two devices share a hostname prefix and one is an "a" / one is "b" /
    # or naming like fw-01 / fw-02 with both having chassis-cluster → HA pair
    for i in range(len(all_facts)):
        for j in range(i + 1, len(all_facts)):
            a, b = all_facts[i], all_facts[j]
            if not (a.has_chassis_cluster or b.has_chassis_cluster):
                continue
            if _is_ha_pair(a.hostname, b.hostname):
                upsert(a.hostname, b.hostname, "ha-pair-naming", 0.9,
                       "Naming + chassis-cluster suggests HA pair")

    return list(edges.values())


def _ip_owned_by(query_ip: str, owned_ips_cidr: list[str]) -> bool:
    """Return True if query_ip (bare IP) is contained in any of owned_ips_cidr's networks
    (or matches one exactly)."""
    try:
        q = ipaddress.ip_address(query_ip)
    except (ipaddress.AddressValueError, ValueError):
        return False
    for cidr in owned_ips_cidr:
        try:
            iface = ipaddress.ip_interface(cidr)
        except (ipaddress.AddressValueError, ValueError):
            continue
        if q == iface.ip:
            return True
    return False


def _is_ha_pair(name_a: str, name_b: str) -> bool:
    """Heuristic for HA naming: fw-01a/fw-01b, fw-01/fw-02 (sequential), fw-20a/fw-20b."""
    # Pattern A: same base + a/b suffix (e.g. fw-01a, fw-01b)
    base_re = re.compile(r"^(.+?-(?:fw|rt|sw)-\d+)([ab])$", re.I)
    ma, mb = base_re.match(name_a), base_re.match(name_b)
    if ma and mb and ma.group(1) == mb.group(1) and ma.group(2) != mb.group(2):
        return True
    # Pattern B: sequential numbers within same role (fw-01/fw-02, rt-01/rt-02)
    seq_re = re.compile(r"^(.+?-(?:fw|rt|sw)-)(\d+)$", re.I)
    sa, sb = seq_re.match(name_a), seq_re.match(name_b)
    if sa and sb and sa.group(1) == sb.group(1):
        try:
            n_a, n_b = int(sa.group(2)), int(sb.group(2))
            if abs(n_a - n_b) == 1:
                return True
        except ValueError:
            pass
    return False
