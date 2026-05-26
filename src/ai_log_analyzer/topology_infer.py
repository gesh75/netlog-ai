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
from dataclasses import dataclass, field

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

# Local BGP AS — `router bgp 65001` (EOS / FRR) or `routing-options autonomous-system 65001` (Junos)
_LOCAL_AS_BGP = re.compile(r"\brouter\s+bgp\s+(?P<asn>\d+)", re.I)
_LOCAL_AS_JUNOS = re.compile(r"\bautonomous-system\s+(?P<asn>\d+)", re.I)

# BGP neighbor with remote-as captured — needed to label per-peer ASN
_BGP_NEIGHBOR_FULL = re.compile(
    r"(?:neighbor|peer)\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?:remote-as|peer-as)\s+(?P<asn>\d+)",
    re.I,
)

# BGP address-family blocks — captures the AF name as it appears in the config.
# Catches `address-family ipv4 unicast`, `address-family l2vpn evpn`, etc.
_BGP_AF_BLOCK = re.compile(
    # Accept both two-word (Junos/FRR: `ipv4 unicast`, `l2vpn evpn`) and
    # single-word (EOS: `evpn`, `ipv4`) forms. Stop at end of line.
    r"\baddress-family\s+(?P<af>(?:ipv4|ipv6|l2vpn|vpnv4|vpnv6|evpn)(?:\s+(?:unicast|multicast|evpn|labeled-unicast))?)\b",
    re.I,
)
# Junos: `protocols evpn` block + `family evpn signaling`
_JUNOS_EVPN = re.compile(r"\bprotocols\s+evpn\b|\bfamily\s+evpn\s+signaling\b", re.I)

# OSPF: process-level router-id and area/timer details on interfaces
_OSPF_ROUTER_ID_FRR = re.compile(r"\brouter\s+ospf\b[\s\S]*?\bospf\s+router-id\s+(?P<rid>\d+\.\d+\.\d+\.\d+)", re.I)
_OSPF_ROUTER_ID_EOS = re.compile(r"\brouter\s+ospf\b[\s\S]*?\brouter-id\s+(?P<rid>\d+\.\d+\.\d+\.\d+)", re.I)
_OSPF_ROUTER_ID_JUN = re.compile(r"\brouter-id\s+(?P<rid>\d+\.\d+\.\d+\.\d+)\s*;", re.I)
# Interface OSPF: area + hello/dead/cost. FRR style — one tag per line in interface block.
_OSPF_IFACE_BLOCK_FRR = re.compile(
    r"^interface\s+(?P<iface>\S+)\s*\n(?P<body>(?:\s+\S[^\n]*\n)+)",
    re.M,
)
_OSPF_IF_AREA = re.compile(r"\bip\s+ospf\s+area\s+(?P<area>\S+)", re.I)
_OSPF_IF_HELLO = re.compile(r"\bip\s+ospf\s+hello-interval\s+(?P<v>\d+)", re.I)
_OSPF_IF_DEAD = re.compile(r"\bip\s+ospf\s+dead-interval\s+(?P<v>\d+)", re.I)
_OSPF_IF_COST = re.compile(r"\bip\s+ospf\s+cost\s+(?P<v>\d+)", re.I)
_OSPF_IF_NETWORK = re.compile(r"\bip\s+ospf\s+network\s+(?P<nt>\S+)", re.I)
# Junos: `protocols ospf area 0.0.0.0 interface ge-0/0/0`
_OSPF_JUN_AREA_IFACE = re.compile(
    r"\barea\s+(?P<area>\d+\.\d+\.\d+\.\d+|\d+)[\s\S]*?\binterface\s+(?P<iface>[\w/\.\-]+)",
    re.I,
)

# VXLAN: source-interface and VNI lists
# EOS: `vxlan source-interface Loopback1`; `vxlan vni 10010 vrf VRF1`; `vxlan vlan 10 vni 10010`
_VXLAN_SOURCE_EOS = re.compile(r"\bvxlan\s+source-interface\s+(?P<src>\S+)", re.I)
_VXLAN_VNI_EOS = re.compile(r"\bvxlan\s+(?:vlan\s+\d+\s+vni|vni)\s+(?P<vni>\d+)(?:\s+vrf\s+(?P<vrf>\S+))?", re.I)
# FRR: `vni 10010` inside `interface vxlan10010` blocks
_VXLAN_VNI_FRR = re.compile(r"\bvni\s+(?P<vni>\d+)\b", re.I)
# Junos: `set vlans X vxlan vni Y`; `set routing-instances X vtep-source-interface loN`
_VXLAN_VNI_JUN = re.compile(r"\bvxlan\s+vni\s+(?P<vni>\d+)", re.I)
_VTEP_SOURCE_JUN = re.compile(r"\bvtep-source-interface\s+(?P<src>\S+)", re.I)

# Interface address + name — needed for L1/L3 edge endpoint labelling.
# EOS/FRR/IOS style: `interface eth0\n  ip address 10.1.1.1/30`
# IMPORTANT: the body must only match space/tab-indented lines so it stops at
# the blank line / next top-level stanza — \s+ would eat newlines and run to EOF.
_IFACE_BLOCK_EOS = re.compile(
    r"^interface\s+(?P<iface>\S+)[ \t]*\n(?P<body>(?:[ \t]+\S[^\n]*\n)+)",
    re.M,
)
_IFACE_DESC_LINE = re.compile(r"^[ \t]+description\s+(?P<d>.+?)\s*$", re.I | re.M)
# Nokia SRL: ``interface ethernet-1/1 { ... subinterface 0 { ipv4 { address 10.0.1.3/31 { } } } }``
# Indented up to ~4 levels, address is on its own line with optional trailing brace.
_IFACE_BLOCK_SRL = re.compile(
    r"interface\s+(?P<iface>(?:ethernet-\d+(?:/\d+)+|system\d+|lo\d*|mgmt\d+))\s*\{(?P<body>.*?)^\s*\}\s*$",
    re.M | re.S,
)
_SRL_IFACE_ADDR = re.compile(r"address\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})", re.I)
_SRL_IFACE_DESC = re.compile(r"description\s+\"?(?P<d>[^\"\n;{}]+)\"?", re.I)
# FRR: `vrf NAME\n vni 50001\nexit-vrf` — captures L3 VNIs tied to a tenant VRF.
_FRR_VRF_VNI = re.compile(
    r"^vrf\s+(?P<vrf>\S+)\s*\n(?P<body>(?:\s+[^\n]*\n)+?)exit-vrf",
    re.M,
)
_FRR_ADVERTISE_ALL_VNI = re.compile(r"\badvertise-all-vni\b", re.I)
# Junos: `set interfaces ge-0/0/0 unit 0 family inet address 10.1.1.1/30`
_JUNOS_IF_SET = re.compile(
    r"set\s+interfaces\s+(?P<iface>\S+)(?:\s+unit\s+\d+)?\s+family\s+inet\s+address\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})",
    re.I,
)
_JUNOS_IF_DESC = re.compile(
    r"set\s+interfaces\s+(?P<iface>\S+)\s+(?:unit\s+\d+\s+)?description\s+\"?(?P<d>[^\"\n;]+)\"?",
    re.I,
)

# VRF list (best-effort, multi-vendor)
_VRF_EOS = re.compile(r"\bvrf\s+definition\s+(?P<v>\S+)", re.I)
_VRF_FRR = re.compile(r"\bvrf\s+(?P<v>\S+)\b", re.I)
_VRF_JUNOS = re.compile(r"\brouting-instances\s+(?P<v>\S+)\s+\{", re.I)

# Interface description — captures the description text
_DESCRIPTION = re.compile(r'description\s+["\']?([^"\';\n]+?)["\']?\s*[;\n]', re.I)

# Link speed (per-interface). Vendor styles:
#   EOS/IOS:   ``speed 100g`` / ``speed 10000``                 (bare line in iface block)
#   SRL:       ``port-speed 100G``                              (under ``ethernet { }``)
#   Junos:     ``set interfaces et-0/0/0 gigether-options speed 100g``
# We normalize to a short string like "100G", "10G", "1G", "40G", "25G".
_SPEED_KW = re.compile(r"(?:port-)?speed\s+(?P<v>\d+)\s*([GgMm])?", re.I)
_JUNOS_SPEED_SET = re.compile(
    r"set\s+interfaces\s+\S+\s+(?:unit\s+\d+\s+)?(?:gigether-options|ether-options)\s+speed\s+(?P<v>\d+)\s*([GgMm])?",
    re.I,
)

def _norm_speed(num: str, unit: str | None) -> str:
    """Normalize speed-like tokens to ``NUMUNIT`` (e.g. ``100G``).
    - "100" + "g"   → "100G"
    - "10000"       → "10G"  (Mbps form, common in IOS)
    - "1000"        → "1G"
    """
    try:
        n = int(num)
    except (TypeError, ValueError):
        return ""
    if unit and unit.upper() == "G":
        return f"{n}G"
    # No unit or Mbps unit
    if n >= 1000 and n % 1000 == 0:
        return f"{n // 1000}G"
    return f"{n}M"

# Speed inference from interface-name prefixes. Only used when no explicit speed
# directive was found. Conservative: only fires for vendor names with a well-
# known fixed speed (no guess for ambiguous prefixes like ``Ethernet1``).
def _infer_speed_from_name(name: str) -> str:
    if not name:
        return ""
    s = name.lower()
    if s.startswith("hundredgig"):       return "100G"
    if s.startswith("fortygig"):         return "40G"
    if s.startswith("twentyfivegig"):    return "25G"
    if s.startswith(("tengig", "tengige")): return "10G"
    if s.startswith("gigabitethernet"):  return "1G"
    if s.startswith("xe-"):              return "10G"
    if s.startswith("ge-"):              return "1G"
    if s.startswith("mge-"):             return "100G"
    if s.startswith("et-"):              return "40G"   # Junos default for et-* is 40G or 100G; 40G is safer
    return ""

# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class IfaceInfo:
    """One interface as it appears in the config — used to label L1/L3 edges."""
    name: str
    ip: str = ""        # CIDR, e.g. "10.1.1.1/30"
    description: str = ""
    speed: str = ""     # Normalized speed e.g. "100G" / "10G" / "1G"; "" if unknown
    ospf_area: str = ""
    ospf_hello: int | None = None
    ospf_dead: int | None = None
    ospf_cost: int | None = None
    ospf_network_type: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name, "ip": self.ip, "description": self.description,
            "speed": self.speed,
            "ospf_area": self.ospf_area,
            "ospf_hello": self.ospf_hello, "ospf_dead": self.ospf_dead,
            "ospf_cost": self.ospf_cost, "ospf_network_type": self.ospf_network_type,
        }


@dataclass
class DeviceFacts:
    """Structured facts about one device, extracted purely from its config."""
    hostname: str
    platform: str
    interface_ips: list[str]      # CIDR strings, e.g. ["10.1.1.1/30", ...] — kept for back-compat
    bgp_neighbors: list[str]      # bare IPs
    mlag_peers: list[str]         # bare IPs
    descriptions: list[str]
    has_chassis_cluster: bool     # Junos HA partner indicator
    local_asn: int | None = None             # AS this device runs BGP under
    bgp_peer_asn: dict[str, int] = field(default_factory=dict)  # peer_ip -> remote-as
    bgp_afs: list[str] = field(default_factory=list)            # ["ipv4-unicast","l2vpn-evpn",...]
    has_evpn_signaling: bool = False
    # New: structured interface inventory keyed by name. Lets edges report
    # interface name + IP + description without re-parsing the config.
    interfaces: dict[str, IfaceInfo] = field(default_factory=dict)
    # Router identity (loopback / OSPF / BGP-derived router-id)
    router_id: str = ""
    # VXLAN
    vtep_source_iface: str = ""
    vtep_ip: str = ""
    l2_vnis: list[int] = field(default_factory=list)
    l3_vnis: list[int] = field(default_factory=list)
    # VRFs (names only — full RD/RT parsing left for a later pass)
    vrfs: list[str] = field(default_factory=list)
    # OSPF process-level
    ospf_router_id: str = ""

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname, "platform": self.platform,
            "interface_ips": self.interface_ips,
            "bgp_neighbors": self.bgp_neighbors,
            "mlag_peers": self.mlag_peers,
            "descriptions": self.descriptions,
            "has_chassis_cluster": self.has_chassis_cluster,
            "local_asn": self.local_asn,
            "bgp_peer_asn": dict(self.bgp_peer_asn),
            "bgp_afs": list(self.bgp_afs),
            "has_evpn_signaling": self.has_evpn_signaling,
            "interfaces": {k: v.to_dict() for k, v in self.interfaces.items()},
            "router_id": self.router_id,
            "vtep_source_iface": self.vtep_source_iface,
            "vtep_ip": self.vtep_ip,
            "l2_vnis": list(self.l2_vnis),
            "l3_vnis": list(self.l3_vnis),
            "vrfs": list(self.vrfs),
            "ospf_router_id": self.ospf_router_id,
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

    local_asn: int | None = None
    m_bgp = _LOCAL_AS_BGP.search(config_text)
    if m_bgp:
        local_asn = int(m_bgp.group("asn"))
    else:
        m_jun = _LOCAL_AS_JUNOS.search(config_text)
        if m_jun:
            local_asn = int(m_jun.group("asn"))

    bgp_peer_asn: dict[str, int] = {}
    for m in _BGP_NEIGHBOR_FULL.finditer(config_text):
        peer_ip = m.group("ip")
        if _is_real_ip(peer_ip):
            bgp_peer_asn[peer_ip] = int(m.group("asn"))

    # Address families enabled under `router bgp` blocks. Normalized to
    # "ipv4-unicast" / "l2vpn-evpn" / "vpnv4-unicast" style. EOS uses
    # single-word shorthand (`address-family evpn`, `address-family ipv4`) —
    # we expand to the canonical form so we don't get dupes.
    _AF_CANON = {
        "evpn": "l2vpn-evpn",
        "ipv4": "ipv4-unicast",
        "ipv6": "ipv6-unicast",
        "vpnv4": "vpnv4-unicast",
        "vpnv6": "vpnv6-unicast",
    }
    bgp_afs: list[str] = []
    for m in _BGP_AF_BLOCK.finditer(config_text):
        af = re.sub(r"\s+", "-", m.group("af").lower())
        af = _AF_CANON.get(af, af)
        if af not in bgp_afs:
            bgp_afs.append(af)
    has_evpn_signaling = bool(_JUNOS_EVPN.search(config_text)) or any("evpn" in af for af in bgp_afs)
    if has_evpn_signaling and "l2vpn-evpn" not in bgp_afs:
        bgp_afs.append("l2vpn-evpn")

    # Structured interface inventory — name -> IfaceInfo. Used by both
    # PHYSICAL edge labelling (iface+ip+desc) and OSPF edge labelling (area+cost).
    interfaces: dict[str, IfaceInfo] = {}
    if plat in ("junos", "junos-srx", "junos-mx", "junos-ex"):
        for m in _JUNOS_IF_SET.finditer(config_text):
            iface = m.group("iface")
            info = interfaces.setdefault(iface, IfaceInfo(name=iface))
            if not info.ip:
                info.ip = m.group("ip")
        for m in _JUNOS_IF_DESC.finditer(config_text):
            iface = m.group("iface")
            info = interfaces.setdefault(iface, IfaceInfo(name=iface))
            if not info.description:
                info.description = m.group("d").strip()
        for m in _JUNOS_SPEED_SET.finditer(config_text):
            # Junos speed is on a separate ``set interfaces NAME gigether-options speed ...`` line.
            # Match the iface name out of the full match for safety.
            line = m.group(0)
            nm = re.search(r"set\s+interfaces\s+(\S+)", line)
            if nm:
                iface = nm.group(1)
                info = interfaces.setdefault(iface, IfaceInfo(name=iface))
                if not info.speed:
                    info.speed = _norm_speed(m.group("v"), m.group(2))
    # EOS/FRR/IOS block format works for non-Junos vendors.
    for m in _IFACE_BLOCK_EOS.finditer(config_text):
        iface = m.group("iface")
        body = m.group("body")
        info = interfaces.setdefault(iface, IfaceInfo(name=iface))
        ip_m = _EOS_IF_ADDR.search(body)
        if ip_m and not info.ip:
            info.ip = ip_m.group("ip")
        desc_m = _IFACE_DESC_LINE.search(body)
        if desc_m and not info.description:
            info.description = desc_m.group("d").strip()
        sp_m = _SPEED_KW.search(body)
        if sp_m and not info.speed:
            info.speed = _norm_speed(sp_m.group("v"), sp_m.group(2))
    # Nokia SRL — nested braces; we grab the outer ``interface NAME { ... }``
    # body and look for ``address X.X.X.X/Y`` plus optional ``description ...``.
    # Also feed the discovered IPs back into uniq_ips so _shared_subnet() can
    # see them when inferring inter-device links (it iterates interface_ips).
    for m in _IFACE_BLOCK_SRL.finditer(config_text):
        iface = m.group("iface")
        body = m.group("body")
        info = interfaces.setdefault(iface, IfaceInfo(name=iface))
        ip_m = _SRL_IFACE_ADDR.search(body)
        if ip_m and not info.ip:
            info.ip = ip_m.group("ip")
            if info.ip not in seen and _is_real_ip(info.ip):
                seen.add(info.ip)
                uniq_ips.append(info.ip)
        d_m = _SRL_IFACE_DESC.search(body)
        if d_m and not info.description:
            info.description = d_m.group("d").strip()
        sp_m = _SPEED_KW.search(body)
        if sp_m and not info.speed:
            info.speed = _norm_speed(sp_m.group("v"), sp_m.group(2))
        area_m = _OSPF_IF_AREA.search(body)
        if area_m:
            info.ospf_area = area_m.group("area")
        h_m = _OSPF_IF_HELLO.search(body)
        if h_m:
            info.ospf_hello = int(h_m.group("v"))
        d_m = _OSPF_IF_DEAD.search(body)
        if d_m:
            info.ospf_dead = int(d_m.group("v"))
        c_m = _OSPF_IF_COST.search(body)
        if c_m:
            info.ospf_cost = int(c_m.group("v"))
        nt_m = _OSPF_IF_NETWORK.search(body)
        if nt_m:
            info.ospf_network_type = nt_m.group("nt")

    # Speed inference from interface name — only when no explicit speed was set.
    # Skipped for vendor-agnostic names (Ethernet1, eth1, ethernet-1/X) since
    # those don't encode speed; better to leave blank than to invent.
    for info in interfaces.values():
        if not info.speed:
            info.speed = _infer_speed_from_name(info.name)

    # Router-IDs — FRR/EOS/Junos forms
    router_id = ""
    ospf_router_id = ""
    for rx in (_OSPF_ROUTER_ID_FRR, _OSPF_ROUTER_ID_EOS):
        m = rx.search(config_text)
        if m:
            ospf_router_id = m.group("rid")
            break
    if not ospf_router_id:
        m = _OSPF_ROUTER_ID_JUN.search(config_text)
        if m:
            ospf_router_id = m.group("rid")
    # Best-effort device router-id: prefer explicit OSPF RID, else any loopback IP.
    router_id = ospf_router_id
    if not router_id:
        for ip in uniq_ips:
            try:
                iface = ipaddress.ip_interface(ip)
                if iface.network.prefixlen == 32:
                    router_id = str(iface.ip)
                    break
            except (ipaddress.AddressValueError, ValueError):
                continue

    # VXLAN
    vtep_source_iface = ""
    vtep_ip = ""
    l2_vnis: list[int] = []
    l3_vnis: list[int] = []
    m = _VXLAN_SOURCE_EOS.search(config_text)
    if m:
        vtep_source_iface = m.group("src")
    else:
        m = _VTEP_SOURCE_JUN.search(config_text)
        if m:
            vtep_source_iface = m.group("src")
    if vtep_source_iface and vtep_source_iface.lower() in (n.lower() for n in interfaces):
        info = next(v for k, v in interfaces.items() if k.lower() == vtep_source_iface.lower())
        if info.ip:
            try:
                vtep_ip = str(ipaddress.ip_interface(info.ip).ip)
            except (ipaddress.AddressValueError, ValueError):
                vtep_ip = info.ip
    # FRR / Nokia SRL: VTEP source is implicit — it's the loopback used by EVPN.
    # FRR uses ``interface lo`` + ``advertise-all-vni`` under l2vpn-evpn AF.
    # SRL uses ``interface system0`` + ``afi-safi evpn`` under default network-instance.
    has_evpn_signal = bool(_FRR_ADVERTISE_ALL_VNI.search(config_text)) or "afi-safi evpn" in config_text
    if not vtep_ip and has_evpn_signal:
        # Try the conventional loopback names per platform; first /32 wins.
        for candidate in ("lo", "Loopback0", "Loopback1", "system0", "lo0"):
            info = interfaces.get(candidate) or next(
                (v for k, v in interfaces.items() if k.lower() == candidate.lower()), None
            )
            if info and info.ip:
                try:
                    vtep_ip = str(ipaddress.ip_interface(info.ip).ip)
                    if not vtep_source_iface:
                        vtep_source_iface = info.name
                    break
                except (ipaddress.AddressValueError, ValueError):
                    continue
    # Pick up VNIs (multi-vendor)
    for rx in (_VXLAN_VNI_EOS, _VXLAN_VNI_JUN):
        for m in rx.finditer(config_text):
            try:
                v = int(m.group("vni"))
                if v not in l2_vnis and v not in l3_vnis:
                    # Heuristic: L3VNI numbers commonly >= 50_000; L2VNI lower. Fallback: bucket all as L2.
                    (l3_vnis if v >= 50_000 else l2_vnis).append(v)
            except (TypeError, ValueError):
                continue
    if plat == "frr":
        # FRR pattern: dedicated `vxlan{vni}` interface block contains `vni <N>`
        for blk in _IFACE_BLOCK_EOS.finditer(config_text):
            iname = blk.group("iface")
            if not iname.lower().startswith("vxlan"):
                continue
            for m in _VXLAN_VNI_FRR.finditer(blk.group("body")):
                try:
                    v = int(m.group("vni"))
                    if v not in l2_vnis and v not in l3_vnis:
                        (l3_vnis if v >= 50_000 else l2_vnis).append(v)
                except (TypeError, ValueError):
                    continue
        # FRR L3VNI binding: ``vrf TENANT-A\n vni 50001\nexit-vrf`` is the
        # tenant-VRF → L3 VNI mapping used in symmetric IRB EVPN deployments.
        for m in _FRR_VRF_VNI.finditer(config_text):
            for vni_m in _VXLAN_VNI_FRR.finditer(m.group("body")):
                try:
                    v = int(vni_m.group("vni"))
                    if v not in l2_vnis and v not in l3_vnis:
                        l3_vnis.append(v)
                except (TypeError, ValueError):
                    continue

    # VRFs — flat list of names. We dedupe and skip common config-grammar
    # tokens that look like VRF names but aren't (admin-state, default, etc.).
    _VRF_SKIP = {
        "default", "instance", "context", "admin-state", "enable", "disable",
        "type", "interface", "subinterface", "ip-mtu", "next-hop", "static",
    }
    vrfs: list[str] = []
    for rx in (_VRF_EOS, _VRF_FRR, _VRF_JUNOS):
        for m in rx.finditer(config_text):
            v = m.group("v").strip().rstrip("{").strip()
            if v and v.lower() not in _VRF_SKIP and v not in vrfs:
                vrfs.append(v)

    return DeviceFacts(
        hostname=hostname, platform=plat,
        interface_ips=uniq_ips, bgp_neighbors=bgp_peers,
        mlag_peers=mlag, descriptions=descs,
        has_chassis_cluster=has_cluster,
        local_asn=local_asn,
        bgp_peer_asn=bgp_peer_asn,
        bgp_afs=bgp_afs,
        has_evpn_signaling=has_evpn_signaling,
        interfaces=interfaces,
        router_id=router_id,
        vtep_source_iface=vtep_source_iface,
        vtep_ip=vtep_ip,
        l2_vnis=l2_vnis,
        l3_vnis=l3_vnis,
        vrfs=vrfs,
        ospf_router_id=ospf_router_id,
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
