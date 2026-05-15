"""Rich multi-cluster Graphviz diagram for a site bundle.

Produces a DOT file matching the style of the existing
`03_Site_Reports/Per_Site/Site_Analyses/HEL1_Traffic_Flow_Diagram.dot`:

  1. cluster_Architecture       — High-level tier overview (WAN → FW → Switches)
  2. cluster_network_details    — WAN IPs / VLANs / Internal subnets
  3. cluster_flow1/2/3          — Traffic flow paths (Internet, Management, Storage)

If graphviz `dot` is installed, can also render to PNG/SVG.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable


# ─────────────────────────────────────────────────────────────────────────────
# VLAN / Subnet classification
# ─────────────────────────────────────────────────────────────────────────────

VLAN_CATEGORIES: dict[str, tuple[str, str]] = {
    # name_keyword: (category_label, emoji)
    "mgmt":       ("Management", "🟡"),
    "management": ("Management", "🟡"),
    "ipmi":       ("IPMI/BMC", "🟤"),
    "bmc":        ("IPMI/BMC", "🟤"),
    "pxe":        ("PXE/Boot", "⚪"),
    "boot":       ("PXE/Boot", "⚪"),
    "storage":    ("Storage", "🔵"),
    "stor":       ("Storage", "🔵"),
    "dr":         ("DR/Backup", "🟣"),
    "backup":     ("DR/Backup", "🟣"),
    "advpn":      ("ADVPN", "🟢"),
    "vpn":        ("ADVPN", "🟢"),
    "prod":       ("Production/Access", "🟠"),
    "access":     ("Production/Access", "🟠"),
    "wan":        ("WAN/External", "🔴"),
    "transit":    ("WAN/External", "🔴"),
    "core":       ("Network/Transit", "⚫"),
    "fabric":     ("Network/Transit", "⚫"),
    "infra":      ("Infrastructure", "⚫"),
    "infrastructure": ("Infrastructure", "⚫"),
}

CATEGORY_ORDER = ["WAN/External", "Management", "Production/Access", "Storage",
                   "DR/Backup", "IPMI/BMC", "PXE/Boot", "ADVPN", "Network/Transit",
                   "Infrastructure", "Other"]


def categorize_vlan(name: str, vlan_id: int | None = None,
                     subnets: list[str] | None = None) -> tuple[str, str]:
    """Return (category, emoji) for a VLAN name/id/subnets.

    Detection order:
      1. Subnet-based (example-style numbering: 10.1.x.x=mgmt, 10.245.x.x=storage, etc.)
      2. Name keyword (mgmt/storage/dr/ipmi/pxe/advpn/...)
      3. VLAN ID range heuristics (14 = mgmt, 200+ = vpn, 28/100 = ipmi)
      4. Falls back to ('Other', '⚫')
    """
    # Rule 1: Subnet-based (most reliable when names are generic like "vlan10")
    if subnets:
        for s in subnets:
            try:
                octets = s.split("/")[0].split(".")
                if len(octets) != 4:
                    continue
                o0, o1 = int(octets[0]), int(octets[1])
            except (ValueError, IndexError):
                continue
            # 10.1.x.x → Management (example standard)
            if o0 == 10 and o1 == 1:
                return "Management", "🟡"
            # 10.245.206.x / 10.245.205.x → Storage
            if o0 == 10 and o1 == 245 and 200 <= int(octets[2]) <= 206:
                return "Storage", "🔵"
            # 10.245.207.x → IPMI/BMC
            if o0 == 10 and o1 == 245 and int(octets[2]) == 207:
                return "IPMI/BMC", "🟤"
            # 10.245.208.x / 209.x → PXE/Boot or DR
            if o0 == 10 and o1 == 245 and int(octets[2]) in (208, 209):
                return "PXE/Boot", "⚪"
            # 10.92.x.x / 10.216.x.x / 10.218.x.x → DR
            if o0 == 10 and o1 in (92, 216, 218):
                return "DR/Backup", "🟣"
            # 10.2.x.x → Fabric / transit
            if o0 == 10 and o1 == 2:
                return "Network/Transit", "⚫"
            # 10.253.x.x → Production
            if o0 == 10 and o1 == 253:
                return "Production/Access", "🟠"
    # Rule 2: Name keyword
    n = (name or "").lower()
    for kw, (cat, emoji) in VLAN_CATEGORIES.items():
        if kw in n:
            return cat, emoji
    # Rule 3: VLAN ID heuristics (example standard mappings)
    if vlan_id is not None:
        # Production/access ranges per demo-EAST dot file: 20/21, 63/64
        if vlan_id in (14, 15):           return "Management", "🟡"
        if vlan_id in (22, 23):           return "Storage", "🔵"
        if vlan_id == 24:                  return "DR/Backup", "🟣"
        if vlan_id in (28, 100):           return "IPMI/BMC", "🟤"
        if vlan_id == 30:                  return "PXE/Boot", "⚪"
        if vlan_id in (20, 21, 63, 64):   return "Production/Access", "🟠"
        if vlan_id in (206, 216, 226):    return "ADVPN", "🟢"
        if vlan_id in (10, 19, 33, 34, 66, 115): return "Network/Transit", "⚫"
        if vlan_id >= 4000:                return "Infrastructure", "⚫"
    return "Other", "⚫"


# ─────────────────────────────────────────────────────────────────────────────
# Extractors (richer than site_doc — pulls VLAN names, WAN IPs, ADVPN, etc.)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class VlanInfo:
    vlan_id: int
    name: str = ""
    subnets: list[str] = field(default_factory=list)
    description: str = ""
    category: str = "Other"
    emoji: str = "⚫"


@dataclass
class WanIp:
    ip: str            # CIDR or bare IP
    interface: str = ""
    description: str = ""
    isp: str = ""      # detected ISP name if any


@dataclass
class IspProfile:
    name: str
    asn: str = ""
    circuit_id: str = ""
    interfaces: list[str] = field(default_factory=list)
    public_ips: list[str] = field(default_factory=list)
    status: str = "active"  # active | shutdown | unknown


@dataclass
class AdvpnTunnel:
    interface: str   # e.g. st0.1
    address: str = ""
    description: str = ""


# Junos VLAN block:  vlan-name vlan10 { vlan-id 10; l3-interface irb.10; }
_JUNOS_VLAN_BLOCK = re.compile(
    r"(?P<name>\S+)\s*\{\s*[^{}]*?vlan-id\s+(?P<id>\d{1,4})\s*;[^{}]*?\}",
    re.S,
)
# Junos VLAN list-style: `set vlans vlan10 vlan-id 10`
_JUNOS_VLAN_SET = re.compile(r"set\s+vlans\s+(\S+)\s+vlan-id\s+(\d{1,4})", re.I)
# EOS: vlan 10\n   name MGMT
_EOS_VLAN_BLOCK = re.compile(r"^\s*vlan\s+(\d{1,4})\s*\n(?:\s+name\s+(\S+))?", re.M)
# IRB / SVI subnet bindings: `irb.10 unit 10 family inet address 10.1.1.1/24` → vlan 10
_JUNOS_IRB_SUBNET = re.compile(
    r"irb\s*\{[^}]*?unit\s+(\d{1,4})[^}]*?address\s+(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})",
    re.S,
)
# EOS interface Vlan10 / ip address 10.1.1.1/24
_EOS_VLAN_SUBNET = re.compile(
    r"interface\s+Vlan(\d{1,4})\s*\n(?:\s+\S[^\n]*\n)*?\s+ip\s+address\s+(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})",
    re.M,
)

# Public IP detection — anything outside RFC1918 / link-local / loopback
import ipaddress as _ip


def _is_public_ip(ip: str) -> bool:
    # Treat sanitizer-pseudonymized public IPs as public too
    if ip.startswith("PUB-"):
        return True
    try:
        addr = _ip.ip_interface(ip).ip if "/" in ip else _ip.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or
                addr.is_multicast or addr.is_reserved or addr.is_unspecified)


def extract_vlans(config_text: str, platform: str) -> dict[int, VlanInfo]:
    """Return {vlan_id: VlanInfo} extracted from one config."""
    vlans: dict[int, VlanInfo] = {}
    if platform.lower().startswith("jun"):
        for m in _JUNOS_VLAN_BLOCK.finditer(config_text):
            try:
                vid = int(m.group("id"))
            except ValueError:
                continue
            name = m.group("name")
            vlans.setdefault(vid, VlanInfo(vlan_id=vid, name=name))
        for m in _JUNOS_VLAN_SET.finditer(config_text):
            try:
                vid = int(m.group(2))
            except ValueError:
                continue
            vlans.setdefault(vid, VlanInfo(vlan_id=vid, name=m.group(1)))
        # IRB subnet → vlan_id
        for m in _JUNOS_IRB_SUBNET.finditer(config_text):
            try:
                vid = int(m.group(1))
            except ValueError:
                continue
            vlans.setdefault(vid, VlanInfo(vlan_id=vid))
            subnet = m.group(2)
            if subnet not in vlans[vid].subnets:
                vlans[vid].subnets.append(subnet)
    else:  # EOS / IOS
        for m in _EOS_VLAN_BLOCK.finditer(config_text):
            vid = int(m.group(1))
            name = m.group(2) or ""
            vlans.setdefault(vid, VlanInfo(vlan_id=vid, name=name))
        for m in _EOS_VLAN_SUBNET.finditer(config_text):
            vid = int(m.group(1))
            vlans.setdefault(vid, VlanInfo(vlan_id=vid))
            if m.group(2) not in vlans[vid].subnets:
                vlans[vid].subnets.append(m.group(2))

    # Assign categories (uses subnet info too)
    for v in vlans.values():
        v.category, v.emoji = categorize_vlan(v.name, v.vlan_id, v.subnets)
    return vlans


def merge_vlans(per_device: list[dict[int, VlanInfo]]) -> dict[int, VlanInfo]:
    """Merge VLAN dicts from many devices into one global view (union subnets)."""
    out: dict[int, VlanInfo] = {}
    for vmap in per_device:
        for vid, v in vmap.items():
            if vid not in out:
                out[vid] = VlanInfo(vlan_id=vid, name=v.name)
            o = out[vid]
            if v.name and not o.name:
                o.name = v.name
            for s in v.subnets:
                if s not in o.subnets:
                    o.subnets.append(s)
            if not o.category or o.category == "Other":
                o.category, o.emoji = categorize_vlan(o.name or v.name, vid, o.subnets)
    # Final re-categorization pass once all subnets are merged
    for v in out.values():
        v.category, v.emoji = categorize_vlan(v.name, v.vlan_id, v.subnets)
    return out


def extract_wan_ips(config_text: str, platform: str) -> list[WanIp]:
    """Find public-IP-bearing interfaces — Junos + EOS + Junos `set` style."""
    out: list[WanIp] = []
    if platform.lower().startswith("jun"):
        # ── Form A: Hierarchical Junos config (interfaces { reth0 { unit 0 { ... }}})
        # Walk line-by-line, track current interface + description from outer block.
        cur_iface: str = ""
        cur_unit: str = ""
        cur_desc: str = ""
        brace_depth = 0
        iface_stack: list[tuple[str, int]] = []  # (iface_name, depth_at_open)
        for raw_line in config_text.splitlines():
            line = raw_line.rstrip()
            # Track brace depth for scope
            opens = line.count("{")
            closes = line.count("}")
            # Detect interface block opening:  ge-0/0/0 {   or  reth0 {   or  unit 0 {
            m_open = re.match(r"^\s*((?:ge|xe|et|ae|reth|fe|me|fxp|st|lo)\S*)\s*\{", line)
            if m_open and "unit" not in m_open.group(1):
                cur_iface = m_open.group(1)
                cur_desc = ""
                iface_stack.append((cur_iface, brace_depth))
            m_unit = re.match(r"^\s*unit\s+(\d+)\s*\{", line)
            if m_unit:
                cur_unit = m_unit.group(1)
            # Description on the same scope
            m_d = re.match(r'^\s*description\s+"?([^";\n]+)"?\s*;', line)
            if m_d and cur_iface:
                cur_desc = m_d.group(1).strip()
            # Address — handle both line-start AND inline-after-`family inet { address X;`
            for m_a in re.finditer(
                r"address\s+((?:\d{1,3}(?:\.\d{1,3}){3}|PUB-[0-9a-f]{6,16})(?:/\d{1,2})?)\s*;",
                line,
            ):
                ip_val = m_a.group(1)
                if cur_iface and _is_public_ip(ip_val):
                    ifname = cur_iface + (f".{cur_unit}" if cur_unit else "")
                    out.append(WanIp(ip=ip_val, interface=ifname, description=cur_desc))
            # Update depth + pop interface scope when its brace closes
            brace_depth += opens - closes
            while iface_stack and brace_depth <= iface_stack[-1][1]:
                iface_stack.pop()
                cur_iface = iface_stack[-1][0] if iface_stack else ""
                cur_unit = ""
                cur_desc = ""
        # ── Form B: Junos `set` style config (single-line):
        # `set interfaces reth0 unit 0 family inet address 89.116.175.X/26`
        for m in re.finditer(
            r"set\s+interfaces\s+(\S+)\s+unit\s+(\d+)\s+family\s+inet\s+address\s+"
            r"((?:\d{1,3}(?:\.\d{1,3}){3}|PUB-[0-9a-f]{6,16})(?:/\d{1,2})?)",
            config_text,
        ):
            ip = m.group(3)
            if not _is_public_ip(ip):
                continue
            ifname = f"{m.group(1)}.{m.group(2)}"
            # Look for matching description elsewhere
            desc_pat = (rf"set\s+interfaces\s+{re.escape(m.group(1))}\s+"
                        rf"(?:unit\s+\d+\s+)?description\s+\"?([^\";\n]+)")
            d_m = re.search(desc_pat, config_text)
            out.append(WanIp(ip=ip, interface=ifname,
                             description=(d_m.group(1).strip() if d_m else "")))
    else:
        # EOS / IOS: interface X / ip address Y/Z, possibly with description
        cur_iface = ""
        cur_desc = ""
        for line in config_text.splitlines():
            m = re.match(r"\s*interface\s+(\S+)", line)
            if m:
                cur_iface = m.group(1)
                cur_desc = ""
                continue
            m = re.match(r"\s+description\s+(.+)", line)
            if m:
                cur_desc = m.group(1).strip()
                continue
            m = re.match(r"\s+ip\s+address\s+(\S+)", line)
            if m and _is_public_ip(m.group(1)):
                out.append(WanIp(ip=m.group(1), interface=cur_iface, description=cur_desc))
    # Dedup by IP
    seen: set[str] = set()
    uniq: list[WanIp] = []
    for w in out:
        if w.ip in seen:
            continue
        seen.add(w.ip)
        uniq.append(w)
    return uniq


def extract_isp_profiles(config_text: str, platform: str,
                          wan_ips: list[WanIp]) -> list[IspProfile]:
    """Detect ISPs from interface descriptions referencing transit providers."""
    isp_kws = {
        "telia": "Telia", "arelion": "Arelion", "lumen": "Lumen", "cogent": "Cogent",
        "ntt": "NTT", "gtt": "GTT", "leaseweb": "Leaseweb", "level3": "Level3",
        "centurylink": "CenturyLink", "verizon": "Verizon", "att": "AT&T",
        "deutsche telekom": "Deutsche Telekom", "vodafone": "Vodafone",
        "optus": "Optus", "telstra": "Telstra", "tpg": "TPG",
        "swisscom": "Swisscom", "colt": "Colt", "comcast": "Comcast",
        "orange": "Orange", "bt": "BT", "kpn": "KPN", "tata": "Tata",
        "akamai": "Akamai",
    }
    profiles: dict[str, IspProfile] = {}
    for w in wan_ips:
        d = (w.description or "").lower()
        for kw, friendly in isp_kws.items():
            if kw in d:
                prof = profiles.setdefault(friendly, IspProfile(name=friendly))
                prof.public_ips.append(w.ip)
                if w.interface and w.interface not in prof.interfaces:
                    prof.interfaces.append(w.interface)
                # Detect shutdown — look for "deactivate" or "disable" near this interface
                if any(t in d for t in ("disabled", "shutdown", "decommis")):
                    prof.status = "shutdown"
                break

    # Also search descriptions explicitly for shutdown context
    for prof in profiles.values():
        for ifc in prof.interfaces:
            pattern = rf"(?:deactivate\s+interfaces\s+{re.escape(ifc)}|interfaces\s+{re.escape(ifc)}[\s\S]{{0,200}}disable)"
            if re.search(pattern, config_text, re.I):
                prof.status = "shutdown"
                break

    # Try to extract ASNs near ISP keywords (best-effort)
    for kw, friendly in isp_kws.items():
        if friendly not in profiles:
            continue
        m = re.search(
            rf"description[^;]*{re.escape(kw)}[^;]*[\s\S]{{0,500}}?peer-as\s+(\d+)",
            config_text, re.I,
        )
        if m:
            profiles[friendly].asn = m.group(1)
    return sorted(profiles.values(), key=lambda p: p.name)


def extract_advpn_tunnels(config_text: str, platform: str) -> list[AdvpnTunnel]:
    out: list[AdvpnTunnel] = []
    if platform.lower().startswith("jun"):
        for m in re.finditer(
            r"(st\d+\.\d+)\s*\{[\s\S]{0,800}?\}",
            config_text,
        ):
            block = m.group(0)
            addr_m = re.search(r"address\s+(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})", block)
            desc_m = re.search(r"description\s+([^;\n]+)", block)
            out.append(AdvpnTunnel(
                interface=m.group(1),
                address=addr_m.group(1) if addr_m else "",
                description=(desc_m.group(1) if desc_m else "").strip(' "'),
            ))
    return out


# ─────────────────────────────────────────────────────────────────────────────
# DOT diagram generation (demo-EAST style — 3 clusters)
# ─────────────────────────────────────────────────────────────────────────────

def build_site_dot(
    site_id: str,
    devices: list[dict],
    *,
    include_flows: bool = True,
) -> str:
    """Generate a comprehensive multi-cluster DOT for a site bundle."""
    # Per-device fact gathering
    all_vlans: list[dict[int, VlanInfo]] = []
    all_wan: list[WanIp] = []
    fws: list[str] = []
    sws: list[str] = []
    rts: list[str] = []
    fw_configs: dict[str, tuple[str, str]] = {}  # hostname -> (platform, config_text)

    for d in devices:
        host = d["hostname"]
        platform = d.get("platform", "junos")
        cfg = d.get("config_text", "")
        all_vlans.append(extract_vlans(cfg, platform))
        if "fw" in host:
            fws.append(host); fw_configs[host] = (platform, cfg)
        elif "rt" in host:
            rts.append(host)
        else:
            sws.append(host)
        # WAN IPs from firewall + router devices
        if "fw" in host or "rt" in host:
            all_wan.extend(extract_wan_ips(cfg, platform))
    vlans = merge_vlans(all_vlans)
    # Dedup WAN IPs
    seen_ip: set[str] = set()
    wan_ips: list[WanIp] = []
    for w in all_wan:
        if w.ip in seen_ip:
            continue
        seen_ip.add(w.ip)
        wan_ips.append(w)

    # Compose the DOT
    lines: list[str] = []
    lines.append(f"// {site_id} Comprehensive Traffic Flow Diagram (auto-generated)")
    lines.append(f"digraph {site_id}_Flow_Diagram {{")
    lines.append('    graph [fontname="Arial", fontsize=12, '
                 f'label="{site_id} Datacenter Traffic Flow", '
                 'labelloc=t, concentrate=true, rankdir=TB, splines=ortho];')
    lines.append('    node [fontname="Arial", fontsize=10, shape=box, style=filled, margin=0.2];')
    lines.append('    edge [fontname="Arial", fontsize=9, penwidth=2];')
    lines.append("")

    # ─── Section 1: High-Level Architecture ───
    lines.append("    // SECTION 1: HIGH-LEVEL ARCHITECTURE")
    lines.append("    subgraph cluster_Architecture {")
    lines.append('        label="High-Level Architecture Overview";')
    lines.append('        style=filled; color="#e0e0e0"; fontsize=14; fontname="Arial Bold";')
    lines.append("")
    # WAN cluster
    lines.append("        subgraph cluster_wan_arch {")
    lines.append('            label="Internet / WAN Layer";')
    lines.append('            style=filled; color="#b3d9ff"; rank=same;')
    wan_summary = ", ".join(w.ip for w in wan_ips[:3])
    extra = f"\\n(+{len(wan_ips)-3} more)" if len(wan_ips) > 3 else ""
    lines.append(f'            Internet [label="Internet\\n\\nWAN: {wan_summary}{extra}", '
                  f'shape=cloud, fillcolor="#87ceeb", fontsize=10, width=3];')
    lines.append("        }")
    lines.append("")
    # Firewall cluster
    if fws:
        lines.append("        subgraph cluster_security_arch {")
        lines.append('            label="Tier 2: Security Layer";')
        lines.append('            style=filled; color="#ffcccc"; rank=same;')
        for fw in fws:
            lines.append(f'            {_n(fw)}_arch [label="{fw}", fillcolor="#ff6666", shape=component];')
        lines.append("        }")
        lines.append("")
    # Router cluster
    if rts:
        lines.append("        subgraph cluster_router_arch {")
        lines.append('            label="Tier 2b: Edge Routers";')
        lines.append('            style=filled; color="#ffeebf"; rank=same;')
        for rt in rts:
            lines.append(f'            {_n(rt)}_arch [label="{rt}", fillcolor="#ffa500", shape=ellipse];')
        lines.append("        }")
        lines.append("")
    # Switch cluster
    if sws:
        lines.append("        subgraph cluster_fabric_arch {")
        lines.append(f'            label="Tier 3: Switching Fabric | {len(sws)} Switches";')
        lines.append('            style=filled; color="#ccffcc";')
        for sw in sws:
            lines.append(f'            {_n(sw)}_arch [label="{sw}", fillcolor="#66cc66"];')
        lines.append("        }")
        lines.append("")
    # Architectural connections
    if fws and (rts or sws):
        target_devices = rts + sws
        targets = " ".join(f"{_n(t)}_arch" for t in target_devices[:6])
        more = f' /* +{len(target_devices)-6} more */' if len(target_devices) > 6 else ""
        lines.append('        Internet -> {' + " ".join(f"{_n(f)}_arch" for f in fws) +
                      '} [color="#0066cc", penwidth=3];')
        lines.append('        ' + " ".join(f"{_n(f)}_arch" for f in fws) +
                      f' -> {{{targets}{more}}} [color="#009900"];')
    elif sws and not fws:
        lines.append('        Internet -> {' + " ".join(f"{_n(t)}_arch" for t in sws[:3]) +
                      '} [color="#0066cc", penwidth=3];')
    lines.append("    }")
    lines.append("")

    # ─── Section 2: Network Configuration Details ───
    lines.append("    // SECTION 2: NETWORK DETAILS")
    lines.append("    subgraph cluster_network_details {")
    lines.append('        label="Network Configuration Details";')
    lines.append('        style=filled; color="#f0f0f0"; fontsize=12; fontname="Arial Bold";')
    lines.append("")
    # WAN IPs cluster
    if wan_ips:
        lines.append("        subgraph cluster_wan_details {")
        lines.append('            label="WAN Interfaces & IP Addresses";')
        lines.append('            style=filled; color="#cce6ff";')
        wan_label = "WAN Interfaces:\\l"
        for i, w in enumerate(wan_ips[:10], 1):
            wan_label += f"  {i}. {w.ip}\\l"
        if len(wan_ips) > 10:
            wan_label += f"  ... +{len(wan_ips)-10} more\\l"
        lines.append(f'            WAN_IPs [label="{wan_label}", shape=box, fillcolor="#e6f2ff", fontsize=9, align=left];')
        lines.append("        }")
        lines.append("")
    # VLAN cluster
    if vlans:
        lines.append("        subgraph cluster_vlan_details {")
        lines.append('            label="VLAN Configuration & Network Mapping";')
        lines.append('            style=filled; color="#ccffcc";')
        vlan_label = "VLANs & Subnets:\\l"
        for vid in sorted(vlans.keys()):
            v = vlans[vid]
            subnets = ", ".join(v.subnets) if v.subnets else "—"
            tag = f" - {v.category}" if v.category != "Other" else ""
            sub_str = f": {subnets}" if v.subnets else ""
            vlan_label += f"  VLAN {vid}{tag}{sub_str}\\l"
        # Escape any literal " inside the label
        vlan_label = vlan_label.replace('"', "'")
        lines.append(f'            VLAN_List [label="{vlan_label}", shape=box, fillcolor="#e6ffe6", fontsize=8, align=left];')
        lines.append("        }")
        lines.append("")
    # Internal subnets (categorized)
    by_cat: dict[str, list[str]] = defaultdict(list)
    for v in vlans.values():
        for s in v.subnets:
            try:
                addr = _ip.ip_interface(s).ip
                if not addr.is_global:
                    by_cat[v.category].append(s)
            except ValueError:
                pass
    if by_cat:
        lines.append("        subgraph cluster_internal_networks {")
        lines.append('            label="Internal Network Subnets";')
        lines.append('            style=filled; color="#fff0cc";')
        nets_label = ""
        for cat in CATEGORY_ORDER:
            if cat not in by_cat:
                continue
            emoji = next((e for _, (c, e) in VLAN_CATEGORIES.items() if c == cat), "⚫")
            nets_label += f"{emoji} {cat}:\\l"
            for s in sorted(set(by_cat[cat]))[:6]:
                nets_label += f"  {s}\\l"
            if len(set(by_cat[cat])) > 6:
                nets_label += f"  ... +{len(set(by_cat[cat])) - 6} more\\l"
        lines.append(f'            Internal_Nets [label="{nets_label}", shape=box, fillcolor="#fff5e6", fontsize=8, align=left];')
        lines.append("        }")
    lines.append("    }")
    lines.append("")

    # ─── Section 3: Traffic Flow Diagrams ───
    if include_flows:
        flow_n = 1
        # Flow 1: Internet / WAN
        if fws or sws:
            entry_fw = fws[0] if fws else (sws[0] if sws else None)
            core_sw = next((s for s in sws if "sw-04" in s or "sw-01" in s), sws[0] if sws else None)
            lines.append("    // FLOW 1: Internet/WAN Traffic")
            lines.append(f"    subgraph cluster_flow{flow_n} {{")
            lines.append(f'        label="Flow {flow_n}: Internet/WAN Traffic";')
            lines.append('        style=filled; color="#cce6ff";')
            lines.append('        flow1_internet [label="Internet/WAN\\n' +
                          '\\n'.join(w.ip for w in wan_ips[:3]) + '", shape=cloud, fillcolor="#87ceeb"];')
            if entry_fw:
                lines.append(f'        flow1_fw [label="Firewall\\n{entry_fw}", fillcolor="#ff6666", shape=component];')
                lines.append('        flow1_internet -> flow1_fw [color="#0066cc", penwidth=3];')
                if core_sw:
                    lines.append(f'        flow1_core [label="Core Switch\\n{core_sw}", fillcolor="#66cc66"];')
                    lines.append('        flow1_fw -> flow1_core [color="#009900"];')
                    lines.append('        flow1_servers [label="Production\\nServers", shape=box3d, fillcolor="#ffcc99"];')
                    lines.append('        flow1_core -> flow1_servers [color="#009900"];')
            lines.append("    }")
            lines.append("")
            flow_n += 1
        # Flow 2: Management
        mgmt_vlans = [v for v in vlans.values() if v.category == "Management"]
        if mgmt_vlans:
            lines.append("    // FLOW 2: Management Traffic")
            lines.append(f"    subgraph cluster_flow{flow_n} {{")
            lines.append(f'        label="Flow {flow_n}: Management Traffic | VLAN {mgmt_vlans[0].vlan_id}";')
            lines.append('        style=filled; color="#fff0cc";')
            lines.append('        flow2_mgmt [label="Management\\nSystem", shape=cylinder, fillcolor="#ffe699"];')
            lines.append('        flow2_sw [label="Mgmt Switch\\n' +
                          f'VLAN {mgmt_vlans[0].vlan_id}", fillcolor="#66cc66"];')
            if fws:
                lines.append(f'        flow2_fw [label="Firewall\\nMgmt Zone", fillcolor="#ff6666", shape=component];')
                lines.append('        flow2_sw -> flow2_fw [color="#cc9900"];')
                lines.append('        flow2_dev [label="Network\\nDevices", shape=box3d, fillcolor="#ffcc99"];')
                lines.append('        flow2_fw -> flow2_dev [color="#cc9900"];')
            lines.append('        flow2_mgmt -> flow2_sw [color="#cc9900"];')
            lines.append("    }")
            lines.append("")
            flow_n += 1
        # Flow 3: Storage
        stor_vlans = [v for v in vlans.values() if v.category == "Storage"]
        if stor_vlans:
            lines.append("    // FLOW 3: Storage Traffic")
            lines.append(f"    subgraph cluster_flow{flow_n} {{")
            lines.append(f'        label="Flow {flow_n}: Storage Traffic | VLAN {stor_vlans[0].vlan_id}";')
            lines.append('        style=filled; color="#ccffcc";')
            lines.append('        flow3_comp [label="Compute\\nServers", shape=box3d, fillcolor="#ffcc99"];')
            lines.append(f'        flow3_sw [label="Storage Switch\\nVLAN {stor_vlans[0].vlan_id}", fillcolor="#66cc66"];')
            lines.append('        flow3_stor [label="Storage Arrays\\nSAN/NAS", shape=cylinder, fillcolor="#9999ff"];')
            lines.append('        flow3_comp -> flow3_sw [color="#009900"];')
            lines.append('        flow3_sw -> flow3_stor [color="#009900"];')
            lines.append("    }")
    lines.append("}")
    return "\n".join(lines)


def _n(name: str) -> str:
    """Sanitize node id for DOT (replace non-alphanum with underscore)."""
    return re.sub(r"[^A-Za-z0-9_]", "_", name)


# ─────────────────────────────────────────────────────────────────────────────
# Render DOT → SVG / PNG (graphviz must be installed)
# ─────────────────────────────────────────────────────────────────────────────

def render_dot(dot_text: str, fmt: str = "svg") -> bytes | None:
    """Render DOT to PNG or SVG bytes. Returns None if graphviz is unavailable.

    Uses byte-mode subprocess pipes — the previous `text=True` codepath
    corrupted PNG output via a `latin-1` round-trip that mangled non-ASCII
    bytes inside PNG chunks.
    """
    if shutil.which("dot") is None:
        return None
    fmt = fmt.lower()
    if fmt not in ("png", "svg"):
        return None
    try:
        proc = subprocess.run(
            ["dot", f"-T{fmt}"],
            input=dot_text.encode("utf-8"),
            capture_output=True, timeout=30,
        )
        if proc.returncode != 0:
            return None
        return proc.stdout
    except (subprocess.TimeoutExpired, OSError):
        return None


def render_dot_to_png(dot_text: str) -> bytes | None:
    """Render DOT to PNG bytes directly (binary-safe)."""
    if shutil.which("dot") is None:
        return None
    try:
        proc = subprocess.run(
            ["dot", "-Tpng"], input=dot_text.encode("utf-8"),
            capture_output=True, timeout=30,
        )
        if proc.returncode != 0:
            return None
        return proc.stdout
    except (subprocess.TimeoutExpired, OSError):
        return None
