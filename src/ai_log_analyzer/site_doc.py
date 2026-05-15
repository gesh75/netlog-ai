"""Comprehensive site documentation generator — PEER-D-style depth.

Produces a multi-section markdown report (~600-1200 lines) covering:

  1. Executive Summary (LLM-enriched, with status/tier/critical findings)
  2. Infrastructure Composition (by role + software versions)
  3. Facility Information (inferred from hostname pattern)
  4. Site Architecture (role, ASN, device types)
  5. Per-Device Details (one section per device with role description)
  6. VLAN and Subnet Documentation (categorized: mgmt/storage/DR/IPMI/PXE/ADVPN)
  7. WAN / Public IP Inventory + ISP Profiles
  8. BGP & Routing Analysis (iBGP / eBGP / OSPF / ISIS / Static)
  9. ADVPN / IPsec Tunnels
 10. Security Configuration (zones, policies, chassis-cluster)
 11. Network Services (DNS, NTP, SNMP, Syslog, RADIUS, TACACS)
 12. Software Versions and Lifecycle (with EOL warnings)
 13. Compliance Findings (built-in rule engine)
 14. Topology Diagram (Mermaid inline + Graphviz DOT exported)
 15. Recommendations (P1-P4 with SLA targets)
 16. Technical Summary
 17. Appendices (config file inventory, BGP peer table, edge-inference rules)
"""
from __future__ import annotations

import base64
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ai_log_analyzer import compliance, llm, site_diagram, topology, topology_infer


# ─────────────────────────────────────────────────────────────────────────────
# Software lifecycle / EOL — known Junos + EOS release dates and EOL deadlines
# ─────────────────────────────────────────────────────────────────────────────

# Conservative lifecycle hints. Format: prefix → (release_date, eol_date_estimate, status)
JUNOS_LIFECYCLE: dict[str, tuple[str, str, str]] = {
    "12.": ("2012", "2018", "🔴 EOL — critical security risk"),
    "13.": ("2013", "2019", "🔴 EOL — critical security risk"),
    "14.": ("2014", "2020", "🔴 EOL — out of support"),
    "15.": ("2015", "2021", "🔴 EOL — out of support"),
    "16.": ("2016", "2022", "🔴 EOL — out of support"),
    "17.": ("2017", "2023", "🟠 EOL — limited support"),
    "18.": ("2018", "2024", "🟠 EOL approaching / limited support"),
    "19.1": ("2019", "2024-09", "🟠 EOL — limited support"),
    "19.2": ("2019", "2025-04", "🟠 EOL / EOL approaching"),
    "19.3": ("2019", "2025-09", "🟠 EOL approaching"),
    "19.4": ("2019", "2025-12", "🟡 EOL within 12 months"),
    "20.": ("2020", "2026", "🟡 EOL approaching"),
    "21.1": ("2021", "2025", "🟡 EOL approaching"),
    "21.2": ("2021", "2026", "🟡 EOL within 12 months"),
    "21.3": ("2021", "2026", "🟡 EOL within 12 months"),
    "21.4": ("2021", "2028", "✅ Supported (LTS)"),
    "22.": ("2022", "2027", "✅ Supported"),
    "23.": ("2023", "2028", "✅ Supported"),
    "24.": ("2024", "2029", "✅ Current"),
}

EOS_LIFECYCLE: dict[str, tuple[str, str, str]] = {
    "4.20": ("2018", "2023", "🔴 EOL — out of support"),
    "4.21": ("2018", "2023", "🔴 EOL — out of support"),
    "4.22": ("2019", "2024", "🟠 EOL approaching / limited support"),
    "4.23": ("2019", "2024", "🟠 EOL approaching"),
    "4.24": ("2020", "2025", "🟠 EOL"),
    "4.25": ("2021", "2026", "🟡 EOL within 12 months"),
    "4.26": ("2021", "2026", "🟡 EOL within 12 months"),
    "4.27": ("2022", "2027", "✅ Supported"),
    "4.28": ("2022", "2027", "✅ Supported"),
    "4.29": ("2023", "2028", "✅ Supported"),
    "4.30": ("2023", "2028", "✅ Supported"),
    "4.31": ("2024", "2029", "✅ Current"),
    "4.32": ("2024", "2029", "✅ Current"),
}


# Pre-sort lifecycle prefixes by descending length once — the order is
# stable, so we can do this at import time and skip the per-call sort.
_LIFECYCLE_SORTED_JUNOS: tuple[tuple[str, tuple[str, str, str]], ...] = tuple(
    sorted(JUNOS_LIFECYCLE.items(), key=lambda x: -len(x[0]))
)
_LIFECYCLE_SORTED_EOS: tuple[tuple[str, tuple[str, str, str]], ...] = tuple(
    sorted(EOS_LIFECYCLE.items(), key=lambda x: -len(x[0]))
)
_LIFECYCLE_UNKNOWN: tuple[str, str, str] = ("", "", "❓ Unknown / not in lifecycle DB")
_LIFECYCLE_NO_VERSION: tuple[str, str, str] = ("", "", "❓ Unknown version")


def lifecycle_for(version: str, platform: str) -> tuple[str, str, str]:
    """Return (release_date, eol_date, status_emoji_text) for a software version."""
    if not version:
        return _LIFECYCLE_NO_VERSION
    v = version.strip()
    table = (_LIFECYCLE_SORTED_EOS if platform.lower() in ("eos", "arista")
             else _LIFECYCLE_SORTED_JUNOS)
    for prefix, info in table:
        if v.startswith(prefix):
            return info
    return _LIFECYCLE_UNKNOWN


def _is_risky(status: str) -> bool:
    """True if a lifecycle status indicates EOL or limited support."""
    return "🔴" in status or "🟠" in status


# ─────────────────────────────────────────────────────────────────────────────
# Site code → facility inference (rough hints from IATA-ish 3-letter codes)
# ─────────────────────────────────────────────────────────────────────────────

SITE_CODE_HINTS: dict[str, tuple[str, str]] = {
    # site_prefix : (city, country/region)
    "fra": ("Frankfurt", "Germany"),
    "lhr": ("London Heathrow", "United Kingdom"),
    "lon": ("London", "United Kingdom"),
    "ams": ("Amsterdam", "Netherlands"),
    "cdg": ("Paris CDG", "France"),
    "zrh": ("Zurich", "Switzerland"),
    "ach": ("Aachen", "Germany"),
    "hel": ("Helsinki", "Finland"),
    "sof": ("Sofia", "Bulgaria"),
    "syd": ("Sydney", "Australia"),
    "sin": ("Singapore", "Singapore"),
    "hkg": ("Hong Kong", "Hong Kong"),
    "kul": ("Kuala Lumpur", "Malaysia"),
    "nrt": ("Tokyo Narita", "Japan"),
    "hnd": ("Tokyo Haneda", "Japan"),
    "icn": ("Seoul Incheon", "South Korea"),
    "iad": ("Washington DC (Dulles)", "United States"),
    "phx": ("Phoenix", "United States"),
    "ord": ("Chicago", "United States"),
    "lax": ("Los Angeles", "United States"),
    "los": ("Los Angeles", "United States"),
    "dfw": ("Dallas / Fort Worth", "United States"),
    "yyz": ("Toronto", "Canada"),
    "gru": ("São Paulo", "Brazil"),
    "bom": ("Mumbai", "India"),
    "del": ("Delhi", "India"),
    "vie": ("Vienna", "Austria"),
    "auh": ("Abu Dhabi", "United Arab Emirates"),
    "dxb": ("Dubai", "United Arab Emirates"),
    "got": ("Gothenburg", "Sweden"),
    "osl": ("Oslo", "Norway"),
    "skg": ("Thessaloniki", "Greece"),
    "ist": ("Istanbul", "Turkey"),
    "tlv": ("Tel Aviv", "Israel"),
    "jnb": ("Johannesburg", "South Africa"),
    "akl": ("Auckland", "New Zealand"),
    "bll": ("Billund", "Denmark"),
    "lis": ("Lisbon", "Portugal"),
    "fco": ("Rome Fiumicino", "Italy"),
    "mmj": ("Matsumoto", "Japan"),
    "cgk": ("Jakarta", "Indonesia"),
    "tpe": ("Taipei", "Taiwan"),
    "bud": ("Budapest", "Hungary"),
    "waw": ("Warsaw", "Poland"),
    "prg": ("Prague", "Czech Republic"),
}


def facility_for(site_id: str) -> tuple[str, str]:
    code3 = site_id.lower()[:3]
    return SITE_CODE_HINTS.get(code3, ("Unknown city", "Unknown region"))


# ─────────────────────────────────────────────────────────────────────────────
# DeviceProfile (richer than v1)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(slots=True)
class DeviceProfile:
    hostname: str
    platform: str
    role: str
    function_code: str
    config_size_bytes: int

    model_hint: str = ""
    software_version: str = ""
    serial_hint: str = ""

    interface_ips: list[str] = field(default_factory=list)
    loopback_ips: list[str] = field(default_factory=list)
    interfaces_described: int = 0

    vlans: dict = field(default_factory=dict)  # vlan_id → VlanInfo
    wan_ips: list = field(default_factory=list)
    advpn: list = field(default_factory=list)

    local_asn: str = ""
    bgp_neighbors: list[dict] = field(default_factory=list)
    ospf_areas: list[str] = field(default_factory=list)
    isis_enabled: bool = False
    static_routes_count: int = 0

    evpn_enabled: bool = False
    vxlan_vni_count: int = 0

    chassis_cluster: bool = False
    security_zones: list[str] = field(default_factory=list)
    security_policies_count: int = 0

    snmp_v3: bool = False
    snmp_v2c_present: bool = False
    ntp_servers: list[str] = field(default_factory=list)
    syslog_hosts: list[str] = field(default_factory=list)
    radius_servers: list[str] = field(default_factory=list)
    tacacs_servers: list[str] = field(default_factory=list)
    dns_servers: list[str] = field(default_factory=list)

    isp_descriptions: list[str] = field(default_factory=list)

    role_description: str = ""  # "Primary Edge Router" etc.
    # Cached lifecycle tuple — set once in extract_profile so we don't re-query
    # the lifecycle table in every section builder.
    lifecycle: tuple[str, str, str] = ("", "", "")


# Roles considered ISP-gateways (firewalls or WAN routers) — used to filter
# which devices to scan for ISP profiles. Kept in sync with site_optimize.py.
_GATEWAY_ROLES: frozenset[str] = frozenset({"firewall", "router", "gateway"})
_GATEWAY_HOSTNAME_TOKENS: frozenset[str] = frozenset({"fw", "rt", "gw"})
_HOSTNAME_SPLIT_RE = re.compile(r"[-_.]")


def _is_gateway_device(d: dict) -> bool:
    """Whether a device should be scanned for ISP profiles.

    Reuses _detect_role() when no explicit role is set, and splits hostnames on
    `[-_.]` boundaries to avoid substring false positives (e.g. `partner-01`
    no longer matches `rt` and `firmware-host` no longer matches `fw`).
    """
    hostname = str(d.get("hostname", "")).lower()
    role = str(d.get("role") or _detect_role(hostname)[0]).lower()
    if role in _GATEWAY_ROLES:
        return True
    parts = _HOSTNAME_SPLIT_RE.split(hostname)
    return any(part in _GATEWAY_HOSTNAME_TOKENS for part in parts)


# ─────────────────────────────────────────────────────────────────────────────
# Markdown cell helpers — keep `|` / backticks / newlines from breaking tables
# ─────────────────────────────────────────────────────────────────────────────

def md_cell(value: object) -> str:
    """Escape a value for safe insertion into a markdown table cell."""
    if value is None:
        return ""
    s = str(value)
    return (s.replace("\\", "\\\\")
             .replace("|", "\\|")
             .replace("\r", "")
             .replace("\n", "<br>"))


def md_code(value: object) -> str:
    """Safely format inline markdown code — escapes embedded backticks."""
    if value is None:
        return "``"
    escaped = str(value).replace("`", "\\`")
    return f"`{escaped}`"


def _extend_unique(target: list, values: list) -> None:
    """In-place extend `target` with items from `values`, skipping duplicates."""
    seen = set(target)
    for v in values:
        if v in seen:
            continue
        target.append(v)
        seen.add(v)


# Pre-compiled regexes used in extract_profile (hot path — one device/call)
_RE_VERSION_JUNOS = re.compile(r"^\s*version\s+([\w.\-]+);?", re.M)
_RE_VERSION_EOS = re.compile(r"EOS-(\d[\d.M\-]+)", re.I)
_RE_VERSION_FRR = re.compile(r"frr\s+version\s+([\w.]+)", re.I)
_RE_MODEL = re.compile(r"\((QFX\d+\w*|EX\d+\w*|MX\d+\w*|SRX\d+\w*|DCS-\S+|7050\S+|7280\S+)", re.I)
_RE_LOOPBACK_JUNOS = re.compile(
    r"lo0\s+\{[^}]*?address\s+(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})", re.S,
)
_RE_LOOPBACK_EOS = re.compile(
    r"interface\s+(?:Loopback|lo)\d+\s*\n\s*ip\s+address\s+(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})",
    re.I,
)
_RE_LOCAL_ASN = re.compile(r"(?:autonomous-system|router\s+bgp|local-as)\s+(\d+)", re.I)
_RE_BGP_JUNOS = re.compile(r"neighbor\s+(\S+)\s*\{[^}]*?peer-as\s+(\d+)", re.S)
_RE_BGP_EOS = re.compile(r"neighbor\s+(\S+)\s+remote-as\s+(\d+)")
_RE_OSPF_AREA = re.compile(r"area\s+(\d+(?:\.\d+\.\d+\.\d+)?)", re.I)
# Anchor IS-IS detection to a config statement (avoid false positives in
# interface descriptions or comments that mention "isis").
_RE_ISIS = re.compile(
    r"^\s*(?:set\s+protocols\s+isis\b|protocols\s+\{\s*isis\b|router\s+isis\b)",
    re.I | re.M,
)
_RE_STATIC_ROUTE = re.compile(r"\bip\s+route\b|\broute\s+0\.0\.0\.0", re.I)
_RE_EVPN = re.compile(r"\bevpn\b", re.I)
_RE_VXLAN_VNI = re.compile(r"\bvni\s+\d+\b", re.I)
_RE_SEC_ZONE = re.compile(r"security-zone\s+(\S+)")
_RE_SEC_POLICY = re.compile(r"\bpolicy\s+\S+\s*\{")
_RE_SNMP_V3 = re.compile(r"snmp\s+v3|usm\s+user|snmp-server\s+user", re.I)
_RE_SNMP_V2C = re.compile(r"snmp-server\s+community", re.I)
_RE_NTP = re.compile(r"(?:ntp\s+server|set\s+system\s+ntp\s+server)\s+(\S+)")
_RE_SYSLOG = re.compile(r"(?:syslog\s+host|logging\s+host)\s+(\S+)")
_RE_RADIUS = re.compile(r"radius-server\s+(?:host\s+)?(\S+)")
_RE_TACACS = re.compile(r"tacacs-server\s+(?:host\s+)?(\S+)")
_RE_DNS = re.compile(r"(?:name-server|ip\s+name-server)\s+(\S+)")
_RE_ENDPOINT_OK = re.compile(r"^[A-Za-z0-9._:-]+$")


_ISP_KEYWORDS = (
    "isp", "telia", "arelion", "lumen", "cogent", "ntt", "gtt", "leaseweb",
    "level3", "centurylink", "tata", "verizon", "att", "deutsche telekom",
    "vodafone", "optus", "telstra", "tpg", "swisscom", "colt", "comcast",
    "orange", "bt", "kpn", "akamai", "google", "amazon", "microsoft",
)

# Rendering constants (hoisted out of function bodies)
_ROLE_ORDER: dict[str, int] = {
    "firewall": 0, "router": 1, "switch": 2, "storage": 3, "edr": 4, "unknown": 9,
}
_ROLE_PLURALS: dict[str, str] = {
    "firewall": "Firewalls", "router": "Routers", "switch": "Switches",
    "storage": "Storage devices", "edr": "EDR clusters", "unknown": "Other devices",
}
_VLAN_CATEGORY_ORDER: tuple[str, ...] = (
    "Management", "Production/Access", "Storage", "DR/Backup",
    "IPMI/BMC", "PXE/Boot", "ADVPN", "WAN/External",
    "Network/Transit", "Infrastructure", "Other",
)
_REC_PRIORITY_TITLES: tuple[tuple[str, str], ...] = (
    ("recs_p1", "P1 — CRITICAL (30-day SLA)"),
    ("recs_p2", "P2 — HIGH (60-day SLA)"),
    ("recs_p3", "P3 — MEDIUM (90-day SLA)"),
    ("recs_p4", "P4 — LOW (120-day SLA)"),
)
_SEVERITY_RANK: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3}


_BAD_ENDPOINT_CHARS = frozenset('<>"*')
_ENDPOINT_TRAILING = " ;,\t\r\n"


def _real_endpoints(matches: list[str], *, limit: int = 8) -> list[str]:
    """Filter raw regex captures into clean service endpoints.

    Strips Junos's trailing `;` (e.g. `10.1.1.1;`), drops template tokens
    containing `<`/`>`/`"`/`*`, and dedupes while preserving first-seen order.
    """
    out: list[str] = []
    seen: set[str] = set()
    for raw in matches:
        value = raw.strip().strip(_ENDPOINT_TRAILING)
        if not value:
            continue
        if any(c in _BAD_ENDPOINT_CHARS for c in value):
            continue
        if not _RE_ENDPOINT_OK.fullmatch(value):
            continue
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
        if len(out) >= limit:
            break
    return out


def extract_profile(hostname: str, platform: str, config_text: str) -> DeviceProfile:
    plat = (platform or "").lower()
    role, _ = _detect_role(hostname)
    p = DeviceProfile(
        hostname=hostname, platform=plat, role=role,
        function_code=hostname.split("-")[1] if "-" in hostname else "",
        config_size_bytes=len(config_text),
    )

    # Software version — try each pattern in order
    for rx in (_RE_VERSION_JUNOS, _RE_VERSION_EOS, _RE_VERSION_FRR):
        m = rx.search(config_text)
        if m:
            p.software_version = m.group(1)
            break

    # Model hint
    m = _RE_MODEL.search(config_text)
    if m:
        p.model_hint = m.group(1)

    # Topology-infer facts
    facts = topology_infer.extract_facts(hostname, plat, config_text)
    p.interface_ips = facts.interface_ips
    p.chassis_cluster = facts.has_chassis_cluster

    # VLANs / WAN IPs / ADVPN
    p.vlans = site_diagram.extract_vlans(config_text, plat)
    p.wan_ips = site_diagram.extract_wan_ips(config_text, plat)
    p.advpn = site_diagram.extract_advpn_tunnels(config_text, plat)

    # Loopback IPs (per-platform regex)
    if plat.startswith("jun"):
        p.loopback_ips = _RE_LOOPBACK_JUNOS.findall(config_text)
    elif plat in ("eos", "frr", "ios"):
        p.loopback_ips = _RE_LOOPBACK_EOS.findall(config_text)

    p.interfaces_described = len(facts.descriptions)
    p.isp_descriptions = [d for d in facts.descriptions
                          if any(kw in d.lower() for kw in _ISP_KEYWORDS)]

    # ASN
    m = _RE_LOCAL_ASN.search(config_text)
    if m:
        p.local_asn = m.group(1)

    # BGP neighbors — Junos hierarchical first, then EOS/IOS flat
    seen_peers: set[str] = set()
    for m in _RE_BGP_JUNOS.finditer(config_text):
        ip = m.group(1)
        if ip in seen_peers:
            continue
        seen_peers.add(ip)
        p.bgp_neighbors.append({"ip": ip, "remote_as": m.group(2)})
    for m in _RE_BGP_EOS.finditer(config_text):
        ip = m.group(1)
        if ip in seen_peers:
            continue
        seen_peers.add(ip)
        p.bgp_neighbors.append({"ip": ip, "remote_as": m.group(2)})

    # OSPF / IS-IS / static
    for m in _RE_OSPF_AREA.finditer(config_text):
        area = m.group(1)
        if area not in p.ospf_areas:
            p.ospf_areas.append(area)
    p.isis_enabled = bool(_RE_ISIS.search(config_text))
    p.static_routes_count = len(_RE_STATIC_ROUTE.findall(config_text))

    # EVPN / VXLAN
    p.evpn_enabled = bool(_RE_EVPN.search(config_text))
    p.vxlan_vni_count = len(_RE_VXLAN_VNI.findall(config_text))

    # Security
    p.security_zones = list(dict.fromkeys(_RE_SEC_ZONE.findall(config_text)))
    p.security_policies_count = len(_RE_SEC_POLICY.findall(config_text))

    # SNMP
    p.snmp_v3 = bool(_RE_SNMP_V3.search(config_text))
    p.snmp_v2c_present = bool(_RE_SNMP_V2C.search(config_text))

    # Service endpoints
    p.ntp_servers = _real_endpoints(_RE_NTP.findall(config_text))
    p.syslog_hosts = _real_endpoints(_RE_SYSLOG.findall(config_text))
    p.radius_servers = _real_endpoints(_RE_RADIUS.findall(config_text))
    p.tacacs_servers = _real_endpoints(_RE_TACACS.findall(config_text))
    p.dns_servers = _real_endpoints(_RE_DNS.findall(config_text))

    # Cache lifecycle so section builders don't re-query the table
    p.lifecycle = lifecycle_for(p.software_version, p.platform)

    return p


def _detect_role(hostname: str) -> tuple[str, str]:
    parts = hostname.lower().split("-")
    if len(parts) < 2:
        return "unknown", ""
    func = parts[1]
    role = {"fw": "firewall", "rt": "router", "sw": "switch",
            "edr": "edr", "acs": "storage"}.get(func, "unknown")
    return role, func


def assign_role_descriptions(profiles: list[DeviceProfile]) -> None:
    """Add 'Primary/Secondary/Standby' classification by role + ordering."""
    by_role: dict[str, list[DeviceProfile]] = defaultdict(list)
    for p in profiles:
        by_role[p.role].append(p)
    for role, ps in by_role.items():
        # Sort by function_code + number suffix to get a consistent ordering
        ps.sort(key=lambda x: x.hostname)
        if role == "firewall":
            for i, p in enumerate(ps):
                if i == 0:
                    p.role_description = "Primary Firewall"
                elif i == 1:
                    p.role_description = "Secondary Firewall"
                else:
                    p.role_description = f"Firewall #{i+1}"
                if p.chassis_cluster:
                    p.role_description += " (HA chassis-cluster)"
        elif role == "router":
            for i, p in enumerate(ps):
                p.role_description = ("Primary Edge Router" if i == 0
                                       else "Secondary Edge Router" if i == 1
                                       else f"Standby Router #{i+1}")
        elif role == "switch":
            for i, p in enumerate(ps):
                # Heuristic: if has BGP → ISP-edge / core spine, EVPN → fabric leaf
                if p.bgp_neighbors and p.isp_descriptions:
                    p.role_description = "ISP-edge / Core switch"
                elif p.evpn_enabled or p.vxlan_vni_count > 0:
                    p.role_description = "EVPN-VXLAN fabric leaf"
                elif p.bgp_neighbors:
                    p.role_description = "Core switch"
                else:
                    p.role_description = "Access / distribution switch"
        elif role == "storage":
            for p in ps:
                p.role_description = "Storage / ACS device"
        elif role == "edr":
            for p in ps:
                p.role_description = "EDR / telemetry cluster"
        else:
            for p in ps:
                p.role_description = "Unclassified network device"


# ─────────────────────────────────────────────────────────────────────────────
# Markdown rendering (the big one)
# ─────────────────────────────────────────────────────────────────────────────

def render_site_doc(
    site_id: str,
    devices: list[dict],
    *,
    include_diagram: bool = True,
    include_compliance: bool = True,
    use_llm_summary: bool = True,
) -> str:
    profiles = [extract_profile(d["hostname"], d.get("platform", "junos"),
                                  d.get("config_text", "")) for d in devices]
    assign_role_descriptions(profiles)

    # Aggregate site-wide data — single pass for WAN dedup
    all_vlans = site_diagram.merge_vlans([p.vlans for p in profiles])
    all_wan_ips: list[site_diagram.WanIp] = []
    seen_wan: set[str] = set()
    for p in profiles:
        for w in p.wan_ips:
            if w.ip in seen_wan:
                continue
            seen_wan.add(w.ip)
            all_wan_ips.append(w)

    # ISP profiles aggregated across gateway devices (role-based, not substring)
    all_isps: dict[str, site_diagram.IspProfile] = {}
    for d in devices:
        if not _is_gateway_device(d):
            continue
        for prof in site_diagram.extract_isp_profiles(
            d.get("config_text", ""), d.get("platform", "junos"), all_wan_ips,
        ):
            existing = all_isps.get(prof.name)
            if existing is None:
                all_isps[prof.name] = prof
                continue
            # Dedupe — same prof may be re-discovered on a peer config
            _extend_unique(existing.public_ips, prof.public_ips)
            _extend_unique(existing.interfaces, prof.interfaces)
            if prof.status == "shutdown":
                existing.status = "shutdown"
            if prof.asn and not existing.asn:
                existing.asn = prof.asn
    # Materialize once so section builders don't re-allocate
    isp_list = list(all_isps.values())

    site = site_id.upper()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    city, country = facility_for(site)
    out: list[str] = []

    # ─── 0. Header ───
    out.append(f"# {site} Datacenter — Comprehensive Site Analysis")
    out.append("")
    out.append(f"**Analysis Date:** {now}  ")
    out.append(f"**Site Code:** {site}  ")
    out.append(f"**Estimated Location:** {city}, {country}  ")
    out.append(f"**Devices in Bundle:** {len(profiles)}  ")
    out.append(f"**Total Config Size (sanitized):** {sum(p.config_size_bytes for p in profiles)//1024} KB  ")
    asns_seen = sorted({p.local_asn for p in profiles if p.local_asn})
    if asns_seen:
        out.append(f"**Local ASN(s):** {', '.join(asns_seen)}  ")
    out.append("")
    out.append("**Data Sources:**")
    out.append("- Sanitized device configurations (all secrets + PII redacted)")
    out.append("- AI Log Analyzer pattern-matching engine + LLM enrichment")
    out.append("- Built-in compliance rules + multi-signal topology inference")
    out.append("")
    out.append("---")
    out.append("")

    # ─── 1. Executive Summary ───
    out.append("## 1. Executive Summary")
    out.append("")
    out.append(_executive_summary(site, profiles, isp_list,
                                    all_vlans, use_llm=use_llm_summary))
    out.append("")

    # ─── 2. Infrastructure Composition ───
    out.append("## 2. Infrastructure Composition")
    out.append("")
    out.append(_composition_table(profiles))
    out.append("")

    # ─── 3. Facility Information ───
    out.append("## 3. Facility Information")
    out.append("")
    out.append(f"- **Site Code:** {site}")
    out.append(f"- **Inferred City:** {city}")
    out.append(f"- **Inferred Country/Region:** {country}")
    out.append(f"- **Network Devices in this bundle:** {len(profiles)}")
    funcs = Counter(p.function_code for p in profiles)
    out.append(f"- **Device functions:** "
               + ", ".join(f"{n}× `{f}`" for f, n in funcs.most_common()))
    out.append("")
    out.append("> _Facility metadata (rack count, exact address, contact) is not derivable from sanitized configs — pull from NetBox or DCIM for production reports._")
    out.append("")

    # ─── 4. Site Architecture ───
    out.append("## 4. Site Architecture")
    out.append("")
    out.extend(_architecture_section(profiles, all_isps, all_vlans))
    out.append("")

    # ─── 5. Per-Device Details ───
    out.append("## 5. Device Details")
    out.append("")
    out.append("Each subsection: role classification, key facts, BGP peers, ISP interfaces, software lifecycle.")
    out.append("")
    grouped: dict[str, list[DeviceProfile]] = defaultdict(list)
    for p in profiles:
        grouped[p.role].append(p)
    for role in sorted(grouped.keys(), key=lambda r: _ROLE_ORDER.get(r, 9)):
        out.append(f"### {_ROLE_PLURALS.get(role, role.capitalize() + 's')} ({len(grouped[role])})")
        out.append("")
        for p in sorted(grouped[role], key=lambda x: x.hostname):
            out.extend(_device_section(p))

    # ─── 6. VLAN and Subnet Documentation ───
    out.append("## 6. VLAN and Subnet Documentation")
    out.append("")
    out.extend(_vlan_section(all_vlans))
    out.append("")

    # ─── 7. WAN / Public IP Inventory + ISPs ───
    out.append("## 7. WAN / Public IP Inventory + ISP Profiles")
    out.append("")
    out.extend(_wan_isp_section(all_wan_ips, isp_list))
    out.append("")

    # ─── 8. BGP & Routing Analysis ───
    out.append("## 8. BGP & Routing Analysis")
    out.append("")
    out.extend(_bgp_routing_section(profiles, isp_list))
    out.append("")

    # ─── 9. ADVPN / IPsec Tunnels ───
    advpn_count = sum(len(p.advpn) for p in profiles)
    if advpn_count:
        out.append("## 9. ADVPN / IPsec Tunnels")
        out.append("")
        out.extend(_advpn_section(profiles))
        out.append("")

    # ─── 10. Security Configuration ───
    out.append("## 10. Security Configuration")
    out.append("")
    out.extend(_security_section(profiles))
    out.append("")

    # ─── 11. Network Services ───
    out.append("## 11. Network Services (DNS, NTP, SNMP, Syslog, RADIUS, TACACS)")
    out.append("")
    out.extend(_services_section(profiles))
    out.append("")

    # ─── 12. Software Versions and Lifecycle ───
    out.append("## 12. Software Versions and Lifecycle")
    out.append("")
    out.extend(_software_lifecycle_section(profiles))
    out.append("")

    # ─── 13. Compliance ───
    if include_compliance:
        out.append("## 13. Compliance Findings")
        out.append("")
        out.append(_compliance_section(devices))
        out.append("")

    # ─── 14. Topology Diagram ───
    if include_diagram:
        out.append("## 14. Topology Diagrams")
        out.append("")
        # Mermaid (inline)
        topo = topology.build_topology(site, devices)
        out.append("### 14.1 Mermaid Topology (inferred via 5 signal types)")
        out.append("")
        out.append("```mermaid")
        out.append(topology.to_mermaid(topo))
        out.append("```")
        out.append("")
        out.append(f"_Inferred edges: {len(topo.edges)} (across {len(topo.nodes)} devices)._")
        out.append("")
        # Graphviz DOT (architecture + details + flows)
        out.append("### 14.2 Architecture + Traffic Flow Diagram (Graphviz DOT)")
        out.append("")
        out.append("Render with: `dot -Tpng diagram.dot -o diagram.png`")
        out.append("")
        out.append("```dot")
        out.append(site_diagram.build_site_dot(site, devices))
        out.append("```")
        out.append("")

    # ─── 15. Recommendations ───
    out.append("## 15. Recommendations")
    out.append("")
    out.extend(_recommendations_section(profiles, isp_list))
    out.append("")

    # ─── 16. Technical Summary ───
    out.append("## 16. Technical Summary")
    out.append("")
    out.extend(_technical_summary(site, profiles, all_vlans, isp_list,
                                    all_wan_ips))
    out.append("")

    # ─── 17. Appendices ───
    out.append("## 17. Appendices")
    out.append("")
    out.extend(_appendices(profiles))

    out.append(f"\n_Report generated by AI Log Analyzer at {now}._")

    return "\n".join(out)


# ─────────────────────────────────────────────────────────────────────────────
# Section builders
# ─────────────────────────────────────────────────────────────────────────────

def _executive_summary(site: str, profiles: list[DeviceProfile],
                        isps: list, vlans: dict, *, use_llm: bool) -> str:
    by_role = Counter(p.role for p in profiles)
    versions = Counter(p.software_version for p in profiles if p.software_version)
    has_evpn = any(p.evpn_enabled for p in profiles)
    has_vxlan = any(p.vxlan_vni_count > 0 for p in profiles)
    has_ha = any(p.chassis_cluster for p in profiles)
    total_bgp = sum(len(p.bgp_neighbors) for p in profiles)
    asns = sorted({p.local_asn for p in profiles if p.local_asn})

    # Software risk (uses cached p.lifecycle — set once in extract_profile)
    risky: list[tuple[str, str]] = []
    for p in profiles:
        if not p.software_version:
            continue
        _, _, status = p.lifecycle
        if _is_risky(status):
            risky.append((p.hostname, f"{p.software_version} — {status}"))

    if use_llm and llm.get_state().get("enabled"):
        sys = (
            "You write the EXECUTIVE SUMMARY of a comprehensive datacenter site analysis. "
            "Output markdown, 5-7 paragraphs with these emoji-prefixed sections: "
            "🏢 Site Status (active/standby), 🎯 Priority Classification (Tier 1/2/3), "
            "📊 Infrastructure Overview, 🔴 CRITICAL FINDINGS (bullet list of risks), "
            "✅ Positive Highlights, 🌐 Network Architecture, 📈 IP Space. "
            "Be specific (device counts, ASN, ISPs, software versions). No preamble."
        )
        usr = (
            f"SITE: {site}\n"
            f"DEVICES: {len(profiles)} ({dict(by_role)})\n"
            f"ASN(s): {asns or 'none'}\n"
            f"Software versions: {dict(versions.most_common(5))}\n"
            f"EOL/at-risk devices: {risky[:5]}\n"
            f"EVPN: {has_evpn}; VXLAN: {has_vxlan}; HA chassis-cluster: {has_ha}\n"
            f"BGP neighbors: {total_bgp}\n"
            f"ISPs: {[(i.name, i.status, i.asn) for i in isps]}\n"
            f"VLAN count: {len(vlans)} ({Counter(v.category for v in vlans.values())})\n\n"
            "Write the executive summary now."
        )
        try:
            text = llm.query(sys, usr, max_tokens=1800)
        except Exception:
            text = ""  # Don't let report generation fail on a flaky LLM
        if text:
            return text

    # Deterministic fallback (still rich)
    lines: list[str] = []
    lines.append(f"🏢 **Site Status:** ACTIVE — {len(profiles)} devices ({dict(by_role)})")
    lines.append("")
    lines.append(f"🎯 **Priority Classification:** "
                 + ("**Tier 1** (full firewall + multiple switches)"
                    if by_role.get("firewall", 0) >= 1 and by_role.get("switch", 0) >= 4
                    else "**Tier 2** (limited size)"))
    lines.append("")
    lines.append(f"📊 **Infrastructure Overview:**")
    lines.append(f"- {by_role.get('firewall', 0)} firewall(s), "
                 f"{by_role.get('router', 0)} router(s), "
                 f"{by_role.get('switch', 0)} switch(es)")
    lines.append(f"- {sum(p.config_size_bytes for p in profiles)//1024} KB total sanitized config")
    lines.append(f"- {len(vlans)} distinct VLANs documented")
    lines.append(f"- {total_bgp} BGP neighbor configurations")
    lines.append("")
    if risky:
        lines.append("🔴 **CRITICAL FINDINGS:**")
        for host, ver in risky[:6]:
            lines.append(f"- `{host}`: {ver}")
        lines.append("")
    if len(versions) > 1:
        lines.append(f"⚠️ **Version drift** — {len(versions)} distinct software versions detected. "
                     "Consider standardizing.")
        lines.append("")
    lines.append("✅ **Positive Highlights:**")
    if has_ha:
        lines.append("- HA chassis-cluster present on at least one firewall")
    if has_evpn or has_vxlan:
        lines.append(f"- Modern overlay fabric: EVPN={has_evpn}, VXLAN={has_vxlan}")
    if total_bgp >= 4:
        lines.append("- Healthy BGP footprint (4+ neighbors)")
    if not risky:
        lines.append("- All software versions in supported lifecycle window")
    lines.append("")
    if asns:
        lines.append(f"🌐 **Network Architecture:** ASN {', '.join(asns)} · "
                     f"{len(isps)} ISP(s) detected: "
                     + ", ".join(f"{i.name} ({i.status})" for i in isps))
    return "\n".join(lines)


def _composition_table(profiles: list[DeviceProfile]) -> str:
    by_role: dict[str, list[DeviceProfile]] = defaultdict(list)
    for p in profiles:
        by_role[p.role].append(p)
    lines = ["| Role | Count | Devices | Models | Versions |",
             "|------|-------|---------|--------|----------|"]
    for role in ("firewall", "router", "switch", "storage", "edr", "unknown"):
        ps = by_role.get(role, [])
        if not ps:
            continue
        models = ", ".join(sorted({p.model_hint for p in ps if p.model_hint}) or {"-"})
        versions = ", ".join(sorted({p.software_version for p in ps if p.software_version}) or {"-"})
        lines.append(f"| {role} | {len(ps)} | {', '.join(p.hostname for p in ps)} | {models} | {versions} |")
    return "\n".join(lines)


def _architecture_section(profiles: list[DeviceProfile], isps: dict, vlans: dict) -> list[str]:
    out: list[str] = []
    out.append("### 4.1 Role and Function")
    out.append("")
    out.append("This site provides:")
    if any(p.role == "firewall" for p in profiles):
        out.append("- **Perimeter security** via firewall(s)")
    if any(p.bgp_neighbors for p in profiles):
        out.append("- **External connectivity** via BGP")
    if any(p.evpn_enabled or p.vxlan_vni_count for p in profiles):
        out.append("- **Overlay fabric** (EVPN-VXLAN)")
    if any(p.advpn for p in profiles):
        out.append("- **Inter-site VPN** (ADVPN tunnels)")
    out.append("")
    asns = sorted({p.local_asn for p in profiles if p.local_asn})
    if asns:
        out.append("### 4.2 Autonomous System Configuration")
        out.append("")
        for a in asns:
            holders = [p.hostname for p in profiles if p.local_asn == a]
            out.append(f"- **AS{a}** — declared on: {', '.join(holders)}")
        out.append("")
    out.append("### 4.3 Network Device Types")
    out.append("")
    by_role = Counter(p.role for p in profiles)
    for role, n in by_role.most_common():
        out.append(f"- **{role.capitalize()}:** {n}")
    return out


def _device_section(p: DeviceProfile) -> list[str]:
    out = [f"#### `{p.hostname}` — {p.role_description or p.role.capitalize()}"]
    out.append("")
    # Quick facts table
    out.append("| Attribute | Value |")
    out.append("|-----------|-------|")
    out.append(f"| Platform | {p.platform} |")
    if p.model_hint:       out.append(f"| Model (hint) | {p.model_hint} |")
    if p.software_version:
        rel, eol, status = p.lifecycle
        out.append(f"| Software | `{p.software_version}` · {status} |")
        if rel and eol:
            out.append(f"| Lifecycle | Released {rel} · EOL ~{eol} |")
    if p.local_asn:        out.append(f"| Local ASN | {p.local_asn} |")
    if p.loopback_ips:     out.append(f"| Loopback(s) | `{', '.join(p.loopback_ips)}` |")
    out.append(f"| Interfaces with IPs | {len(p.interface_ips)} |")
    out.append(f"| Interface descriptions | {p.interfaces_described} |")
    if p.vlans:            out.append(f"| VLANs configured | {len(p.vlans)} |")
    if p.chassis_cluster:  out.append("| Chassis-cluster | ✅ HA |")
    if p.evpn_enabled:     out.append("| EVPN | ✅ enabled |")
    if p.vxlan_vni_count:  out.append(f"| VXLAN VNIs | {p.vxlan_vni_count} |")
    if p.ospf_areas:       out.append(f"| OSPF areas | `{', '.join(p.ospf_areas)}` |")
    if p.isis_enabled:     out.append("| IS-IS | ✅ enabled |")
    if p.security_zones:
        out.append(f"| Security zones | {len(p.security_zones)} ({', '.join(p.security_zones[:5])}{'…' if len(p.security_zones)>5 else ''}) |")
    if p.security_policies_count: out.append(f"| Security policies | {p.security_policies_count} |")
    out.append(f"| Config size (sanitized) | {p.config_size_bytes//1024} KB |")
    out.append("")
    if p.bgp_neighbors:
        out.append(f"**BGP neighbors ({len(p.bgp_neighbors)}):**")
        out.append("")
        out.append("| Peer IP | Remote AS |")
        out.append("|---------|-----------|")
        for n in p.bgp_neighbors[:30]:
            out.append(f"| `{n['ip']}` | {n['remote_as']} |")
        if len(p.bgp_neighbors) > 30:
            out.append(f"| _…+{len(p.bgp_neighbors)-30} more_ | |")
        out.append("")
    if p.isp_descriptions:
        out.append("**ISP / external interfaces:**")
        out.append("")
        for d in p.isp_descriptions[:6]:
            out.append(f"- {md_code(d[:120])}")
        out.append("")
    if p.wan_ips:
        out.append("**Public WAN IPs:**")
        out.append("")
        for w in p.wan_ips[:6]:
            iface = f" on {md_code(w.interface)}" if w.interface else ""
            desc = f" — {md_cell(w.description)}" if w.description else ""
            out.append(f"- {md_code(w.ip)}{iface}{desc}")
        out.append("")
    return out


def _vlan_section(vlans: dict) -> list[str]:
    out: list[str] = []
    if not vlans:
        return ["_No VLANs detected._"]
    out.append(f"**Total distinct VLANs across site:** {len(vlans)}")
    out.append("")
    by_cat: dict[str, list] = defaultdict(list)
    for v in vlans.values():
        by_cat[v.category].append(v)
    for cat in _VLAN_CATEGORY_ORDER:
        if cat not in by_cat:
            continue
        vlist = sorted(by_cat[cat], key=lambda v: v.vlan_id)
        emoji = vlist[0].emoji if vlist else "⚫"
        out.append(f"### {emoji} {cat} ({len(vlist)} VLANs)")
        out.append("")
        out.append("| VLAN ID | Name | Subnets |")
        out.append("|---------|------|---------|")
        for v in vlist:
            subs = ", ".join(md_code(s) for s in v.subnets) or "—"
            out.append(f"| {v.vlan_id} | {md_code(v.name or '-')} | {subs} |")
        out.append("")
    return out


def _wan_isp_section(wan_ips: list, isps: list) -> list[str]:
    out: list[str] = []
    if wan_ips:
        out.append(f"### 7.1 WAN / Public IP Inventory ({len(wan_ips)} IPs)")
        out.append("")
        out.append("| Public IP | Interface | Description |")
        out.append("|-----------|-----------|-------------|")
        for w in wan_ips[:30]:
            out.append(f"| {md_code(w.ip)} | {md_code(w.interface or '-')} | "
                        f"{md_cell(w.description or '-')} |")
        if len(wan_ips) > 30:
            out.append(f"| _… +{len(wan_ips)-30} more_ | | |")
        out.append("")
    if isps:
        out.append(f"### 7.2 ISP Profiles ({len(isps)} detected)")
        out.append("")
        for isp in isps:
            status_emoji = ("✅ ACTIVE" if isp.status == "active"
                            else "⚠️ SHUTDOWN" if isp.status == "shutdown"
                            else "❓ UNKNOWN")
            out.append(f"#### {md_cell(isp.name)} {status_emoji}")
            out.append("")
            out.append(f"- **Status:** {isp.status}")
            if isp.asn:
                out.append(f"- **Detected ASN:** AS{isp.asn}")
            if isp.interfaces:
                out.append("- **Interfaces:** "
                            + ", ".join(md_code(i) for i in isp.interfaces))
            if isp.public_ips:
                out.append("- **Public IPs:** "
                            + ", ".join(md_code(ip) for ip in isp.public_ips[:6]))
            out.append("")
    else:
        out.append("_No ISP descriptors detected from sanitized configs._")
        out.append("")
    return out


def _bgp_routing_section(profiles: list[DeviceProfile], isps: list) -> list[str]:
    total = sum(len(p.bgp_neighbors) for p in profiles)
    out: list[str] = []
    if not total:
        return ["_No BGP neighbors detected across the site._"]
    out.append(f"### 8.1 BGP Footprint")
    out.append("")
    out.append(f"- **Total BGP neighbor configurations:** {total}")
    out.append(f"- **Devices with BGP:** {sum(1 for p in profiles if p.bgp_neighbors)}")
    out.append("")
    # iBGP vs eBGP
    asns_local = {p.local_asn for p in profiles if p.local_asn}
    ibgp = ebgp = 0
    for p in profiles:
        for n in p.bgp_neighbors:
            if n["remote_as"] in asns_local:
                ibgp += 1
            else:
                ebgp += 1
    out.append(f"- **iBGP sessions** (same AS): {ibgp}")
    out.append(f"- **eBGP sessions** (different AS): {ebgp}")
    out.append("")
    # Remote-AS distribution
    as_count: Counter[str] = Counter()
    for p in profiles:
        for n in p.bgp_neighbors:
            as_count[n["remote_as"]] += 1
    out.append("### 8.2 Remote AS Distribution")
    out.append("")
    out.append("| Remote AS | Neighbor count | Likely identity |")
    out.append("|-----------|----------------|-----------------|")
    isp_asns = {i.asn: i.name for i in isps if i.asn}
    for asn, cnt in as_count.most_common(15):
        ident = isp_asns.get(asn, "internal/iBGP" if asn in asns_local else "external (unknown)")
        out.append(f"| {asn} | {cnt} | {ident} |")
    out.append("")
    # OSPF / ISIS / Static
    out.append("### 8.3 IGP and Static Routing")
    out.append("")
    ospf_devs = [p.hostname for p in profiles if p.ospf_areas]
    isis_devs = [p.hostname for p in profiles if p.isis_enabled]
    static_total = sum(p.static_routes_count for p in profiles)
    out.append(f"- **OSPF** enabled on: {', '.join(ospf_devs) or 'none'}")
    if ospf_devs:
        all_areas = sorted({a for p in profiles for a in p.ospf_areas})
        out.append(f"- **OSPF areas seen:** {', '.join(all_areas)}")
    out.append(f"- **IS-IS** enabled on: {', '.join(isis_devs) or 'none'}")
    out.append(f"- **Static route entries (site-wide):** {static_total}")
    return out


def _advpn_section(profiles: list[DeviceProfile]) -> list[str]:
    out: list[str] = []
    for p in profiles:
        if not p.advpn:
            continue
        out.append(f"### `{p.hostname}` ADVPN tunnels ({len(p.advpn)})")
        out.append("")
        out.append("| Interface | Address | Description |")
        out.append("|-----------|---------|-------------|")
        for t in p.advpn[:10]:
            out.append(f"| {md_code(t.interface)} | {md_code(t.address or '-')} | "
                        f"{md_cell(t.description or '-')} |")
        out.append("")
    return out


def _security_section(profiles: list[DeviceProfile]) -> list[str]:
    fws = [p for p in profiles if p.role == "firewall" or p.security_zones]
    if not fws:
        return ["_No firewall-class devices in this bundle._"]
    out: list[str] = []
    for p in fws:
        out.append(f"### `{p.hostname}` Security Architecture")
        out.append("")
        if p.chassis_cluster:
            out.append("- **HA mode:** ✅ chassis-cluster active")
        if p.security_zones:
            out.append(f"- **Security zones ({len(p.security_zones)}):**")
            for z in p.security_zones[:20]:
                out.append(f"  - `{z}`")
            if len(p.security_zones) > 20:
                out.append(f"  - _… +{len(p.security_zones)-20} more_")
        out.append(f"- **Security policies declared:** {p.security_policies_count}")
        out.append("")
    return out


def _services_section(profiles: list[DeviceProfile]) -> list[str]:
    out: list[str] = ["| Device | SNMP | NTP servers | Syslog hosts | RADIUS | TACACS | DNS |",
                       "|--------|------|-------------|--------------|--------|--------|-----|"]
    for p in profiles:
        snmp = ("v3" if p.snmp_v3 else "") + ("/v2c" if p.snmp_v2c_present else "")
        out.append(f"| `{p.hostname}` | {snmp or '—'} | "
                   f"{', '.join(p.ntp_servers[:3]) or '—'} | "
                   f"{', '.join(p.syslog_hosts[:3]) or '—'} | "
                   f"{', '.join(p.radius_servers[:2]) or '—'} | "
                   f"{', '.join(p.tacacs_servers[:2]) or '—'} | "
                   f"{', '.join(p.dns_servers[:2]) or '—'} |")
    out.append("")
    # Warnings
    warns: list[str] = []
    v2c = [p.hostname for p in profiles if p.snmp_v2c_present]
    if v2c: warns.append(f"⚠️ **SNMPv2c (clear-text)** found on: {', '.join(v2c)}")
    no_ntp = [p.hostname for p in profiles if not p.ntp_servers]
    if no_ntp: warns.append(f"⚠️ **No NTP configured** on: {', '.join(no_ntp)}")
    no_syslog = [p.hostname for p in profiles if not p.syslog_hosts]
    if no_syslog: warns.append(f"⚠️ **No remote syslog** on: {', '.join(no_syslog)}")
    no_aaa = [p.hostname for p in profiles if not p.radius_servers and not p.tacacs_servers]
    if no_aaa: warns.append(f"⚠️ **No centralized AAA (RADIUS/TACACS)** on: {', '.join(no_aaa)}")
    if warns:
        out.append("**Site-wide service warnings:**")
        out.append("")
        out.extend(warns)
    return out


def _software_lifecycle_section(profiles: list[DeviceProfile]) -> list[str]:
    out: list[str] = []
    out.append("| Device | Platform | Version | Status | Released | EOL ~ |")
    out.append("|--------|----------|---------|--------|----------|-------|")
    risky_count = 0
    for p in profiles:
        if not p.software_version:
            out.append(f"| `{p.hostname}` | {p.platform} | _unknown_ | ❓ | — | — |")
            continue
        rel, eol, status = p.lifecycle
        if _is_risky(status):
            risky_count += 1
        out.append(f"| `{p.hostname}` | {p.platform} | `{p.software_version}` | "
                   f"{status} | {rel or '—'} | {eol or '—'} |")
    out.append("")
    if risky_count:
        out.append(f"⚠️ **{risky_count} device(s) running EOL or limited-support software** — "
                   "see Recommendations section.")
    return out


def _compliance_section(devices: list[dict]) -> str:
    report = compliance.check_bundle(devices)
    lines: list[str] = []
    lines.append(f"**Compliance score:** {report['passed']}/{report['total_checks']} "
                 f"checks passed ({report['pass_rate']}%) — {report['failed']} failures")
    lines.append("")
    failing = [r for r in report.get("rules", []) if r["fail"] > 0]
    if not failing:
        return "\n".join(lines) + "\n✅ All compliance rules passed."
    lines.append("**Failing rules:**")
    lines.append("")
    lines.append("| Severity | Rule | Pass | Fail | Failing devices |")
    lines.append("|----------|------|------|------|-----------------|")
    for r in sorted(failing, key=lambda x: _SEVERITY_RANK.get(x["severity"], 9)):
        devs = ", ".join(fd["device"] for fd in r["failing_devices"][:6])
        if len(r["failing_devices"]) > 6:
            devs += f" (+{len(r['failing_devices'])-6} more)"
        lines.append(f"| {r['severity'].upper()} | {r['rule_name']} | {r['pass']} | "
                     f"{r['fail']} | {devs} |")
    return "\n".join(lines)


def _recommendations_section(profiles: list[DeviceProfile], isps: list) -> list[str]:
    recs: dict[str, list[str]] = {key: [] for key, _ in _REC_PRIORITY_TITLES}

    # Single pass over profiles to collect per-device problems
    v2c: list[str] = []
    no_syslog: list[str] = []
    no_ntp: list[str] = []
    no_aaa: list[str] = []
    versions: Counter[str] = Counter()
    for p in profiles:
        if p.software_version:
            versions[p.software_version] += 1
            _, _, status = p.lifecycle
            if "🔴" in status:
                recs["recs_p1"].append(
                    f"**Upgrade `{p.hostname}` from `{p.software_version}`** — "
                    f"{status.replace('🔴 ', '')}. Target: current LTS."
                )
        if p.snmp_v2c_present:
            v2c.append(p.hostname)
        if not p.syslog_hosts:
            no_syslog.append(p.hostname)
        if not p.ntp_servers:
            no_ntp.append(p.hostname)
        if not p.radius_servers and not p.tacacs_servers:
            no_aaa.append(p.hostname)

    if v2c:
        recs["recs_p1"].append(
            f"**Migrate SNMPv2c → v3** on: {', '.join(v2c)}. "
            "Communities are clear-text — security finding."
        )
    shutdown_isps = [i for i in isps if i.status == "shutdown"]
    if shutdown_isps:
        recs["recs_p2"].append(
            f"**Validate shutdown ISP(s)**: {', '.join(i.name for i in shutdown_isps)}. "
            "Either re-enable for redundancy or decommission to avoid pay-for-nothing circuits."
        )
    if no_syslog:
        recs["recs_p2"].append(
            f"**Configure remote syslog** on: {', '.join(no_syslog)}. "
            "Logs lost on reboot if no remote collector."
        )
    if len(versions) > 1:
        recs["recs_p3"].append(
            f"**Standardize software version** — {len(versions)} distinct versions: "
            f"{dict(versions)}. Pick a target and roll out."
        )
    if no_ntp:
        recs["recs_p3"].append(f"**Configure NTP** on: {', '.join(no_ntp)}.")
    if no_aaa:
        recs["recs_p3"].append(
            f"**Configure centralized AAA (RADIUS/TACACS)** on: {', '.join(no_aaa)}."
        )
    if len(isps) == 1:
        recs["recs_p4"].append(
            "**Evaluate adding a secondary ISP** for redundancy. "
            "Currently only one ISP detected."
        )

    out: list[str] = []
    for key, title in _REC_PRIORITY_TITLES:
        items = recs[key]
        out.append(f"### {title}")
        out.append("")
        if not items:
            out.append("- _None at this priority._")
        else:
            for i, txt in enumerate(items, 1):
                out.append(f"{i}. {txt}")
        out.append("")
    return out


def _technical_summary(site: str, profiles: list[DeviceProfile],
                        vlans: dict, isps: list, wan_ips: list) -> list[str]:
    out: list[str] = []
    out.append("| Metric | Value |")
    out.append("|--------|-------|")
    out.append(f"| Site | {site} |")
    out.append(f"| Devices | {len(profiles)} ({Counter(p.role for p in profiles)}) |")
    out.append(f"| VLANs | {len(vlans)} |")
    out.append(f"| ISPs | {len(isps)} ({', '.join(f'{i.name}/{i.status}' for i in isps) or '—'}) |")
    out.append(f"| Public WAN IPs | {len(wan_ips)} |")
    out.append(f"| BGP neighbors (total) | {sum(len(p.bgp_neighbors) for p in profiles)} |")
    out.append(f"| Distinct software versions | {len(set(p.software_version for p in profiles if p.software_version))} |")
    out.append(f"| ADVPN tunnels (total) | {sum(len(p.advpn) for p in profiles)} |")
    out.append(f"| Security zones (total) | {sum(len(p.security_zones) for p in profiles)} |")
    out.append(f"| Security policies (total) | {sum(p.security_policies_count for p in profiles)} |")
    return out


def _appendices(profiles: list[DeviceProfile]) -> list[str]:
    out: list[str] = []
    out.append("### Appendix A: Configuration File Inventory")
    out.append("")
    out.append("| Device | Platform | Size (sanitized) | Software | Loopback |")
    out.append("|--------|----------|------------------|----------|----------|")
    for p in sorted(profiles, key=lambda x: x.hostname):
        out.append(f"| `{p.hostname}` | {p.platform} | {p.config_size_bytes//1024} KB | "
                   f"{p.software_version or '—'} | {', '.join(p.loopback_ips) or '—'} |")
    out.append("")
    out.append("### Appendix B: BGP Peer Summary (all devices)")
    out.append("")
    out.append("| Device | Peer IP | Remote AS |")
    out.append("|--------|---------|-----------|")
    for p in profiles:
        for n in p.bgp_neighbors[:8]:
            out.append(f"| `{p.hostname}` | `{n['ip']}` | {n['remote_as']} |")
    out.append("")
    out.append("### Appendix C: Edge-Inference Rules (topology)")
    out.append("")
    out.append("1. **description-hostname** (conf 0.95): an interface description names another device by hostname.")
    out.append("2. **mlag-peer** (conf 1.0): EOS `peer-address` resolves to another device's interface IP.")
    out.append("3. **bgp-neighbor** (conf 0.95): BGP neighbor IP matches another device's interface IP exactly.")
    out.append("4. **subnet-co-membership** (conf 0.85): two devices both have an interface in the same /28-/31 network.")
    out.append("5. **ha-pair-naming** (conf 0.9): paired naming (`-01a/-01b` or `-01/-02`) plus chassis-cluster presence.")
    out.append("")
    out.append("### Appendix D: Tooling & Data Provenance")
    out.append("")
    out.append("- AI Log Analyzer (this tool)")
    out.append("- Sanitized config bundle: `04_Scripts_Tools/AI_Log_Analyzer/sites/`")
    out.append("- LLM provider: configurable runtime (Ollama / Docker Model Runner / Anthropic)")
    out.append("- Compliance engine: 9 built-in rules (SSHv2, telnet-banned, NTP-redundancy, etc.)")
    return out


# ─────────────────────────────────────────────────────────────────────────────
# HTML render
# ─────────────────────────────────────────────────────────────────────────────

def render_site_doc_html(site_id: str, devices: list[dict], **kwargs) -> str:
    import html as _html
    md = render_site_doc(site_id, devices, **kwargs)
    body_html = _markdown_to_html(md)

    # Render Graphviz DOT to PNG if available
    dot_text = site_diagram.build_site_dot(site_id.upper(), devices)
    png_bytes = site_diagram.render_dot_to_png(dot_text)
    diagram_img = ""
    if png_bytes:
        b64 = base64.b64encode(png_bytes).decode()
        diagram_img = (f'<h2>Auto-Rendered Traffic Flow Diagram</h2>'
                       f'<img src="data:image/png;base64,{b64}" style="max-width:100%;border:1px solid #30363d;border-radius:6px;">')

    safe_title = _html.escape(site_id.upper())
    return f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><title>{safe_title} — Comprehensive Site Analysis</title>
<style>
  body {{ font: 14px/1.55 -apple-system, system-ui, sans-serif;
          background:#0d1117; color:#e6edf3; margin:0; padding:30px;
          max-width:1150px; margin:auto; }}
  h1 {{ border-bottom:2px solid #30363d; padding-bottom:8px; color:#58a6ff; }}
  h2 {{ margin-top:32px; color:#79c0ff; font-size:20px;
        border-bottom:1px solid #30363d; padding-bottom:4px; }}
  h3 {{ margin-top:18px; color:#c9d1d9; font-size:16px; }}
  h4 {{ margin-top:12px; color:#c9d1d9; font-size:14px; }}
  code {{ background:#161b22; padding:1px 6px; border-radius:3px;
          font-family: ui-monospace, "SF Mono", monospace; color:#79c0ff; font-size:90%; }}
  pre {{ background:#161b22; padding:12px; border-radius:6px;
         border:1px solid #30363d; overflow:auto; white-space:pre-wrap; font-size:12px; }}
  pre code {{ background:transparent; padding:0; color:#c9d1d9; }}
  table {{ border-collapse:collapse; width:100%; margin:14px 0;
           font-size:13px; background:#161b22; }}
  th, td {{ padding:8px 12px; border:1px solid #30363d; text-align:left; }}
  th {{ background:#0d1117; color:#8b949e; font-size:11px;
        text-transform:uppercase; letter-spacing:0.5px; }}
  tr:nth-child(even) {{ background:#0d1117; }}
  ul li {{ margin:4px 0; }}
  .mermaid {{ background:white; border-radius:6px; padding:12px; margin:16px 0; }}
  img {{ max-width:100%; }}
  @media print {{ body {{ background:white; color:#24292e; max-width:none; padding:20px; }}
                  h1,h2,h3,h4 {{ color:#0366d6; }}
                  pre, code, table {{ background:#f6f8fa; color:#24292e; }}
                  th {{ background:#eee; color:#586069; }}
                  pre {{ font-size:10px; }} }}
</style>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<script>document.addEventListener('DOMContentLoaded', () => {{
  mermaid.initialize({{startOnLoad:false,theme:'default'}});
  mermaid.run({{querySelector:'pre.lang-mermaid'}});
}});</script>
</head><body>
{body_html}
{diagram_img}
</body></html>"""


def _markdown_to_html(md: str) -> str:
    """Tiny markdown → HTML converter. Same as before."""
    import html as _h
    lines = md.split("\n")
    out: list[str] = []
    i = 0
    in_code = False
    code_lang = ""
    code_buf: list[str] = []

    def flush_code():
        nonlocal code_buf, code_lang
        if code_lang == "mermaid":
            out.append(f'<pre class="lang-mermaid mermaid">{_h.escape(chr(10).join(code_buf))}</pre>')
        elif code_lang:
            out.append(f'<pre class="lang-{_h.escape(code_lang)}"><code>'
                        f'{_h.escape(chr(10).join(code_buf))}</code></pre>')
        else:
            out.append(f'<pre><code>{_h.escape(chr(10).join(code_buf))}</code></pre>')
        code_buf = []
        code_lang = ""

    def inline(s: str) -> str:
        s = _h.escape(s)
        s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
        s = re.sub(r"\*\*([^*]+?)\*\*", r"<strong>\1</strong>", s)
        s = re.sub(r"(?<!\*)\*([^*\n]+?)\*(?!\*)", r"<em>\1</em>", s)
        return s

    while i < len(lines):
        line = lines[i]
        if line.startswith("```"):
            if in_code:
                flush_code(); in_code = False
            else:
                in_code = True; code_lang = line[3:].strip()
            i += 1; continue
        if in_code:
            code_buf.append(line); i += 1; continue
        if line.startswith("# "):
            out.append(f"<h1>{inline(line[2:].strip())}</h1>"); i += 1; continue
        if line.startswith("## "):
            out.append(f"<h2>{inline(line[3:].strip())}</h2>"); i += 1; continue
        if line.startswith("### "):
            out.append(f"<h3>{inline(line[4:].strip())}</h3>"); i += 1; continue
        if line.startswith("#### "):
            out.append(f"<h4>{inline(line[5:].strip())}</h4>"); i += 1; continue
        if line.strip() == "---":
            out.append("<hr>"); i += 1; continue
        if line.startswith("|") and i + 1 < len(lines) and re.match(r"^\|\s*[-:]+", lines[i + 1]):
            header_cells = [c.strip() for c in line.strip("|").split("|")]
            tbl = ["<table><thead><tr>"]
            for c in header_cells:
                tbl.append(f"<th>{inline(c)}</th>")
            tbl.append("</tr></thead><tbody>")
            i += 2
            while i < len(lines) and lines[i].startswith("|"):
                row = [c.strip() for c in lines[i].strip("|").split("|")]
                tbl.append("<tr>")
                for c in row:
                    tbl.append(f"<td>{inline(c)}</td>")
                tbl.append("</tr>"); i += 1
            tbl.append("</tbody></table>")
            out.append("".join(tbl)); continue
        if line.startswith("- "):
            ul = ["<ul>"]
            while i < len(lines) and lines[i].startswith("- "):
                ul.append(f"<li>{inline(lines[i][2:].strip())}</li>"); i += 1
            ul.append("</ul>")
            out.append("".join(ul)); continue
        if re.match(r"^\d+\.\s+", line):
            ol = ["<ol>"]
            while i < len(lines) and re.match(r"^\d+\.\s+", lines[i]):
                content = re.sub(r"^\d+\.\s+", "", lines[i]).strip()
                ol.append(f"<li>{inline(content)}</li>"); i += 1
            ol.append("</ol>")
            out.append("".join(ol)); continue
        if line.strip() == "":
            i += 1; continue
        out.append(f"<p>{inline(line.strip())}</p>"); i += 1

    if in_code:
        flush_code()
    return "\n".join(out)
