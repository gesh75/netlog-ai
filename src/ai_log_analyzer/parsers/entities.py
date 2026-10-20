"""Entity extraction shared by every parser.

``enrich_netos(appname, message)`` turns a free-text data-center NOS line
(Junos, Arista EOS, Cisco IOS-XE / NX-OS, FRR, SONiC, Cumulus, SR Linux) into
canonical structured fields: vendor, event_type, peer_ip, asn, vrf, vni,
interface, tunnel_id and a down/up ``state`` used for recovery pairing.

Every rule is gated by a cheap substring test before any regex runs, so the
cost on lines that carry no entity is a handful of ``in`` checks.
"""
from __future__ import annotations

import ipaddress
import re

_IPV4 = r"(?:\d{1,3}\.){3}\d{1,3}"
_IPV6 = r"[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}"
_IP = rf"(?:{_IPV4}|{_IPV6})"


def valid_ip(text: str | None) -> str:
    """Canonical form of an IP address, or "" when ``text`` is not one."""
    if not text:
        return ""
    try:
        return str(ipaddress.ip_address(text.strip().strip("[](),;")))
    except ValueError:
        return ""


def first_ip(patterns: tuple[re.Pattern[str], ...], text: str) -> str:
    for pattern in patterns:
        for m in pattern.finditer(text):
            ip = valid_ip(m.group("ip"))
            if ip:
                return ip
    return ""


# ── Vendor detection ────────────────────────────────────────────────────────

_EOS_AGENTS = frozenset({
    "ebra", "bgp", "rib", "stp", "lag", "lacptxagent", "lldp", "ira", "configagent",
    "fhrp", "mlag", "ospf", "bfd", "sysdb", "procmgr", "superserver", "aaa", "xcvr",
    "phyethtool", "sandfap", "strataagent", "evpn", "vxlan", "vxlanswfwd", "acl",
})
_FRR_APPS = frozenset({"bgpd", "ospfd", "ospf6d", "zebra", "bfdd", "isisd", "staticd",
                       "watchfrr", "pimd", "ldpd", "frr", "vtysh"})
_SONIC_APPS = frozenset({"orchagent", "syncd", "swss", "teamd", "teamsyncd", "portsyncd",
                         "neighsyncd", "fpmsyncd", "bgpcfgd", "sonic", "pmon", "lldpmgrd"})
_CUMULUS_APPS = frozenset({"switchd", "clagd", "ptmd", "nvued", "ifupdown2", "netd"})
_JUNOS_APPS = frozenset({"rpd", "mgd", "kmd", "chassisd", "dcd", "l2ald", "pfed", "jddosd",
                         "alarmd", "craftd", "jlaunchd", "lacpd", "bfdd-junos", "mib2d",
                         "snmpd-junos", "eventd", "kernel-junos", "iked"})
_NXOS_FACILITIES = frozenset({"ETHPORT", "ETH_PORT_CHANNEL", "VPC", "SYSMGR", "VSHD",
                              "IFMGR", "ETHPM", "VDC_MGR", "PLATFORM", "MODULE", "NVE"})
_MNEMONIC_RE = re.compile(r"%(?P<fac>[A-Z][A-Z0-9_]+)-(?P<sev>\d)-(?P<mnem>[A-Z0-9_]+)")
_JUNOS_TAG_RE = re.compile(r"\b(?:RPD|KMD|SNMP_TRAP|CHASSISD|UI|BFDD|LACPD|DCD|L2ALD|PFE|JSRPD|ESWD)_[A-Z0-9_]+")
_CAMEL_RE = re.compile(r"^[A-Z][a-z]+(?:[A-Z][a-z0-9]*)*$")


def detect_vendor(appname: str, message: str) -> str:
    app = (appname or "").strip()
    app_l = app.lower()
    if "#" in app_l or app_l in _SONIC_APPS:
        return "sonic"
    if app_l in _CUMULUS_APPS:
        return "cumulus"
    if app_l in _FRR_APPS:
        return "frr"
    if app_l in _JUNOS_APPS or _JUNOS_TAG_RE.search(message):
        return "juniper"
    # The Junos-style envelope can move "%FAC-SEV-MNEMONIC" into the appname.
    m = _MNEMONIC_RE.search(f"{app} {message}")
    if m:
        if app_l in _EOS_AGENTS or (app and _CAMEL_RE.match(app)):
            return "arista"
        if m.group("fac") in _NXOS_FACILITIES or re.search(r"\bbgp-\d+ \[\d+\]", message):
            return "cisco_nxos"
        return "cisco_ios"
    if app_l in _EOS_AGENTS:
        return "arista"
    if "srlinux" in app_l or app_l.startswith("sr_") or app_l.endswith("_mgr"):
        return "nokia_srl"
    return ""


# ── Field extractors ────────────────────────────────────────────────────────

_BGP_PEER_RES = (
    re.compile(rf"\b(?:neighbou?r|peer)\s+(?P<ip>{_IP})", re.IGNORECASE),
    re.compile(rf"\b(?:sent to|received from)\s+(?P<ip>{_IP})", re.IGNORECASE),  # NOTIFICATION sent to <ip>
    re.compile(rf"\bBGP:\s*(?P<ip>{_IP})", re.IGNORECASE),  # FortiOS "BGP: 10.0.0.1-outgoing"
    re.compile(rf"(?P<ip>{_IPV4})\+\d+"),                   # Junos "10.0.0.1+179"
)
_GENERIC_PEER_RES = (
    re.compile(rf"\b(?:neighbou?r|peer|nbr|to|from|remote(?:[- ](?:peer|gateway|address|ip))?)\s*:?\s+(?P<ip>{_IP})", re.IGNORECASE),
    re.compile(rf"(?P<ip>{_IPV4})"),
)
_ASN_RES = (
    re.compile(r"\b(?:External|Internal)\s+AS\s+(?P<asn>\d{1,10})\b"),
    re.compile(r"\bremote[- ]as\s+(?P<asn>\d{1,10})\b", re.IGNORECASE),
    re.compile(r"\bpeer[- ]as\s+(?P<asn>\d{1,10})\b", re.IGNORECASE),
    re.compile(r"\bAS\s?(?P<asn>\d{1,10})\b"),
)
_VRF_RES = (
    re.compile(r"\b[Vv][Rr][Ff]\s+(?P<vrf>[A-Za-z0-9_.:\-]+)"),
    re.compile(r"\(instance\s+(?P<vrf>[A-Za-z0-9_.:\-]+)\)"),
    re.compile(r"\brouting-instance\s+(?P<vrf>[A-Za-z0-9_.:\-]+)"),
)
_VNI_RE = re.compile(r"\b(?:VNI|vni|VNID|vnid|l2vni|l3vni)\s*[:=]?\s*(?P<vni>\d{1,8})\b")
_INTF_NAME = (
    r"(?:(?:Ten|Forty|Hundred|TwentyFive|Fifty|FourHundred)?Gig(?:abit)?E(?:thernet)?"
    r"|FastEthernet|Ethernet|ethernet-|ethernet|Eth|Port-[Cc]hannel|port-channel|Po|Vlan|vlan|Loopback|lo"
    r"|Tunnel|tunnel\.|Management|mgmt|Vxlan|ae|xe-|et-|ge-|mge-|irb\.|st0\.|swp|eth|Bundle-Ether|Te|Gi|Fa|Hu|Fo)"
    r"\d+(?:[/.:]\d+)*"
)
_INTF_RES = (
    re.compile(rf"\bifName\s+(?P<if>{_INTF_NAME})"),
    re.compile(rf"\b[Ii]nterface\s+(?P<if>{_INTF_NAME})"),
    re.compile(rf"(?<![\w-])(?P<if>{_INTF_NAME})(?![\w-])"),
)
_STATE_TO_RE = re.compile(
    r"(?:changed state from|from|old state)\s+(?P<old>\w+)\s+(?:to|event \w+ new state|->)\s+(?P<new>\w+)"
    r"|(?:new[- ]state|state changed to|state)\s*[:=]?\s*(?P<new2>\w+)"
    r"|->\s*(?P<new3>\w+)",
    re.IGNORECASE,
)
_BGP_UP_STATES = frozenset({"established", "up"})
_BGP_DOWN_STATES = frozenset({"idle", "active", "connect", "opensent", "openconfirm", "down", "init"})


def _first(patterns: tuple[re.Pattern[str], ...], text: str, group: str) -> str:
    for pattern in patterns:
        m = pattern.search(text)
        if m and m.group(group):
            return m.group(group).rstrip(",.;:)")
    return ""


def extract_asn(text: str) -> str:
    return _first(_ASN_RES, text, "asn")


def extract_vrf(text: str) -> str:
    vrf = _first(_VRF_RES, text, "vrf")
    # Junos names the default table "master"; EOS/IOS/FRR say "default".
    return "default" if vrf == "master" else vrf


def extract_vni(text: str) -> str:
    m = _VNI_RE.search(text)
    return m.group("vni") if m else ""


def extract_interface(text: str) -> str:
    return _first(_INTF_RES, text, "if")


def final_state_word(text: str) -> str:
    """Last FSM state named in a transition ("from Established to Idle" → "idle")."""
    word = ""
    for m in _STATE_TO_RE.finditer(text):
        word = (m.group("new") or m.group("new2") or m.group("new3") or "").lower()
    return word


def bgp_state(low: str, original: str) -> str:
    word = final_state_word(original)
    if word in _BGP_UP_STATES:
        return "up"
    if word in _BGP_DOWN_STATES:
        return "down"
    if re.search(r"\b(?:down|idle|cease|notification|hold.?tim\w*|reset|closed|connect_failed|connection failed|"
                 r"exceed\w*|left established)\b", low):
        return "down"
    if re.search(r"\b(?:up|established|enter(?:ed)? established)\b", low):
        return "up"
    return ""


_DOWN_RE = re.compile(
    r"changed state to (?:administratively )?down|\blink\s*(?:is\s*)?down\b|link_down|if_down|ifoperstatus down|"
    r"carrier\s*(?:lost|down)|oper(?:ational)?[ -]?(?:state|status)\s*(?:is\s*|changed to\s*)?down|\bis down\b|"
    r"\bwent down\b|\bstate down\b|\bdown\b",
    re.IGNORECASE,
)
_UP_RE = re.compile(
    r"changed state to up|\blink\s*(?:is\s*)?up\b|link_up|if_up|ifoperstatus up|carrier\s*(?:detected|up)|"
    r"oper(?:ational)?[ -]?(?:state|status)\s*(?:is\s*|changed to\s*)?up|\bis up\b|\bcame up\b|\bstate up\b|\bup\b",
    re.IGNORECASE,
)


def updown(text: str) -> str:
    if _DOWN_RE.search(text):
        return "down"
    if _UP_RE.search(text):
        return "up"
    return ""


# ── NOS enrichment ──────────────────────────────────────────────────────────

_MAXPFX_RE = re.compile(r"max(?:imum)?[-_ ]?(?:number of )?(?:prefix|pfx)|prefix[-_ ]limit|maxpfx", re.IGNORECASE)
_PATHCHG_RE = re.compile(r"(?:origin(?:\s+as)?|as[-_ ]?path)\s*(?:change|changed|mismatch|conflict)|\bmoas\b|"
                         r"route leak|possible hijack", re.IGNORECASE)
_LOCAL_IP_RE = re.compile(rf"\b(?:Local-ip|local[- ]address|local ip|source)\s*[:=]?\s*(?P<ip>{_IP})", re.IGNORECASE)
_IPSEC_RE = re.compile(r"\b(?:ipsec|ike|ikev2|isakmp|crypto)\b")
_KMD_TUNNEL_RE = re.compile(r"\bvpn name:\s*(?P<t>[^,]+)|\bVPN\s+(?P<t2>\S+)\s+from\b|\btunnel[- ](?:name|id)\s*[:=]?\s*(?P<t3>[\w.\-]+)",
                            re.IGNORECASE)


def enrich_netos(appname: str, message: str) -> dict[str, str]:
    """Structured fields for a DC NOS free-text line (may be empty).

    Keys prefixed ``attr:`` are vendor extras for ``LogEvent.attrs``.
    """
    msg = message or ""
    low = f"{appname} {msg}".lower()
    out: dict[str, str] = {}
    vendor = detect_vendor(appname, msg)
    if vendor:
        out["vendor"] = vendor

    if "bgp" in low or "adjchange" in low:
        out["event_type"] = "bgp_session"
        if _MAXPFX_RE.search(msg):
            out["event_type"] = "bgp_max_prefix"
        elif _PATHCHG_RE.search(msg):
            out["event_type"] = "bgp_path_change"
        peer = first_ip(_BGP_PEER_RES, msg)
        if peer:
            out["peer_ip"] = peer
        state = bgp_state(low, msg)
        # A max-prefix *warning* is not a session state change; exceeding it is.
        if out["event_type"] == "bgp_max_prefix":
            state = "down" if re.search(r"exceed|teardown|cease|\bdown\b", low) else ""
        if out["event_type"] == "bgp_path_change":
            state = ""
        if state:
            out["state"] = state
    elif "bfd" in low:
        out["event_type"] = "bfd_session"
        peer = first_ip(_GENERIC_PEER_RES, msg)
        if peer:
            out["peer_ip"] = peer
        state = updown(msg)
        if state:
            out["state"] = state
    elif "ospf" in low:
        out["event_type"] = "ospf_adjacency"
        peer = first_ip(_GENERIC_PEER_RES, msg)
        if peer:
            out["peer_ip"] = peer
        word = final_state_word(msg)
        if word == "full":
            out["state"] = "up"
        elif word:
            out["state"] = "down"
        elif re.search(r"\bfull\b", low):
            out["state"] = "up"
        elif re.search(r"\b(?:down|dead)\b", low):
            out["state"] = "down"
    elif "kmd_vpn" in low or _IPSEC_RE.search(low) or ("vpn" in low and "tunnel" in low):
        out["event_type"] = "ipsec_tunnel"
        m = _KMD_TUNNEL_RE.search(msg)
        if m:
            out["tunnel_id"] = (m.group("t") or m.group("t2") or m.group("t3") or "").strip()
        peer = first_ip(_GENERIC_PEER_RES, msg)
        if peer:
            out["peer_ip"] = peer
        m = _LOCAL_IP_RE.search(msg)
        if m and valid_ip(m.group("ip")):
            out["attr:local_ip"] = valid_ip(m.group("ip"))
        state = updown(msg)
        if state:
            out["state"] = state
    elif any(k in low for k in ("lacp", "lag_bundle", "lag member", "teamd", "bundle")):
        out["event_type"] = "lag_member"
        intf = extract_interface(msg)
        if intf:
            out["interface"] = intf
        if re.search(r"leaving|down|timeout|expired|removed|detached", low):
            out["state"] = "down"
        elif re.search(r"joining|added|\bup\b|attached|collecting", low):
            out["state"] = "up"
    elif any(k in low for k in ("link", "updown", "if_down", "if_up", "carrier", "oper", "changed state")):
        intf = extract_interface(msg)
        state = updown(msg)
        if intf and state:
            out["event_type"] = "interface_link"
            out["interface"] = intf
            out["state"] = state
    elif "commit" in low or "config_i" in low or "configured from" in low:
        out["event_type"] = "config_change"

    # Cheap substring gates before the regexes (most lines carry none of these).
    asn = extract_asn(msg) if ("AS" in msg or "-as" in low) else ""
    if asn:
        out["asn"] = asn
    vrf = extract_vrf(msg) if ("vrf" in low or "instance" in low) else ""
    if vrf:
        out["vrf"] = vrf
    vni = extract_vni(msg) if "vni" in low else ""
    if vni:
        out["vni"] = vni
        # An EVPN route event that names a VNI but no BGP peer is about the overlay.
        if "evpn" in low and not out.get("peer_ip"):
            out["event_type"] = "evpn"
            out.pop("state", None)
        out.setdefault("event_type", "evpn")
    return out
