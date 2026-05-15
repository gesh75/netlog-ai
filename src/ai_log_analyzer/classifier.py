"""Pattern-based syslog classifier — vendor-agnostic.

Each event is matched against a regex KB and assigned (severity, category, description).
Works on any normalized event regardless of source (Kibana, FRR docker logs, raw syslog).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

# (regex, severity, category, description) — first match wins.
# Patterns tested against f"{appname} {message}".lower()
_KB_PATTERNS: list[tuple[str, str, str, str]] = [
    # ── CRITICAL ─────────────────────────────────────────────────────────
    (r"kernel\s*panic|core\s*dump|watchdog.*reset|rpd.*panic",          "critical", "system",     "Kernel panic / core dump — OS failure"),
    (r"swap_pager_getswapspace.*failed|swap.*exhaust",                  "critical", "system",     "Kernel swap space exhaustion"),
    (r"out\s+of\s+memory|heap.*exhaust|memory.*full|oom.?kill",         "critical", "system",     "Memory exhaustion / OOM"),
    (r"parity\s+error|sbus\s+transaction|ser_overlay_mem_correction",   "critical", "hardware",   "ASIC memory parity error (hard)"),
    (r"fpc\d+.*(?:offline|power.?off|restart|crash|halt)",              "critical", "hardware",   "FPC/line card offline or crash"),
    (r"(?:major|minor|chassis)\s+alarm",                                "critical", "hardware",   "Chassis alarm triggered"),
    (r"power\s*supply.*fail|psu.*fail|fan.*(?:fail|offline)",           "critical", "hardware",   "Power supply or fan failure"),
    (r"routing\s+engine.*failover|re\d+.*switchover|mastership",        "critical", "system",     "Routing Engine failover/switchover"),
    # ── HIGH ─────────────────────────────────────────────────────────────
    (r"bgp_connect_failed|bgp.*(?:down|cease|no\s+route|hold.?timer)",  "high",     "routing",    "BGP peer down / connect failure"),
    (r"rpd_bgp.*idle|bgp.*state.*idle|bgp.*notification",               "high",     "routing",    "BGP peer idle / notification"),
    (r"%bgp-3-notification|%bgp-5-adjchange.*down",                     "high",     "routing",    "BGP notification / adjacency down (FRR/IOS)"),
    (r"ospf.*(?:neighbor.*down|adj.*change|dead.*timer)",               "high",     "routing",    "OSPF neighbor state change"),
    (r"%ospf-5-adjchg.*down|ospf.*from\s+full\s+to",                    "high",     "routing",    "OSPF adjacency loss (FRR/IOS)"),
    (r"bfd.*(?:down|removed|session.*fail)",                            "high",     "routing",    "BFD session down"),
    (r"isis.*(?:adj.*down|adj.*change|lsp.*purge)",                     "high",     "routing",    "IS-IS adjacency change"),
    (r"license.*(?:expir|invalid|warn)|expir.*license",                 "high",     "compliance", "License expiration warning"),
    (r"ike.*fail|ipsec.*fail|vpn.*down|tunnel.*down|advpn",             "high",     "vpn",        "VPN/IPsec tunnel failure"),
    (r"lacp.*(?:timeout|expired|down)|lag_bundle.*down|ae\d+.*down",    "high",     "lag",        "LACP/LAG member down"),
    (r"lag_bundle.*leaving|lag.*member.*removed",                       "high",     "lag",        "LAG member leaving bundle"),
    (r"mlag.*(?:fail|inconsist|disabled)|mlag.*inactive",               "high",     "lag",        "MLAG failure/inconsistency"),
    (r"snmp_trap_link_down|link\s*down|carrier.*down|if_down",          "high",     "interface",  "Interface link down"),
    (r"err.?disabl|errdisable|shutdown.*error",                         "high",     "interface",  "Interface error-disabled"),
    (r"authentication.*fail|login.*fail|auth.*invalid|pam_unix.*fail",  "high",     "security",   "Authentication failure"),
    (r"vrrp.*(?:master.*change|backup|failover)|hsrp.*change",          "high",     "redundancy", "VRRP/gateway failover"),
    (r"fpc\d+.*(?:error|mem:|unit:)",                                   "high",     "hardware",   "FPC hardware error"),
    (r"l3_entry|l2_entry|memory\s+block|blk:",                          "high",     "hardware",   "ASIC forwarding table error"),
    # ── MEDIUM ───────────────────────────────────────────────────────────
    (r"snmp_trap_link_up|link\s*up|carrier.*up|if_up",                  "medium",   "interface",  "Interface link up"),
    (r"rpd_bgp.*establ|bgp.*established|%bgp-5-adjchange.*up",          "medium",   "routing",    "BGP peer established"),
    (r"ospf.*(?:neighbor.*full|adj.*full)|%ospf-5-adjchg.*full",        "medium",   "routing",    "OSPF neighbor established"),
    (r"ntp.*(?:unreachable|stratum.*16|no.*server|sync\s+lost)",        "medium",   "ntp",        "NTP sync lost/unreachable"),
    (r"stp.*(?:tcn|topology.*change|root.*change)",                     "medium",   "stp",        "STP topology change"),
    (r"pfe.*discard|packet.*drop|policer.*drop|congestion",             "medium",   "performance","Packet drops/policer discard"),
    (r"pause.*frame|flow.?control|flowcontrol",                         "medium",   "performance","Flow control / pause frames"),
    (r"temperature.*(?:warn|high|threshold)|thermal|overheat",          "medium",   "hardware",   "Temperature warning"),
    (r"acl.*deny|firewall.*deny|filter.*block|security.*deny",          "medium",   "security",   "Firewall/ACL deny event"),
    (r"ddos|flood|storm.?control",                                      "medium",   "security",   "DDoS/storm detected"),
    (r"lag_bundle.*joining|lag.*member.*added",                         "medium",   "lag",        "LAG member joining bundle"),
    (r"lacp.*activity|lacpd",                                           "medium",   "lag",        "LACP activity/negotiation"),
    (r"evpn.*(?:route|update|withdraw|type)",                           "medium",   "routing",    "EVPN route update"),
    (r"l2ald|l2.?learning|mac.*(?:move|flap|learn)",                    "medium",   "switching",  "MAC learning/move event"),
    (r"jddosd|ddos.*prot",                                              "medium",   "security",   "DDoS protection event"),
    # ── LOW ──────────────────────────────────────────────────────────────
    (r"accepted\s+(?:publickey|password|keyboard)|sshd.*accept",        "low",      "auth",       "SSH login accepted"),
    (r"session\s+(?:opened|closed)|pam_unix.*session",                  "low",      "auth",       "User session opened/closed"),
    (r"commit.*confirmed|config.*change|commit\b",                      "low",      "config",     "Configuration change committed"),
    (r"lldp.*(?:neighbor|add|delete|update)",                           "low",      "discovery",  "LLDP neighbor change"),
    (r"snmpd|agentx|snmp.*trap",                                        "low",      "monitoring", "SNMP daemon/trap activity"),
    (r"sshd.*(?:disconnect|close|exit)",                                "low",      "auth",       "SSH session disconnected"),
    (r"mgd.*(?:ui_login|ui_commit|cli_command)",                        "low",      "config",     "CLI management activity"),
    (r"alarmd|alarm.*(?:set|clear)",                                    "low",      "hardware",   "Alarm set/clear event"),
    (r"chassisd|craft.*interface",                                      "low",      "hardware",   "Chassis daemon activity"),
    (r"rpd_isis|rpd_ospf|rpd.*(?:start|init|ready)",                    "low",      "routing",    "Routing daemon activity"),
    (r"pfed|dfwd|dcd",                                                  "low",      "system",     "Forwarding daemon activity"),
    (r"(?:arista|strata|eos).*(?:agent|process)",                       "low",      "system",     "EOS agent/process activity"),
    (r"jlaunchd|process.*(?:start|stop|restart)",                       "low",      "system",     "Process lifecycle event"),
    (r"last\s+message\s+repeated",                                      "low",      "system",     "Repeated message suppressed"),
]

SEV_ORDER: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Pre-compile patterns once for speed
_COMPILED: list[tuple[re.Pattern[str], str, str, str]] = [
    (re.compile(p, re.IGNORECASE), s, c, d) for (p, s, c, d) in _KB_PATTERNS
]


@dataclass(frozen=True)
class LogEvent:
    """Normalized input event — what every adapter produces."""
    timestamp: str
    hostname: str
    appname: str
    severity_raw: str
    message: str


@dataclass
class ClassifiedEvent:
    """Output event after classification."""
    timestamp: str
    hostname: str
    appname: str
    severity: str           # critical | high | medium | low | info
    severity_raw: str
    category: str
    description: str
    action: str
    message: str
    sample_message: str = field(default="")  # short version for UI

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "appname": self.appname,
            "severity": self.severity,
            "severity_raw": self.severity_raw,
            "category": self.category,
            "description": self.description,
            "action": self.action,
            "message": self.message,
            "sample_message": self.sample_message,
        }


_DEFAULT_ACTIONS: dict[tuple[str, str], str] = {
    ("critical", "system"):     "Escalate immediately — possible OS/hardware failure",
    ("critical", "hardware"):   "Check chassis hardware — FPC/PSU/Fan replacement may be needed",
    ("critical", "compliance"): "Renew license urgently — feature may stop working",
    ("high", "routing"):        "Check BGP/OSPF neighbors — verify reachability and peering config",
    ("high", "interface"):      "Investigate physical link — check fiber/SFP/patch panel",
    ("high", "lag"):            "Check LAG member links — verify LACP config and cabling",
    ("high", "vpn"):            "Investigate VPN tunnel — check IKE Phase 1/2",
    ("high", "security"):       "Investigate auth failure — check logs for brute force",
    ("high", "redundancy"):     "Verify redundancy state — check VRRP priority and uplink",
    ("medium", "performance"):  "Monitor traffic — check for congestion or rate limiting",
    ("medium", "interface"):    "Verify link stability — check SFP Rx/Tx power",
    ("medium", "security"):     "Review ACL/firewall hits — check for policy violation",
    ("medium", "ntp"):          "Verify NTP reachability — time skew may affect logs",
    ("low", "auth"):             "Informational — log user access for audit",
    ("low", "config"):           "Informational — track config changes in change log",
}


def _action_for(sev: str, cat: str) -> str:
    return _DEFAULT_ACTIONS.get((sev, cat), "Review and investigate as needed")


def classify_events(events: Iterable[LogEvent]) -> tuple[list[ClassifiedEvent], dict[str, int], dict[str, int]]:
    """Classify a stream of LogEvents.

    Returns: (sorted classified events, severity_counts, category_counts).
    Sort order: critical → high → medium → low → info, then by timestamp desc.
    """
    classified: list[ClassifiedEvent] = []
    sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    cat_counts: dict[str, int] = {}

    for ev in events:
        combined = f"{ev.appname} {ev.message}".lower()
        sev, cat, desc = "info", "other", ""

        for pattern, p_sev, p_cat, p_desc in _COMPILED:
            if pattern.search(combined):
                sev, cat, desc = p_sev, p_cat, p_desc
                break

        if not desc:
            snippet = ev.message[:120].strip() or ev.appname or "General log message"
            desc = snippet

        # Promote raw severity if syslog says critical but classifier missed it
        if ev.severity_raw.lower() in ("crit", "emerg", "alert") and sev == "info":
            sev = "high"

        classified.append(ClassifiedEvent(
            timestamp=ev.timestamp,
            hostname=ev.hostname.split(".")[0] if ev.hostname else "",
            appname=ev.appname,
            severity=sev,
            severity_raw=ev.severity_raw,
            category=cat,
            description=desc,
            action=_action_for(sev, cat),
            message=ev.message[:500],
            sample_message=ev.message[:200],
        ))
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        cat_counts[cat] = cat_counts.get(cat, 0) + 1

    # Stable sort: pass 1 sorts newest first by ISO timestamp; pass 2 buckets by severity.
    classified.sort(key=lambda e: e.timestamp, reverse=True)
    classified.sort(key=lambda e: SEV_ORDER.get(e.severity, 5))
    return classified, sev_counts, cat_counts

