"""Pattern-based syslog classifier — vendor-agnostic.

Each event is matched against a regex KB and assigned (severity, category, description).
Works on any normalized event regardless of source (Kibana, FRR docker logs, raw syslog).
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Iterable, Iterator

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
    # Cisco IOS-XE / NX-OS (%FACILITY-SEV-MNEMONIC) + Nokia SR Linux
    (r"%dual-5-nbrchange.*down",                                        "high",     "routing",    "EIGRP neighbor down (IOS)"),
    (r"bgp_mgr.*(?:to\s+(?:idle|active|connect)\b|session.*(?:down|fail))", "high", "routing",    "BGP peer down / connect failure"),
    (r"%(?:link-3-updown|lineproto-5-updown).*to\s+down",               "high",     "interface",  "Interface link down"),
    (r"%ethport-5-if_down|%eth_port_channel.*down",                     "high",     "interface",  "Interface link down"),
    (r"\w+_mgr.*oper.*state.*down|srlinux.*port.*down",                 "high",     "interface",  "Interface link down"),
    (r"%sec_login-4-login_failed|%authpriv.*fail",                      "high",     "security",   "Authentication failure"),
    (r"%sysmgr-2-service_crashed|%sysmgr.*(?:crash|terminated)",        "critical", "system",     "NX-OS service crash"),
    (r"%vpc-2-|vpc.*peer.*(?:down|fail)",                               "high",     "lag",        "vPC peer failure (NX-OS)"),
    (r"%hsrp-5-statechange|%fhrp",                                      "high",     "redundancy", "VRRP/gateway failover"),
    (r"%envmon.*(?:fan|temperature|supply)|%platform.*(?:thermal|power)", "critical", "hardware", "Power supply or fan failure"),
    (r"%module-2-|%platform-2-",                                        "critical", "hardware",  "Chassis alarm triggered"),
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
    (r"%(?:link-3-updown|lineproto-5-updown).*to\s+up",                 "medium",   "interface",  "Interface link up"),
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
    (r"%sys-5-config_i|%vshd-5-vshd_syslog_config_i",                   "low",      "config",     "Configuration change committed"),
    (r"%sec_login-5-login_success",                                     "low",      "auth",       "SSH login accepted"),
    (r"lldp.*(?:neighbor|add|delete|update)",                           "low",      "discovery",  "LLDP neighbor change"),
    (r"snmpd|agentx|snmp.*trap",                                        "low",      "monitoring", "SNMP daemon/trap activity"),
    (r"sshd.*(?:disconnect|close|exit)",                                "low",      "auth",       "SSH session disconnected"),
    (r"mgd.*(?:ui_login|ui_commit|cli_command)",                        "low",      "config",     "CLI management activity"),
    (r"alarmd|alarm.*(?:set|clear)",                                    "low",      "hardware",   "Alarm set/clear event"),
    (r"chassisd|craft.*interface",                                      "low",      "hardware",   "Chassis daemon activity"),
    (r"rpd_isis|rpd_ospf|rpd.*(?:start|init|ready)",                    "low",      "routing",    "Routing daemon activity"),
    (r"pfed|dfwd|dcd",                                                  "low",      "system",     "Forwarding daemon activity"),
    (r"inetd|xinetd|ftpd",                                              "low",      "system",     "inetd service activity"),
    (r"(?:arista|strata|eos).*(?:agent|process)",                       "low",      "system",     "EOS agent/process activity"),
    (r"jlaunchd|process.*(?:start|stop|restart)",                       "low",      "system",     "Process lifecycle event"),
    (r"last\s+message\s+repeated",                                      "low",      "system",     "Repeated message suppressed"),
]

SEV_ORDER: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Pre-compile patterns once for speed
_COMPILED: list[tuple[re.Pattern[str], str, str, str]] = [
    (re.compile(p, re.IGNORECASE), s, c, d) for (p, s, c, d) in _KB_PATTERNS
]

# ── Fast-path literal gate ───────────────────────────────────────────────
# In real syslog the vast majority of lines match no KB pattern, yet each one
# paid all ~75 regex scans. The gate below extracts, from every pattern's
# parse tree, a set of literal keywords such that a line CANNOT match the
# pattern without containing one of them. A cheap str-in scan over those
# keywords then decides whether the ordered regex loop needs to run at all.
# Patterns where no literal can be proven stay in an always-checked list, so
# the gate is sound by construction and self-maintains as rules are added.

try:  # Python 3.11+ moved sre_parse under re._parser
    from re import _parser as _sre_parse  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - Python 3.10
    import sre_parse as _sre_parse  # type: ignore[import-not-found]


def _guaranteed_literals(parsed) -> set[str] | None:
    """Lowercase literals, ≥1 of which appears in any match; None = no proof."""
    best: set[str] | None = None
    runs: list[str] = []
    run: list[str] = []

    def _flush() -> None:
        if run:
            runs.append("".join(run))
            run.clear()

    def _prefer(cur: set[str] | None, new: set[str] | None) -> set[str] | None:
        if not new: return cur
        if cur is None: return new
        return new if len(new) < len(cur) else cur

    for op, av in parsed:
        name = op.name
        if name == "LITERAL":
            run.append(chr(av).lower())
            continue
        _flush()
        if name == "SUBPATTERN":  # av = (group, add_flags, del_flags, sub)
            best = _prefer(best, _guaranteed_literals(av[3]))
        elif name == "BRANCH":  # av = (None, [alternatives])
            union: set[str] = set()
            for alt in av[1]:
                alt_lits = _guaranteed_literals(alt)
                if not alt_lits:
                    union = set()
                    break
                union |= alt_lits
            best = _prefer(best, union)
        elif name in ("MAX_REPEAT", "MIN_REPEAT"):  # av = (min, max, item)
            if av[0] >= 1:  # only required (non-optional) repeats guarantee
                best = _prefer(best, _guaranteed_literals(av[2]))
        # IN / ANY / AT / NOT_LITERAL etc. prove nothing — skip
    _flush()

    # Prefer a solid (≥3 char) literal run; else fall back to branch-derived
    # literals (sre hoists common alternation prefixes like '%' into a short
    # run, which would otherwise mask the long per-alternative literals);
    # else settle for the short run.
    solid = [r for r in runs if len(r) >= 3]
    if solid:
        return {max(solid, key=len)}
    if best and all(len(b) >= 3 for b in best):
        return best
    if runs:
        return {max(runs, key=len)}
    return best


_KEYWORDS: tuple[str, ...]
_UNGUARDED: list[tuple[re.Pattern[str], str, str, str]] = []
_kw: set[str] = set()
for _i, (_p, _s, _c, _d) in enumerate(_KB_PATTERNS):
    try:
        _lits = _guaranteed_literals(_sre_parse.parse(_p))
    except Exception:  # unparseable construct — never skip this pattern
        _lits = None
    # Literals under 3 chars match almost every line and would neuter the
    # gate — such patterns go to the always-checked list instead.
    if _lits and all(len(_l) >= 3 for _l in _lits):
        _kw |= _lits
    else:
        _UNGUARDED.append(_COMPILED[_i])
# Prune redundant keywords: if k2 is a substring of k1, any line containing
# k1 also contains k2 — k2 alone suffices for the gate.
_KEYWORDS = tuple(sorted(
    k for k in _kw
    if not any(other != k and other in k for other in _kw)
))

# ── Custom user rules ────────────────────────────────────────────────────
# Loaded from a JSON file (env AI_LOG_ANALYZER_CUSTOM_RULES or add_custom_rules()).
# Custom rules are checked BEFORE the built-in KB so operators can override
# any built-in verdict. They bypass the literal gate — rule counts are small,
# so the extra scans are negligible.
_CUSTOM_RULES: list[tuple[re.Pattern[str], str, str, str]] = []


def add_custom_rules(rules: list[dict]) -> tuple[int, list[str]]:
    """Register user-defined classification rules at runtime.

    Each rule: {"pattern": regex, "severity": critical|high|medium|low|info,
    "category": str, "description": str}. Returns (added_count, errors);
    invalid rules are skipped, never fatal.
    """
    added, errors = 0, []
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            errors.append(f"rule {i}: not an object")
            continue
        pattern = rule.get("pattern", "")
        severity = str(rule.get("severity", "")).lower()
        category = str(rule.get("category", "custom")) or "custom"
        description = str(rule.get("description", "")) or "Custom rule match"
        if severity not in SEV_ORDER:
            errors.append(f"rule {i}: invalid severity {severity!r}")
            continue
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            errors.append(f"rule {i}: bad regex: {exc}")
            continue
        _CUSTOM_RULES.append((compiled, severity, category, description))
        added += 1
    return added, errors


def load_custom_rules_file(path: str) -> tuple[int, list[str]]:
    """Load custom rules from a JSON file: a list of rule objects."""
    import json
    from pathlib import Path
    p = Path(path).expanduser()
    if not p.is_file():
        return 0, [f"custom rules file not found: {p}"]
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return 0, [f"custom rules file unreadable: {exc}"]
    if not isinstance(data, list):
        return 0, ["custom rules file must contain a JSON list"]
    return add_custom_rules(data)


def custom_rules() -> list[dict]:
    """JSON-ready view of the currently registered custom rules."""
    return [
        {"pattern": p.pattern, "severity": s, "category": c, "description": d}
        for (p, s, c, d) in _CUSTOM_RULES
    ]


_rules_path = os.environ.get("AI_LOG_ANALYZER_CUSTOM_RULES", "")
if _rules_path:
    load_custom_rules_file(_rules_path)

# ANSI/VT100 terminal escape sequences — systemd, journald, FRR vtysh, and
# any source piping colored output leaks these into the message field.
# Pattern covers CSI (\x1b[...m), OSC (\x1b]...\x07), and SGR-style codes.
_ANSI_ESCAPE_RE: re.Pattern[str] = re.compile(
    r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])"
)


def strip_ansi(text: str) -> str:
    """Remove ANSI/VT100 escape sequences from log message text.

    systemd boot messages (`\\x1b[0;32m  OK  \\x1b[0m Started ...`), FRR vtysh
    output, and any colorized source leaks raw escape codes that render as
    `[0;32m` / `[0m` garbage in the UI. Stripping at the LogEvent → Classified
    boundary catches every source path with one call.
    """
    if not text or "\x1b" not in text:
        return text
    return _ANSI_ESCAPE_RE.sub("", text)


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
    # How the verdict was reached: 1.0 custom rule, 0.9 KB pattern,
    # 0.6 raw-severity promotion, 0.3 unmatched (description = raw snippet).
    confidence: float = field(default=0.9)

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
            "confidence": self.confidence,
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


def iter_classify(events: Iterable[LogEvent]) -> Iterator[ClassifiedEvent]:
    """Classify a stream of LogEvents lazily, one at a time.

    Pure streaming: no sorting, no counting, O(1) memory regardless of input
    size. Building block for analyze()'s single-pass aggregation; use
    classify_events() when you need the sorted list + counters.
    """
    for ev in events:
        # Strip ANSI escapes once at the boundary — catches systemd green-OK
        # markers, FRR vtysh color codes, and any colorized adapter output.
        clean_message = strip_ansi(ev.message)
        combined = f"{ev.appname} {clean_message}".lower()
        sev, cat, desc = "info", "other", ""
        confidence = 0.9

        # Custom user rules take precedence over the built-in KB.
        for pattern, p_sev, p_cat, p_desc in _CUSTOM_RULES:
            if pattern.search(combined):
                sev, cat, desc = p_sev, p_cat, p_desc
                confidence = 1.0
                break

        if not desc:
            # Literal gate: no keyword → only the unproven patterns can possibly
            # match (their relative order is preserved, so precedence holds).
            if any(k in combined for k in _KEYWORDS):
                candidates = _COMPILED
            else:
                candidates = _UNGUARDED
            for pattern, p_sev, p_cat, p_desc in candidates:
                if pattern.search(combined):
                    sev, cat, desc = p_sev, p_cat, p_desc
                    break

        if not desc:
            snippet = clean_message[:120].strip() or ev.appname or "General log message"
            desc = snippet
            confidence = 0.3

        # Promote raw severity if syslog says critical but classifier missed it
        if ev.severity_raw.lower() in ("crit", "emerg", "alert") and sev == "info":
            sev = "high"
            confidence = 0.6

        yield ClassifiedEvent(
            timestamp=ev.timestamp,
            hostname=ev.hostname.split(".")[0] if ev.hostname else "",
            appname=ev.appname,
            severity=sev,
            severity_raw=ev.severity_raw,
            category=cat,
            description=desc,
            action=_action_for(sev, cat),
            message=clean_message[:500],
            sample_message=clean_message[:200],
            confidence=confidence,
        )


def classify_events(events: Iterable[LogEvent]) -> tuple[list[ClassifiedEvent], dict[str, int], dict[str, int]]:
    """Classify a stream of LogEvents.

    Returns: (sorted classified events, severity_counts, category_counts).
    Sort order: critical → high → medium → low → info, then by timestamp desc.

    Materializes the full list — fine for bounded inputs (API fetches, lab
    logs). For huge files, analyze() streams via iter_classify() instead.
    """
    classified: list[ClassifiedEvent] = []
    sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    cat_counts: dict[str, int] = {}

    for ce in iter_classify(events):
        classified.append(ce)
        sev_counts[ce.severity] = sev_counts.get(ce.severity, 0) + 1
        cat_counts[ce.category] = cat_counts.get(ce.category, 0) + 1

    # Stable sort: pass 1 sorts newest first by ISO timestamp; pass 2 buckets by severity.
    classified.sort(key=lambda e: e.timestamp, reverse=True)
    classified.sort(key=lambda e: SEV_ORDER.get(e.severity, 5))
    return classified, sev_counts, cat_counts

