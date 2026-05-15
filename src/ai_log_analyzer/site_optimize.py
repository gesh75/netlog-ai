"""Site-wide optimization advisor — strategic gap analysis.

Different from `analyzer.analyze_site()` (which finds cross-device DRIFT) — this
module produces a strategic roadmap: "what does this site need to become a
production-grade Tier-1 datacenter?"

Architecture:
    deterministic extraction → deterministic baseline recommendations →
    optional LLM enhancement → strict schema validation → safe response

Even when the LLM is disabled or fails, this module produces a useful baseline
gap analysis derived purely from configuration facts. The LLM only enriches
that baseline — it never replaces it without validation.
"""
from __future__ import annotations

import json
import re
from collections import Counter

from ai_log_analyzer import compliance, llm, site_diagram, site_doc


# Roles considered ISP-gateways (firewalls or WAN routers)
_GATEWAY_ROLES: frozenset[str] = frozenset({"firewall", "router", "gateway"})
_GATEWAY_HOSTNAME_TOKENS: frozenset[str] = frozenset({"fw", "rt", "gw"})
_HOSTNAME_SPLIT_RE = re.compile(r"[-_.]")


def _is_gateway_device(d: dict) -> bool:
    """Whether a device should be scanned for ISP profiles.

    Reuses site_doc._detect_role() when no explicit role is set, and splits
    hostnames on `[-_.]` boundaries to avoid substring false positives
    (e.g. `artemis-switch` no longer matches `rt`).
    """
    hostname = str(d.get("hostname", "")).lower()
    explicit_role = str(d.get("role", "")).lower()
    inferred_role, _ = site_doc._detect_role(hostname)
    role = explicit_role or inferred_role
    if role in _GATEWAY_ROLES:
        return True
    parts = _HOSTNAME_SPLIT_RE.split(hostname)
    return any(part in _GATEWAY_HOSTNAME_TOKENS for part in parts)


def _extend_unique(target: list, values: list) -> None:
    """In-place extend `target` with items from `values`, skipping duplicates."""
    seen = set(target)
    for v in values:
        if v in seen:
            continue
        target.append(v)
        seen.add(v)


def _neighbor_remote_as(n) -> str:
    """Tolerant access to a BGP neighbor's remote AS (dict or dataclass)."""
    if isinstance(n, dict):
        return str(n.get("remote_as", ""))
    return str(getattr(n, "remote_as", ""))


# Tighter BFD detection — anchored to config statements, not interface descriptions
_RE_BFD = re.compile(
    r"^\s*(?:"
    r"set\s+protocols\s+bgp[\s\S]{0,200}?\bbfd\b|"
    r"neighbor\s+\S+[\s\S]{0,100}?\bbfd\b|"
    r"bfd\s+(?:interval|liveness-detection|all-interfaces)\b"
    r")",
    re.I | re.M,
)


def _bfd_used(devices: list[dict]) -> bool:
    return any(_RE_BFD.search(d.get("config_text", "")) for d in devices)


# ─────────────────────────────────────────────────────────────────────────────
# Site facts aggregator
# ─────────────────────────────────────────────────────────────────────────────

def _aggregate_profiles(profiles: list) -> dict:
    """Single-pass aggregation over all device profiles.

    Collapses 8+ separate `for p in profiles` loops into one walk. A second
    short pass classifies BGP neighbors as iBGP/eBGP — that needs the full
    `asns_local` set before it can run.
    """
    result: dict = {
        "has_evpn": False, "has_vxlan": False, "has_ospf": False,
        "has_isis": False, "has_advpn": False, "has_ha": False,
        "devs_no_ntp": [], "devs_no_syslog": [],
        "devs_no_aaa": [], "devs_snmpv2c": [],
        "total_bgp": 0, "ibgp": 0, "ebgp": 0,
        "asns_local": set(), "versions": Counter(),
        "risky": [], "by_role": Counter(),
        "all_wan_ips": [],
    }
    seen_ip: set[str] = set()

    for p in profiles:
        hn = p.hostname
        result["by_role"][p.role] += 1

        # Protocols (short-circuit OR — coerce truthiness via bool())
        result["has_evpn"] = result["has_evpn"] or bool(p.evpn_enabled)
        result["has_vxlan"] = result["has_vxlan"] or p.vxlan_vni_count > 0
        result["has_ospf"] = result["has_ospf"] or bool(p.ospf_areas)
        result["has_isis"] = result["has_isis"] or bool(p.isis_enabled)
        result["has_advpn"] = result["has_advpn"] or bool(p.advpn)
        result["has_ha"] = result["has_ha"] or bool(p.chassis_cluster)

        # Operations posture
        if not p.ntp_servers:
            result["devs_no_ntp"].append(hn)
        if not p.syslog_hosts:
            result["devs_no_syslog"].append(hn)
        if not p.radius_servers and not p.tacacs_servers:
            result["devs_no_aaa"].append(hn)
        if p.snmp_v2c_present:
            result["devs_snmpv2c"].append(hn)

        # WAN IPs (deduplicated)
        for w in p.wan_ips:
            if w.ip not in seen_ip:
                seen_ip.add(w.ip)
                result["all_wan_ips"].append(w)

        # BGP footprint
        if p.local_asn:
            result["asns_local"].add(p.local_asn)
        result["total_bgp"] += len(p.bgp_neighbors)

        # Software risk — use cached lifecycle from site_doc.extract_profile()
        if p.software_version:
            result["versions"][p.software_version] += 1
            _, _, status = p.lifecycle if p.lifecycle != ("", "", "") \
                else site_doc.lifecycle_for(p.software_version, p.platform)
            if "🔴" in status or "🟠" in status:
                result["risky"].append({
                    "device": hn, "version": p.software_version,
                    "platform": p.platform, "status": status,
                })

    # BGP iBGP/eBGP classification — needs complete asns_local set
    for p in profiles:
        for n in p.bgp_neighbors:
            remote_as = _neighbor_remote_as(n)
            if remote_as in result["asns_local"]:
                result["ibgp"] += 1
            else:
                result["ebgp"] += 1

    return result


def _build_isp_map(devices: list[dict], all_wan: list) -> dict:
    """Build name -> ISP profile map from gateway devices only.

    Merges duplicate ISP records discovered on multiple devices, deduplicating
    interfaces and public IPs, and conservatively flagging shutdown status.
    """
    isp_map: dict = {}
    for d in devices:
        if not _is_gateway_device(d):
            continue
        for prof in site_diagram.extract_isp_profiles(
            d.get("config_text", ""), d.get("platform", "junos"), all_wan,
        ):
            existing = isp_map.get(prof.name)
            if existing is None:
                isp_map[prof.name] = prof
                continue
            _extend_unique(existing.interfaces, prof.interfaces)
            _extend_unique(existing.public_ips, prof.public_ips)
            if prof.asn and not existing.asn:
                existing.asn = prof.asn
            # Conservative: any matching profile that says shutdown wins
            if prof.status == "shutdown":
                existing.status = "shutdown"
            elif prof.status == "active" and existing.status not in {"shutdown", "active"}:
                existing.status = "active"
    return isp_map


def collect_site_facts(site_id: str, devices: list[dict]) -> dict:
    """Build a structured summary of the site — pure pattern matching, no LLM.

    This becomes the LLM's input context for strategic analysis. All collections
    are sorted to keep API responses and tests stable.
    """
    profiles = [site_doc.extract_profile(d["hostname"], d.get("platform", "junos"),
                                          d.get("config_text", "")) for d in devices]
    site_doc.assign_role_descriptions(profiles)

    # VLAN aggregation
    vlans = site_diagram.merge_vlans([p.vlans for p in profiles])
    vlan_cats = Counter(v.category for v in vlans.values())

    # Single-pass over profiles
    agg = _aggregate_profiles(profiles)

    # ISP profiles need consolidated WAN list
    isp_map = _build_isp_map(devices, agg["all_wan_ips"])
    isps = list(isp_map.values())

    # Compliance
    comp = compliance.check_bundle(devices)

    wan_interfaces = sorted({
        w.interface for w in agg["all_wan_ips"] if getattr(w, "interface", None)
    })[:10]

    return {
        "site_id": site_id.upper(),
        "device_count": len(profiles),
        "by_role": dict(agg["by_role"]),
        "devices": [
            {"hostname": p.hostname, "role": p.role,
             "platform": p.platform, "version": p.software_version,
             "role_description": p.role_description}
            for p in sorted(profiles, key=lambda x: x.hostname)
        ],
        "vlans": {
            "total": len(vlans),
            "by_category": dict(vlan_cats),
        },
        "wan": {
            "public_ip_count": len(agg["all_wan_ips"]),
            "interfaces": wan_interfaces,
        },
        "isps": [
            {"name": i.name, "status": i.status, "asn": i.asn,
             "interfaces": sorted(set(i.interfaces)),
             "public_ips_count": len(set(i.public_ips))}
            for i in sorted(isps, key=lambda x: x.name.lower())
        ],
        "isp_count_active": sum(1 for i in isps if i.status == "active"),
        "software": {
            "distinct_versions": len(agg["versions"]),
            "version_breakdown": dict(agg["versions"]),
            "risky_devices": agg["risky"],
        },
        "bgp": {
            "total_neighbors": agg["total_bgp"],
            "ibgp_sessions": agg["ibgp"],
            "ebgp_sessions": agg["ebgp"],
            "asns_local": sorted(agg["asns_local"]),
            "bfd_used_anywhere": _bfd_used(devices),
        },
        "protocols": {
            "ospf": agg["has_ospf"], "isis": agg["has_isis"],
            "evpn": agg["has_evpn"], "vxlan": agg["has_vxlan"],
            "advpn": agg["has_advpn"], "chassis_cluster_ha": agg["has_ha"],
        },
        "operations": {
            "devices_without_ntp": sorted(agg["devs_no_ntp"]),
            "devices_without_syslog": sorted(agg["devs_no_syslog"]),
            "devices_without_aaa": sorted(agg["devs_no_aaa"]),
            "devices_with_snmp_v2c": sorted(agg["devs_snmpv2c"]),
        },
        "compliance": {
            "passed": comp["passed"],
            "failed": comp["failed"],
            "pass_rate": comp["pass_rate"],
            "failing_rules": [r["rule_id"] for r in comp["rules"] if r["fail"] > 0],
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# Deterministic baseline advisor (used when LLM disabled or fails)
# ─────────────────────────────────────────────────────────────────────────────

_SEVERITY_RANK: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_ROI_RANK: dict[str, int] = {"high": 0, "medium": 1, "low": 2}

_VALID_SEVERITIES: frozenset[str] = frozenset(_SEVERITY_RANK)
_VALID_ROIS: frozenset[str] = frozenset(_ROI_RANK)
_VALID_CATEGORIES: frozenset[str] = frozenset({
    "isp_redundancy", "ha", "software_lifecycle", "bgp_tuning", "overlay_fabric",
    "security", "monitoring", "aaa", "compliance", "capacity",
})


def _infer_tier(facts: dict) -> str:
    roles = facts["by_role"]
    if (roles.get("firewall", 0) >= 2
            and roles.get("switch", 0) >= 4
            and facts["isp_count_active"] >= 2):
        return "Tier 1"
    if roles.get("firewall", 0) >= 1 and roles.get("switch", 0) >= 2:
        return "Tier 2"
    if facts["device_count"] <= 3:
        return "Branch"
    return "Tier 3"


def _score_maturity(gaps: list[dict]) -> int:
    score = 100
    penalty = {"critical": 20, "high": 12, "medium": 7, "low": 3}
    for g in gaps:
        score -= penalty.get(g.get("severity", "medium"), 5)
    return max(0, min(100, score))


def _build_roadmap(gaps: list[dict]) -> dict:
    def starts_with(eff: str, prefixes: tuple[str, ...]) -> bool:
        return any(eff.startswith(p) for p in prefixes)

    return {
        "phase_1_immediate_0_30_days": [
            g["title"] for g in gaps
            if g["severity"] in {"critical", "high"}
            and starts_with(g.get("estimated_effort", "M"), ("S", "M"))
        ],
        "phase_2_short_term_30_90_days": [
            g["title"] for g in gaps
            if g["severity"] in {"critical", "high"}
            and starts_with(g.get("estimated_effort", "M"), ("L", "XL"))
        ],
        "phase_3_medium_term_90_180_days": [
            g["title"] for g in gaps if g["severity"] == "medium"
        ],
        "phase_4_long_term_6_12_months": [
            g["title"] for g in gaps if g["severity"] == "low"
        ],
    }


def _collect_deterministic_gaps(facts: dict) -> tuple[list[dict], list[str]]:
    """Returns (gaps, best_practices_applied) from pure config facts."""
    gaps: list[dict] = []
    applied: list[str] = []

    # ISP redundancy
    if facts["isp_count_active"] >= 2:
        applied.append("Multiple active ISP profiles detected.")
    elif facts["isp_count_active"] < 2:
        gaps.append({
            "category": "isp_redundancy",
            "severity": "critical",
            "title": "Add redundant active ISP connectivity",
            "current_state": f"{facts['isp_count_active']} active ISP profile(s) detected.",
            "ideal_state": "At least two diverse active ISPs with independent physical paths and eBGP sessions.",
            "rationale": "Single-ISP sites have elevated outage exposure during carrier failures or maintenance.",
            "implementation": [
                "Order diverse secondary ISP circuit.",
                "Configure eBGP with route policy and prefix filtering.",
                "Test failover and document operational runbook.",
            ],
            "config_changes": {},
            "estimated_effort": "L (1-4 weeks)",
            "roi": "high",
            "requires_human_review": True,
        })

    # Software lifecycle
    risky = facts["software"]["risky_devices"]
    if risky:
        devices_summary = ", ".join(
            f"{r['device']} {r['version']}" for r in risky[:6])
        gaps.append({
            "category": "software_lifecycle",
            "severity": "high",
            "title": "Upgrade EOL or limited-support network software",
            "current_state": f"Risky software detected on: {devices_summary}.",
            "ideal_state": "All production devices run supported vendor-recommended LTS releases.",
            "rationale": "Unsupported software increases security, stability, and vendor escalation risk.",
            "implementation": [
                "Select target LTS release per platform.",
                "Stage upgrades on secondary or non-critical nodes first.",
                "Validate control-plane, data-plane, and rollback procedures.",
            ],
            "config_changes": {},
            "estimated_effort": "M (1-5 days)",
            "roi": "high",
            "requires_human_review": True,
        })
    else:
        applied.append("No EOL or limited-support software detected.")

    ops = facts["operations"]

    if ops["devices_with_snmp_v2c"]:
        gaps.append({
            "category": "monitoring",
            "severity": "high",
            "title": "Migrate SNMPv2c monitoring to SNMPv3",
            "current_state": f"SNMPv2c detected on: {', '.join(ops['devices_with_snmp_v2c'])}.",
            "ideal_state": "Use SNMPv3 with authentication and privacy on all devices.",
            "rationale": "SNMPv2c community strings are clear-text and create credential exposure risk.",
            "implementation": [
                "Create SNMPv3 users/groups.",
                "Update monitoring collectors.",
                "Remove SNMPv2c communities after validation.",
            ],
            "config_changes": {},
            "estimated_effort": "S (≤1 day)",
            "roi": "high",
            "requires_human_review": True,
        })

    if ops["devices_without_syslog"]:
        gaps.append({
            "category": "monitoring",
            "severity": "medium",
            "title": "Enable centralized remote syslog",
            "current_state": f"No remote syslog detected on: {', '.join(ops['devices_without_syslog'][:8])}.",
            "ideal_state": "All devices forward logs to redundant centralized collectors.",
            "rationale": "Without remote logging, incident evidence may be lost during reboots or outages.",
            "implementation": [
                "Deploy or confirm redundant syslog collectors.",
                "Configure all devices to forward auth, system, and routing logs.",
                "Validate log ingestion and alerting.",
            ],
            "config_changes": {},
            "estimated_effort": "S (≤1 day)",
            "roi": "high",
            "requires_human_review": True,
        })

    if ops["devices_without_ntp"]:
        gaps.append({
            "category": "monitoring",
            "severity": "medium",
            "title": "Standardize NTP across all devices",
            "current_state": f"No NTP detected on: {', '.join(ops['devices_without_ntp'][:8])}.",
            "ideal_state": "All devices use redundant authenticated NTP sources.",
            "rationale": "Consistent time is required for logs, incident response, and routing event correlation.",
            "implementation": [
                "Define two or more approved NTP servers.",
                "Configure devices by platform.",
                "Validate time synchronization and timezone settings.",
            ],
            "config_changes": {},
            "estimated_effort": "S (≤1 day)",
            "roi": "medium",
            "requires_human_review": True,
        })

    if ops["devices_without_aaa"]:
        gaps.append({
            "category": "aaa",
            "severity": "high",
            "title": "Implement centralized AAA",
            "current_state": f"No RADIUS/TACACS detected on: {', '.join(ops['devices_without_aaa'][:8])}.",
            "ideal_state": "All devices use centralized AAA with local break-glass fallback.",
            "rationale": "Centralized AAA improves access control, auditability, and offboarding safety.",
            "implementation": [
                "Integrate devices with TACACS/RADIUS.",
                "Define role-based command authorization.",
                "Test local fallback access.",
            ],
            "config_changes": {},
            "estimated_effort": "M (1-5 days)",
            "roi": "high",
            "requires_human_review": True,
        })

    # BGP tuning
    if facts["bgp"]["total_neighbors"] > 0 and not facts["bgp"]["bfd_used_anywhere"]:
        gaps.append({
            "category": "bgp_tuning",
            "severity": "medium",
            "title": "Enable BFD for faster BGP failure detection",
            "current_state": f"{facts['bgp']['total_neighbors']} BGP neighbor(s) detected; BFD not detected.",
            "ideal_state": "Critical eBGP/iBGP sessions use BFD and documented timer policies.",
            "rationale": "BFD reduces convergence time after link or peer failure.",
            "implementation": [
                "Identify critical BGP peers.",
                "Enable BFD with conservative timers.",
                "Test failover under maintenance window.",
            ],
            "config_changes": {},
            "estimated_effort": "M (1-5 days)",
            "roi": "medium",
            "requires_human_review": True,
        })

    # Positive signals
    if facts["protocols"]["chassis_cluster_ha"]:
        applied.append("Firewall chassis-cluster HA detected.")
    if facts["bgp"]["bfd_used_anywhere"]:
        applied.append("BFD detected in the site configuration.")
    if not ops["devices_without_ntp"]:
        applied.append("NTP appears configured across all devices.")
    if not ops["devices_without_syslog"]:
        applied.append("Remote syslog appears configured across all devices.")
    if facts["protocols"]["advpn"]:
        applied.append("ADVPN inter-site VPN configured.")
    if facts["protocols"]["evpn"] or facts["protocols"]["vxlan"]:
        applied.append("Modern overlay fabric (EVPN/VXLAN) in use.")

    # Sort gaps by (severity, roi) and cap at 8
    gaps.sort(key=lambda g: (
        _SEVERITY_RANK.get(g["severity"], 9),
        _ROI_RANK.get(g["roi"], 9),
    ))
    return gaps[:8], applied


def _build_deterministic_summary(facts: dict, gaps: list[dict], tier: str) -> str:
    if gaps:
        top = gaps[0]["title"]
        return (
            f"{facts['site_id']} currently assesses as {tier}. "
            f"The highest-priority strategic gap is: {top}. "
            "Address critical resilience, lifecycle, and operations gaps before "
            "treating the site as production-grade Tier-1."
        )
    return (
        f"{facts['site_id']} currently assesses as {tier}. "
        "No major strategic gaps were detected from available configuration facts. "
        "Validate against DCIM, circuit inventory, and operational runbooks."
    )


def _deterministic_advice(site_id: str, facts: dict) -> dict:
    """Pure rule-based gap analysis — runs when LLM is disabled or unavailable."""
    gaps, applied = _collect_deterministic_gaps(facts)
    tier = _infer_tier(facts)
    return {
        "site_id": site_id.upper(),
        "site_summary": _build_deterministic_summary(facts, gaps, tier),
        "maturity_score": _score_maturity(gaps),
        "maturity_tier": tier,
        "best_practices_applied": applied,
        "best_practices_missing": [g["title"] for g in gaps],
        "gaps": gaps,
        "roadmap": _build_roadmap(gaps),
        "llm_powered": False,
        "facts": facts,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Schema validation for LLM output
# ─────────────────────────────────────────────────────────────────────────────

def _validate_analysis(obj: dict | None) -> dict | None:
    """Lightweight dict validator — coerces types, drops malformed gaps, caps lists.

    Returns None if obj is not a dict. Always returns a normalized shape with
    sensible defaults. This avoids returning unvalidated LLM output to clients.
    """
    if not isinstance(obj, dict):
        return None

    out: dict = {
        "site_summary": str(obj.get("site_summary") or ""),
        "maturity_score": 0,
        "maturity_tier": "Unknown",
        "best_practices_applied": [],
        "best_practices_missing": [],
        "gaps": [],
        "roadmap": {},
    }

    # maturity_score: int in [0, 100]
    try:
        score = int(obj.get("maturity_score") or 0)
        out["maturity_score"] = max(0, min(100, score))
    except (TypeError, ValueError):
        pass

    if isinstance(obj.get("maturity_tier"), str):
        out["maturity_tier"] = obj["maturity_tier"]

    for list_key in ("best_practices_applied", "best_practices_missing"):
        raw = obj.get(list_key) or []
        if isinstance(raw, list):
            out[list_key] = [str(x) for x in raw if isinstance(x, (str, int, float))]

    # Gaps — validate each entry, drop malformed, sort by (severity, roi), cap 8
    raw_gaps = obj.get("gaps") or []
    if isinstance(raw_gaps, list):
        out["gaps"] = _validate_gaps(raw_gaps)

    # Roadmap
    raw_road = obj.get("roadmap") or {}
    if isinstance(raw_road, dict):
        out["roadmap"] = {
            k: [str(x) for x in v if isinstance(x, (str, int, float))]
            for k, v in raw_road.items()
            if isinstance(v, list)
        }

    return out


def _validate_gaps(raw: list) -> list[dict]:
    valid: list[dict] = []
    for g in raw:
        if not isinstance(g, dict):
            continue
        severity = str(g.get("severity") or "medium").lower()
        if severity not in _VALID_SEVERITIES:
            severity = "medium"
        roi = str(g.get("roi") or "medium").lower()
        if roi not in _VALID_ROIS:
            roi = "medium"
        category = str(g.get("category") or "compliance").lower()
        if category not in _VALID_CATEGORIES:
            category = "compliance"

        impl = g.get("implementation") or []
        if not isinstance(impl, list):
            impl = []
        impl = [str(x) for x in impl if isinstance(x, (str, int, float))][:5]

        changes = g.get("config_changes") or {}
        if not isinstance(changes, dict):
            changes = {}
        clean_changes: dict[str, list[str]] = {}
        for host, cmds in changes.items():
            if not isinstance(cmds, list):
                continue
            clean_changes[str(host)] = [
                str(c) for c in cmds if isinstance(c, (str, int, float))
            ][:20]

        valid.append({
            "category": category,
            "severity": severity,
            "title": str(g.get("title") or "(no title)"),
            "current_state": str(g.get("current_state") or ""),
            "ideal_state": str(g.get("ideal_state") or ""),
            "rationale": str(g.get("rationale") or ""),
            "implementation": impl,
            "config_changes": clean_changes,
            "estimated_effort": str(g.get("estimated_effort") or "M (1-5 days)"),
            "roi": roi,
            "requires_human_review": True,  # always set — LLM commands are illustrative
        })

    valid.sort(key=lambda g: (
        _SEVERITY_RANK.get(g["severity"], 9),
        _ROI_RANK.get(g["roi"], 9),
    ))
    return valid[:8]


# ─────────────────────────────────────────────────────────────────────────────
# LLM-driven strategic analyzer
# ─────────────────────────────────────────────────────────────────────────────

_SITE_WIDE_SYSTEM_PROMPT = """You are a principal network architect performing a strategic optimization review of an entire datacenter site.

You are given a JSON FACT SUMMARY of the site (device inventory, ISP count, software versions with EOL flags, BGP footprint, protocol usage, operations posture, compliance score). Your job: identify what this site NEEDS to become production-grade, prioritized by ROI.

This is DIFFERENT from finding inconsistencies (drift) — focus on STRATEGIC GAPS:
  • Is ISP redundancy adequate? (single ISP = critical exposure)
  • Are BGP sessions tuned for sub-second convergence (BFD, timers, graceful-restart)?
  • Is software within supported lifecycle (no 🔴/🟠 versions)?
  • Is HA in place where it should be (firewall pair, EVPN-VXLAN spine pair)?
  • Are operations basics covered (centralized syslog, NTP, AAA, SNMPv3)?
  • Are best-practice protocols enabled (overlay fabric for scale, ADVPN for inter-site)?
  • Are there security gaps (zones, SSH hardening, mgmt-plane ACLs)?

Output STRICT JSON only. No markdown fences, no comments, no preamble, no trailing text. Start with `{` end with `}`.

Required shape:

{
  "site_summary": "2-3 sentence strategic posture.",
  "maturity_score": 0,
  "maturity_tier": "Tier 1",
  "best_practices_applied": [],
  "best_practices_missing": [],
  "gaps": [
    {
      "category": "isp_redundancy",
      "severity": "critical",
      "title": "Short gap title",
      "current_state": "Specific facts from input.",
      "ideal_state": "Target state.",
      "rationale": "Business or operational rationale.",
      "implementation": ["step 1", "step 2", "step 3"],
      "config_changes": {
        "hostname": ["vendor command 1", "vendor command 2"]
      },
      "estimated_effort": "M (1-5 days)",
      "roi": "high"
    }
  ],
  "roadmap": {
    "phase_1_immediate_0_30_days": [],
    "phase_2_short_term_30_90_days": [],
    "phase_3_medium_term_90_180_days": [],
    "phase_4_long_term_6_12_months": []
  }
}

Constraints:
1. MAX 8 gaps. Sort by severity then by ROI.
2. Each gap MUST cite specific facts from the input (device names, counts, versions).
3. If unsure of exact vendor syntax, leave `config_changes` empty and describe the change in `implementation`. Do not hallucinate commands.
4. Never include destructive commands (no `delete`, `request system reboot`, `write erase`, etc.).
5. Don't repeat compliance findings as gaps unless strategic.
6. Roadmap entries reference gap titles from gaps[] verbatim.
7. Effort scale: S=hours, M=days, L=weeks, XL=months.

Note: config_changes are ILLUSTRATIVE EXAMPLES ONLY. Network engineers will review before applying."""


def _build_user_prompt(facts: dict) -> str:
    return (
        f"SITE FACT SUMMARY:\n```json\n{json.dumps(facts, indent=2)}\n```\n\n"
        "Produce the strategic optimization JSON now. "
        "Focus on the 5-8 highest-impact gaps for this site's tier."
    )


def _build_retry_prompt(facts: dict) -> str:
    return (
        f"SITE FACT SUMMARY:\n```json\n{json.dumps(facts, indent=2)}\n```\n\n"
        "PREVIOUS RESPONSE WAS INVALID OR TRUNCATED.\n"
        "Re-emit ONLY the JSON object. Keep `rationale` ≤ 1 sentence and "
        "`implementation` ≤ 3 steps per gap. Cap at 6 gaps total. "
        "Start with `{` end with `}`. No fences. No preamble."
    )


def _failure_response(
    site_id: str,
    facts: dict,
    summary: str,
    *,
    llm_powered: bool = False,
    extra: dict | None = None,
) -> dict:
    """Single factory for all failure-path responses — keeps shape consistent."""
    base = {
        "site_id": site_id.upper(),
        "site_summary": summary,
        "maturity_score": 0,
        "maturity_tier": "Unknown",
        "best_practices_applied": [],
        "best_practices_missing": [],
        "gaps": [],
        "roadmap": {},
        "llm_powered": llm_powered,
        "facts": facts,
    }
    if extra:
        base.update(extra)
    return base


def _safe_llm_query(system: str, user: str, max_tokens: int) -> tuple[str, str | None]:
    """Call llm.query() with exception handling.

    Returns (text, error_class_name). On success, error is None.
    """
    try:
        text = llm.query(system, user, max_tokens=max_tokens) or ""
        return text, None
    except Exception as exc:
        return "", type(exc).__name__


def analyze_site_wide(site_id: str, devices: list[dict]) -> dict:
    """Strategic optimization analysis.

    Always returns useful advice — falls back to deterministic rule-based gaps
    when the LLM is disabled, errors out, or returns malformed JSON.
    """
    facts = collect_site_facts(site_id, devices)

    if not llm.get_state().get("enabled", False):
        result = _deterministic_advice(site_id, facts)
        result["site_summary"] = (
            "LLM disabled — deterministic rule-based advice only. " + result["site_summary"]
        )
        return result

    # First attempt
    text, err = _safe_llm_query(_SITE_WIDE_SYSTEM_PROMPT, _build_user_prompt(facts),
                                  max_tokens=8192)
    last_text = text
    if err:
        result = _deterministic_advice(site_id, facts)
        result["site_summary"] = f"LLM call failed ({err}). " + result["site_summary"]
        result["llm_error"] = err
        return result

    parsed = _try_parse_json(text) if text else None
    validated = _validate_analysis(parsed)

    # Retry once with a stricter prompt
    if not validated:
        text2, err2 = _safe_llm_query(_SITE_WIDE_SYSTEM_PROMPT, _build_retry_prompt(facts),
                                        max_tokens=4096)
        if text2:
            last_text = text2
            parsed = _try_parse_json(text2)
            validated = _validate_analysis(parsed)
        if err2 and not validated:
            result = _deterministic_advice(site_id, facts)
            result["site_summary"] = f"LLM retry failed ({err2}). " + result["site_summary"]
            result["llm_error"] = err2
            return result

    if not last_text:
        result = _deterministic_advice(site_id, facts)
        result["site_summary"] = "LLM returned empty response. " + result["site_summary"]
        return result

    if not validated:
        result = _deterministic_advice(site_id, facts)
        result["site_summary"] = (
            "LLM returned malformed JSON — using deterministic baseline. "
            + result["site_summary"]
        )
        result["llm_parse_failed"] = True
        result["raw"] = last_text[:6000]
        result["raw_length"] = len(last_text)
        return result

    # Success path: validated LLM output enriched with site metadata
    validated.update({
        "site_id": site_id.upper(),
        "llm_powered": True,
        "facts": facts,
    })
    return validated


# ─────────────────────────────────────────────────────────────────────────────
# Tolerant JSON parser (handles truncation / fences / prose wrapping)
# ─────────────────────────────────────────────────────────────────────────────

def _parse_if_dict(text: str) -> dict | None:
    """Try to parse text as JSON; return only if result is a dict."""
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except (json.JSONDecodeError, ValueError):
        return None


def _json_closure_stack(s: str) -> list[str]:
    """Compute the list of unclosed bracket closers for a (partial) JSON string."""
    in_str = False
    esc = False
    stack: list[str] = []
    for c in s:
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c == "{":
            stack.append("}")
        elif c == "[":
            stack.append("]")
        elif c in "}]":
            if stack and stack[-1] == c:
                stack.pop()
    return stack


def _walk_for_safe_comma(s: str, *, target_depth: int = 1) -> int:
    """Return the last comma index at exactly the given JSON depth, -1 if none."""
    in_str = False
    esc = False
    depth = 0
    last_safe = -1
    for i, c in enumerate(s):
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c in "{[":
            depth += 1
        elif c in "}]":
            depth -= 1
        elif c == "," and depth == target_depth:
            last_safe = i
    return last_safe


def _try_parse_json(text: str) -> dict | None:
    """Tolerant JSON parser — handles markdown fences, embedded JSON, and
    truncated responses (open strings, trailing commas, unbalanced brackets)."""
    cleaned = re.sub(r"^```[a-z]*\n?", "", text.strip())
    cleaned = re.sub(r"\n?```\s*$", "", cleaned.strip())

    # Fast path: clean JSON
    if result := _parse_if_dict(cleaned):
        return result

    # Try the outermost { ... } substring
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start != -1 and end > start:
        if result := _parse_if_dict(cleaned[start:end + 1]):
            return result

    if start == -1:
        return None

    return _repair_truncated_json(cleaned[start:])


def _repair_truncated_json(s: str) -> dict | None:
    """Close open strings/brackets, strip trailing junk, then retry parse.

    If that still fails, repeatedly drop the trailing element (last comma at
    shallowest open depth) and re-close until JSON is valid or no commas remain.
    Crucially, the bracket stack is RECOMPUTED after each truncation rather
    than being reused — keeps the stack consistent with the truncated text.
    """
    out: list[str] = []
    in_string = False
    escape = False
    last_value_end = 0  # index in `out` after a complete value

    for ch in s:
        out.append(ch)
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
                last_value_end = len(out)
        else:
            if ch == '"':
                in_string = True
            elif ch in "{[":
                pass  # stack handled by _json_closure_stack on the final string
            elif ch in "}]":
                last_value_end = len(out)
            elif ch in "0123456789tnef":
                last_value_end = len(out)

    # Dropped mid-string? Rewind to last complete value
    if in_string:
        out = out[:last_value_end]

    # Strip trailing whitespace / commas / colons before re-closing
    while out and out[-1] in " \t\r\n,:":
        out.pop()

    # Recompute stack from the (possibly truncated) buffer — keeps it consistent
    base = "".join(out)
    stack = _json_closure_stack(base)
    candidate = base + "".join(reversed(stack))

    if result := _parse_if_dict(candidate):
        return result

    # Last-ditch: shed trailing elements at depth=1 (top of root object)
    for _ in range(20):
        last_safe = _walk_for_safe_comma(candidate, target_depth=1)
        if last_safe < 0:
            return None
        candidate = candidate[:last_safe]
        tail = "".join(reversed(_json_closure_stack(candidate)))
        if result := _parse_if_dict(candidate + tail):
            return result
    return None
