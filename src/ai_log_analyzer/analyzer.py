"""High-level analysis pipeline: classify → phased action items → health → exec summary."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ai_log_analyzer import kb, llm
from ai_log_analyzer.classifier import (
    SEV_ORDER,
    ClassifiedEvent,
    LogEvent,
    classify_events,
)
from ai_log_analyzer.sanitize import sanitize


# Recovery events are classified as medium because they're useful in the
# timeline view, but they should NEVER produce action items / runbooks —
# they describe healing, not incidents.
_RECOVERY_DESCRIPTIONS: frozenset[str] = frozenset({
    "Interface link up",
    "BGP peer established",
    "OSPF neighbor established",
    "LAG member joining bundle",
})


@dataclass
class ActionItem:
    severity: str
    category: str
    description: str
    count: int
    devices: list[str]
    sample_messages: list[str]
    deep_analysis: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "count": self.count,
            "devices": self.devices,
            "sample_messages": self.sample_messages,
            "deep_analysis": self.deep_analysis,
        }


@dataclass
class AnalysisResult:
    score: int
    grade: str
    grade_label: str
    severity_counts: dict[str, int]
    category_counts: dict[str, int]
    action_items: list[ActionItem]
    top_devices: list[dict]
    classified_events: list[ClassifiedEvent]
    executive_summary: list[str]
    llm_powered: bool
    generated_at: str

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "grade": self.grade,
            "grade_label": self.grade_label,
            "severity_counts": self.severity_counts,
            "category_counts": self.category_counts,
            "action_items": [a.to_dict() for a in self.action_items],
            "top_devices": self.top_devices,
            "classified_events": [e.to_dict() for e in self.classified_events],
            "executive_summary": self.executive_summary,
            "llm_powered": self.llm_powered,
            "generated_at": self.generated_at,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Health score
# ─────────────────────────────────────────────────────────────────────────────

def health_score(sev_counts: dict[str, int], external_alerts: int = 0) -> tuple[int, str, str]:
    """Compute 0–100 score and A–F grade."""
    score = 100
    score -= min(sev_counts.get("critical", 0) * 5, 40)
    score -= min(sev_counts.get("high", 0) * 2, 30)
    score -= min(sev_counts.get("medium", 0) * 1, 15)
    score -= min(external_alerts * 3, 15)
    score = max(0, min(100, score))

    if score >= 90: return score, "A", "Healthy"
    if score >= 75: return score, "B", "Good"
    if score >= 60: return score, "C", "Attention Needed"
    if score >= 40: return score, "D", "Degraded"
    return score, "F", "Critical"


# ─────────────────────────────────────────────────────────────────────────────
# Phased deep-analysis (the heart of the tool)
# ─────────────────────────────────────────────────────────────────────────────

_DEEP_SYSTEM_PROMPT = """You are a senior network engineer with 20+ years of experience in data center networks (Juniper Junos, Arista EOS, Cisco IOS, FRR). You produce structured incident playbooks for network operations teams.

Output STRICT JSON with this exact shape — no markdown, no preamble, no trailing commentary:

{
  "root_cause": "Technical explanation of why this is happening — specific, actionable.",
  "risk": "What will break if this is not fixed — quantified where possible.",
  "phases": [
    {
      "name": "Diagnose",
      "goal": "One-sentence purpose of this phase.",
      "actions": [
        {
          "cli": {"frr": "vtysh -c '...'", "junos": "show ...", "eos": "show ..."},
          "expected": "What a healthy result looks like.",
          "note": "Context hint or warning."
        }
      ]
    },
    {"name": "Mitigate",  "goal": "...", "actions": [...]},
    {"name": "Remediate", "goal": "...", "actions": [...]},
    {"name": "Verify",    "goal": "...", "actions": [...]},
    {"name": "Optimize",  "goal": "...", "actions": [...]}
  ],
  "preventive_config": [
    "# FRR/Junos/EOS config snippet to drop in",
    "  neighbor <peer> bfd",
    "  ..."
  ],
  "monitoring": [
    "Alert: ... when ... for >N seconds",
    "Track: ... per ... — threshold ..."
  ],
  "timeline": "P1|P2|P3 — investigate within <window>"
}

CRITICAL RULES:
1. Every action MUST include `cli` as a dict keyed by platform ("frr", "junos", "eos"). Include at least one platform; include all three when applicable.
2. Use placeholders <like-this> for IPs/interfaces/ASNs the operator will substitute.
3. The "Optimize" phase MUST propose at least one concrete config-as-code change that prevents recurrence — not just commentary.
4. "preventive_config" is a copy-pasteable config block, not prose.
5. "monitoring" entries are precise alert rules with thresholds.
6. Be specific to the actual event provided — do not produce generic boilerplate."""


def deep_analyze(
    category: str,
    description: str,
    devices: list[str],
    count: int,
    sample_messages: list[str],
    platform_hint: str | None = None,
    skip_llm: bool = False,
) -> dict[str, Any]:
    """Produce a phased deep-analysis result. Tries LLM, falls back to KB."""
    fallback = kb.lookup(category, description)

    if len(devices) == 1:
        dev_ctx = f"Single device affected: {devices[0]}. Likely isolated issue."
    elif 1 < len(devices) <= 3:
        dev_ctx = f"{len(devices)} devices affected: {', '.join(devices)}. Check for shared upstream / common link."
    elif len(devices) > 3:
        head = ", ".join(devices[:5])
        dev_ctx = (f"{len(devices)} devices affected ({head}…). "
                   f"Possible systemic issue — check shared infrastructure (switch / PSU / IGP).")
    else:
        dev_ctx = "No specific devices captured."

    if count > 1000:
        urgency = f"⚠️ Very high event rate ({count:,} occurrences) — flooding logs."
    elif count > 100:
        urgency = f"Elevated event rate ({count:,}) — sustained issue."
    elif count > 10:
        urgency = f"Moderate event rate ({count:,}) — monitor for escalation."
    else:
        urgency = f"Low event rate ({count:,}) — may be transient."

    llm_result: dict | None = None
    if not skip_llm:
        samples = "\n".join(f"  - {m}" for m in sample_messages[:5]) or "  (no samples)"
        user_prompt = (
            f"INCIDENT CONTEXT\n"
            f"Category: {category}\n"
            f"Description: {description}\n"
            f"Occurrences: {count}\n"
            f"Affected devices ({len(devices)}): {', '.join(devices[:5]) if devices else 'unknown'}\n"
            f"Platform hint: {platform_hint or 'mixed (frr/junos/eos)'}\n"
            f"Sample log lines:\n{samples}\n\n"
            f"Produce the 5-phase incident playbook now."
        )
        text = llm.query(_DEEP_SYSTEM_PROMPT, user_prompt, max_tokens=1500)
        if text:
            llm_result = _try_parse_json(text)

    if llm_result:
        return _shape(llm_result, fallback, dev_ctx, urgency, sample_messages, llm_powered=True)
    return _shape({}, fallback, dev_ctx, urgency, sample_messages, llm_powered=False)


def _shape(parsed: dict, fallback: dict, dev_ctx: str, urgency: str,
           sample_messages: list[str], llm_powered: bool) -> dict[str, Any]:
    return {
        "root_cause":        parsed.get("root_cause") or fallback.get("root_cause", ""),
        "risk":              parsed.get("risk") or fallback.get("risk", ""),
        "phases":            _normalize_phases(parsed.get("phases") or fallback.get("phases", [])),
        "preventive_config": parsed.get("preventive_config") or fallback.get("preventive_config", []),
        "monitoring":        parsed.get("monitoring") or fallback.get("monitoring", []),
        "timeline":          parsed.get("timeline") or fallback.get("timeline", "P3"),
        "device_context":    dev_ctx,
        "urgency":           urgency,
        "sample_messages":   sample_messages[:5],
        "llm_powered":       llm_powered,
    }


def _normalize_phases(raw: list) -> list[dict]:
    """Ensure phase actions have a dict `cli`, string `expected`, string `note`."""
    out: list[dict] = []
    for phase in raw or []:
        if not isinstance(phase, dict):
            continue
        actions_raw = phase.get("actions") or []
        actions: list[dict] = []
        for a in actions_raw:
            if not isinstance(a, dict):
                continue
            cli = a.get("cli", {})
            if isinstance(cli, str):
                cli = {"any": cli}
            elif not isinstance(cli, dict):
                cli = {}
            actions.append({
                "cli": cli,
                "expected": str(a.get("expected", "")),
                "note":     str(a.get("note", "")),
            })
        out.append({
            "name":    str(phase.get("name", "")),
            "goal":    str(phase.get("goal", "")),
            "actions": actions,
        })
    return out


def _try_parse_json(text: str) -> dict | None:
    """Parse a possibly-truncated, possibly-fenced JSON response.

    Order of attempts:
      1. Strip ```json fences, parse raw.
      2. Locate first { … last } window, parse.
      3. Auto-repair: balance braces/brackets, drop trailing partial fragment.
    """
    cleaned = re.sub(r"^```[a-z]*\n?", "", text.strip())
    cleaned = re.sub(r"\n?```$", "", cleaned.strip())

    # Attempt 1: direct parse
    try:
        obj = json.loads(cleaned)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        pass

    # Attempt 2: extract widest {…}
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidate = cleaned[start : end + 1]
        try:
            obj = json.loads(candidate)
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            pass

    # Attempt 3: repair truncation — strip trailing partial line, balance braces
    if start != -1:
        partial = cleaned[start:]
        # Drop everything after the last complete value (last comma/brace at top level is hard
        # without a real parser; fallback to lopping the final line that looks incomplete)
        repaired = partial.rstrip()
        # Drop trailing partial line (no closing quote / value)
        if repaired and repaired[-1] not in "}]\"'0123456789tnef":  # truthy/null endings
            last_nl = repaired.rfind("\n")
            if last_nl > 0:
                repaired = repaired[:last_nl]
        # Close unbalanced braces and brackets
        opens_curly = repaired.count("{") - repaired.count("}")
        opens_square = repaired.count("[") - repaired.count("]")
        if opens_square > 0:
            repaired += "]" * opens_square
        if opens_curly > 0:
            repaired += "}" * opens_curly
        try:
            obj = json.loads(repaired)
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            return None

    return None


# ─────────────────────────────────────────────────────────────────────────────
# Action item aggregation
# ─────────────────────────────────────────────────────────────────────────────

def build_action_items(events: list[ClassifiedEvent], llm_top_n: int = 3) -> list[ActionItem]:
    """Deduplicate events into action items, run LLM only on top-N priority items."""
    seen: dict[tuple[str, str], dict] = {}
    for e in events:
        if e.severity not in ("critical", "high", "medium"):
            continue
        # Recovery events go in the timeline, not in action items
        if e.description in _RECOVERY_DESCRIPTIONS:
            continue
        key = (e.severity, e.description)
        bucket = seen.setdefault(key, {
            "severity": e.severity,
            "category": e.category,
            "description": e.description,
            "count": 0,
            "devices": set(),
            "messages": [],
        })
        bucket["count"] += 1
        if e.hostname:
            bucket["devices"].add(e.hostname)
        if len(bucket["messages"]) < 5:
            bucket["messages"].append(e.message[:300])

    sorted_keys = sorted(
        seen.keys(),
        key=lambda k: (SEV_ORDER.get(k[0], 5), -seen[k]["count"]),
    )

    items: list[ActionItem] = []
    for idx, key in enumerate(sorted_keys):
        b = seen[key]
        devices = sorted(b["devices"])[:10]
        deep = deep_analyze(
            category=b["category"],
            description=b["description"],
            devices=devices,
            count=b["count"],
            sample_messages=b["messages"],
            skip_llm=(idx >= llm_top_n),
        )
        items.append(ActionItem(
            severity=b["severity"],
            category=b["category"],
            description=b["description"],
            count=b["count"],
            devices=devices,
            sample_messages=b["messages"][:3],
            deep_analysis=deep,
        ))
    return items


# ─────────────────────────────────────────────────────────────────────────────
# Top devices, executive summary
# ─────────────────────────────────────────────────────────────────────────────

def _extract_top_devices(events: list[ClassifiedEvent], limit: int = 20) -> list[dict]:
    by_host: dict[str, dict] = {}
    for e in events:
        if not e.hostname:
            continue
        bucket = by_host.setdefault(e.hostname, {
            "hostname": e.hostname, "total": 0,
            "critical": 0, "high": 0, "medium": 0, "categories": {},
        })
        bucket["total"] += 1
        if e.severity in ("critical", "high", "medium"):
            bucket[e.severity] += 1
        bucket["categories"][e.category] = bucket["categories"].get(e.category, 0) + 1

    rows = list(by_host.values())
    rows.sort(key=lambda r: (-r["critical"], -r["high"], -r["total"]))
    return rows[:limit]


def _executive_summary(
    sev_counts: dict[str, int],
    cat_counts: dict[str, int],
    score: int,
    grade: str,
    grade_label: str,
    items: list[ActionItem],
    use_llm: bool,
) -> tuple[list[str], bool]:
    if use_llm:
        sys_prompt = (
            "You are a senior network engineer writing a 4-6 bullet executive summary for a "
            "network operations standup. Each bullet must be specific (with device names + numbers), "
            "actionable, and one line. Prefix every bullet with '• '. No headers, no preamble."
        )
        top = [f"{a.severity.upper()} | {a.description} ({a.count}× on {len(a.devices)} devices)"
               for a in items[:5]]
        user_prompt = (
            f"Score: {score}/100 (grade {grade} — {grade_label})\n"
            f"Severity: critical={sev_counts.get('critical', 0)}, "
            f"high={sev_counts.get('high', 0)}, medium={sev_counts.get('medium', 0)}\n"
            f"Top categories: {dict(sorted(cat_counts.items(), key=lambda x: -x[1])[:5])}\n"
            f"Top action items:\n" + ("\n".join(f"  - {t}" for t in top) if top else "  (none)")
        )
        text = llm.query(sys_prompt, user_prompt, max_tokens=400)
        if text:
            bullets = [line.strip().lstrip("•- ").strip() for line in text.split("\n") if line.strip()]
            bullets = [b for b in bullets if b][:6]
            if bullets:
                return bullets, True

    bullets = [
        f"Health score {score}/100 — Grade {grade} ({grade_label})",
        (f"Severity: critical={sev_counts.get('critical', 0)}, "
         f"high={sev_counts.get('high', 0)}, medium={sev_counts.get('medium', 0)}"),
    ]
    if cat_counts:
        top_cats = ", ".join(f"{c} ({n})" for c, n in
                             sorted(cat_counts.items(), key=lambda x: -x[1])[:3])
        bullets.append(f"Top categories: {top_cats}")
    if items:
        for a in items[:3]:
            dev_str = a.devices[0] if len(a.devices) == 1 else f"{len(a.devices)} devices"
            bullets.append(f"{a.severity.upper()} — {a.description} ({a.count}× on {dev_str})")
    else:
        bullets.append("No critical, high, or medium severity issues detected.")
    return bullets, False


def analyze(events: list[LogEvent], use_llm: bool = True, llm_top_n: int = 3) -> AnalysisResult:
    """End-to-end pipeline: classify → action items → score → executive summary.

    Thread-safe: never mutates global llm state. `use_llm=False` is enforced by
    forcing `llm_top_n=0` and disabling the LLM-powered exec summary path.
    """
    classified, sev_counts, cat_counts = classify_events(events)

    effective_llm = use_llm and llm.is_enabled()
    action_items = build_action_items(
        classified,
        llm_top_n=llm_top_n if effective_llm else 0,
    )
    score, grade, grade_label = health_score(sev_counts)
    summary, summary_llm = _executive_summary(
        sev_counts, cat_counts, score, grade, grade_label, action_items,
        use_llm=effective_llm,
    )

    any_llm = summary_llm or any(a.deep_analysis.get("llm_powered") for a in action_items)
    top_devices = _extract_top_devices(classified)

    return AnalysisResult(
        score=score, grade=grade, grade_label=grade_label,
        severity_counts=sev_counts, category_counts=cat_counts,
        action_items=action_items, top_devices=top_devices,
        classified_events=classified[:300],
        executive_summary=summary,
        llm_powered=any_llm,
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Config-aware Optimization (the "killer LLM feature")
# ─────────────────────────────────────────────────────────────────────────────

_OPTIMIZE_SYSTEM_PROMPT = """You are a principal network architect specializing in resiliency, convergence, and operational best practices. You analyze running configurations alongside recent incident logs and propose concrete, copy-pasteable configuration improvements.

Output STRICT JSON only — no markdown fences, no preamble, no trailing text. Start with `{` and end with `}`.

Shape:
{
  "summary": "1-2 sentence overall assessment of the current config posture.",
  "findings": [
    {
      "severity": "critical|high|medium|low",
      "category": "convergence|security|redundancy|monitoring|scalability|compliance",
      "title": "Short title of the issue.",
      "evidence": "Specific config line(s) or log event(s) that prove this finding.",
      "rationale": "Why this matters — quantify impact where possible.",
      "patch": ["config command 1", "config command 2"],
      "rollback": ["how to revert"],
      "verify_cli": ["show command to confirm"]
    }
  ],
  "monitoring_gaps": ["alert rule 1", "alert rule 2"],
  "score": 75
}

OUTPUT BUDGET:
- Maximum 6 findings, sorted by severity descending.
- Each `patch` and `rollback` ≤ 8 lines. Each `verify_cli` ≤ 3 commands.
- Keep strings concise. Total output target: ~2500 tokens.

RULES:
1. Every finding must cite specific evidence — quote the config line or log message.
2. Patches must be valid syntax for the platform (FRR vtysh / Junos set / Arista CLI).
3. Don't invent problems — if config looks fine, return empty findings + score 95.
4. `score` is 0-100 — how mature the current config is for production resilience.
5. Do NOT wrap your response in ```json fences. Output the raw JSON object only."""


def optimize_config(
    hostname: str,
    platform: str,
    running_config: str,
    recent_events: list[dict] | None = None,
) -> dict[str, Any]:
    """Pass current config + recent events to the LLM, get back proposed patches.

    This is the "Optimize" killer feature: analyze the live device state, find
    misconfigurations or missing resilience features, propose concrete patches.
    """
    events_section = ""
    if recent_events:
        events_section = "\nRECENT INCIDENT EVENTS (last analysis cycle):\n" + "\n".join(
            f"  [{e.get('severity', '?')}] {e.get('description', '')}"
            for e in recent_events[:15]
        )

    # CRITICAL: scrub secrets + PII before any external LLM sees the config.
    # The sample manifests are pre-sanitized, but live-fetched configs (via
    # network_tool.fetch_running_config) and raw inputs over /api/optimize are
    # NOT. Belt-and-suspenders — always sanitize here.
    safe_config, redactions = sanitize(running_config, mask_pii=True)

    # Truncate config to fit comfortably in 200K-context models. ~60KB ≈ 20K tokens
    # leaves plenty of room for system prompt + response. Big Junos routers can hit
    # 220KB+; truncation is unavoidable on smaller models. We keep head + tail so
    # protocols block + interfaces block both reach the LLM.
    MAX_CFG = 60000
    if len(safe_config) > MAX_CFG:
        head = safe_config[: int(MAX_CFG * 0.7)]
        tail = safe_config[-int(MAX_CFG * 0.3):]
        cfg_truncated = (
            f"{head}\n\n... [middle truncated, original size {len(safe_config)} chars] ...\n\n{tail}"
        )
    else:
        cfg_truncated = safe_config

    user_prompt = (
        f"DEVICE: {hostname}\n"
        f"PLATFORM: {platform}\n"
        f"{events_section}\n\n"
        f"RUNNING CONFIG:\n```\n{cfg_truncated}\n```\n\n"
        f"Analyze the config + events. Identify resilience gaps, security weaknesses, "
        f"missing monitoring, and convergence improvements. Output the JSON now."
    )

    text = llm.query(_OPTIMIZE_SYSTEM_PROMPT, user_prompt, max_tokens=4096)
    if not text:
        return {
            "summary": "LLM unavailable — no optimization recommendations generated.",
            "findings": [],
            "monitoring_gaps": [],
            "score": 0,
            "llm_powered": False,
        }

    parsed = _try_parse_json(text)
    if not parsed:
        return {
            "summary": "LLM returned non-JSON response — could not parse.",
            "raw": text[:2000],
            "findings": [],
            "monitoring_gaps": [],
            "score": 0,
            "llm_powered": True,
        }

    parsed["llm_powered"] = True
    parsed["redactions_applied"] = redactions
    parsed.setdefault("findings", [])
    parsed.setdefault("monitoring_gaps", [])
    parsed.setdefault("summary", "")
    parsed.setdefault("score", 0)
    return parsed


# ─────────────────────────────────────────────────────────────────────────────
# Site-level analysis — multiple devices analyzed together for cross-device issues
# ─────────────────────────────────────────────────────────────────────────────

_SITE_SYSTEM_PROMPT = """You are a principal network architect reviewing an entire datacenter site. You are given the running-configs of every device in the site simultaneously. Your job is to identify CROSS-DEVICE issues that no single-device review could catch.

Focus on:
  1. HA pair inconsistencies (firewall A vs B; EVPN leaf A vs B)
  2. Asymmetric BGP / OSPF / IS-IS config between peers
  3. Missing reciprocal config (one side has BFD/MD5, peer doesn't)
  4. MTU mismatches on connected interfaces
  5. EVPN-VXLAN fabric consistency (VNI lists, route-targets, anycast gateways)
  6. ISP redundancy gaps (single ISP, missing backup BGP session)
  7. Missing inter-device monitoring (no peer-of-peer alerting)
  8. Compliance drift — feature enabled on most devices but missing on one
  9. Trust-zone leakage (firewall policy on one peer not on the other)
 10. Naming or addressing inconsistencies

Output STRICT JSON only — no markdown fences, no preamble. Start with `{` end with `}`:

{
  "site_summary": "1-2 sentence overall assessment of the site's design + maturity.",
  "topology": {
    "devices_seen": ["fw-01", "fw-02", ...],
    "roles": {"firewall": ["fw-01", "fw-02"], "evpn_leaf": ["sw-11a", "sw-11b"], ...},
    "isp_uplinks": ["sw-04: leaseweb_1, leaseweb_2"]
  },
  "cross_device_findings": [
    {
      "severity": "critical|high|medium|low",
      "category": "ha_drift|asymmetry|fabric|isp_redundancy|monitoring|security|compliance",
      "title": "Short title.",
      "affected_devices": ["fw-01", "fw-02"],
      "evidence": "Quote specific config lines from named devices.",
      "rationale": "Why this matters; quantify impact.",
      "fix_per_device": {
        "fw-01": ["config line 1", "config line 2"],
        "fw-02": ["config line 1", "config line 2"]
      },
      "verify_cli": ["show command on the affected devices"]
    }
  ],
  "monitoring_gaps": ["site-wide alert that should exist"],
  "site_score": 75
}

OUTPUT BUDGET (HARD CAP — exceeding will truncate your response and produce invalid JSON):
- Maximum 5 findings, sorted by severity desc.
- Each `evidence` and `rationale` ≤ 200 chars.
- Each fix_per_device list ≤ 5 lines per device, ≤ 80 chars per line.
- Each finding covers at most 4 affected_devices.
- Maximum 5 monitoring_gaps.
- Total response target: 3500 tokens. STAY WITHIN THIS — start with the highest-severity findings.

RULES:
1. Every finding MUST cite at least 2 devices (cross-device focus).
2. Quote actual lines from the configs as evidence.
3. Use the device hostnames I provide — don't invent names.
4. If the site is well-designed and you find no real cross-device issues, return empty findings + score 90+.
5. Patches must use the correct vendor syntax (Junos `set ...` / EOS `interface X / cmd`).
6. Do NOT wrap your response in ```json fences."""


def analyze_site(
    site_id: str,
    devices: list[dict],
) -> dict:
    """Analyze a whole site (multiple devices) for cross-device issues.

    Args:
        site_id: free-form site name (e.g. "demo-WEST")
        devices: list of {hostname, function, platform, config_text} dicts

    Returns:
        Dict with cross_device_findings, topology summary, monitoring gaps.
    """
    if not devices:
        return {"site_id": site_id, "error": "no devices provided",
                "cross_device_findings": [], "site_score": 0, "llm_powered": False}

    if not llm.get_state()["enabled"]:
        return {
            "site_id": site_id,
            "site_summary": "LLM disabled — cannot run cross-device analysis.",
            "topology": {"devices_seen": [d["hostname"] for d in devices]},
            "cross_device_findings": [],
            "monitoring_gaps": [],
            "site_score": 0,
            "llm_powered": False,
        }

    # Build the multi-device prompt. We budget ~12K chars per device for big sites,
    # 60K total for small ones. The site-wide context is the value-add.
    PER_DEVICE_CHARS = 12000
    TOTAL_BUDGET = 90000  # ~30K tokens, fits Claude 200K easily

    device_blocks: list[str] = []
    running_total = 0
    devices_seen: list[str] = []
    for d in devices:
        cfg = d.get("config_text") or ""
        if not cfg:
            continue
        trimmed = cfg[:PER_DEVICE_CHARS]
        if len(cfg) > PER_DEVICE_CHARS:
            trimmed += f"\n... [config truncated, original {len(cfg)} chars] ..."
        block = (
            f"\n\n========== DEVICE: {d['hostname']} ==========\n"
            f"FUNCTION: {d.get('function', 'unknown')}  |  PLATFORM: {d.get('platform', 'unknown')}\n"
            f"```\n{trimmed}\n```"
        )
        if running_total + len(block) > TOTAL_BUDGET:
            block = (
                f"\n\n========== DEVICE: {d['hostname']} (SKIPPED - budget) ==========\n"
                f"FUNCTION: {d.get('function', 'unknown')}\n"
            )
        device_blocks.append(block)
        devices_seen.append(d["hostname"])
        running_total += len(block)

    user_prompt = (
        f"SITE: {site_id}\n"
        f"DEVICES IN BUNDLE: {len(devices_seen)} ({', '.join(devices_seen)})\n"
        f"{''.join(device_blocks)}\n\n"
        f"Produce the cross-device analysis JSON now."
    )

    text = llm.query(_SITE_SYSTEM_PROMPT, user_prompt, max_tokens=6144)
    if not text:
        return {
            "site_id": site_id,
            "site_summary": "LLM call failed — see /api/llm/status for last error.",
            "topology": {"devices_seen": devices_seen},
            "cross_device_findings": [],
            "monitoring_gaps": [],
            "site_score": 0,
            "llm_powered": False,
        }

    parsed = _try_parse_json(text)
    if not parsed:
        return {
            "site_id": site_id,
            "site_summary": "LLM returned non-JSON response — could not parse.",
            "raw": text[:6000],
            "raw_length": len(text),
            "topology": {"devices_seen": devices_seen},
            "cross_device_findings": [],
            "monitoring_gaps": [],
            "site_score": 0,
            "llm_powered": True,
        }

    parsed["site_id"] = site_id
    parsed["llm_powered"] = True
    parsed.setdefault("topology", {"devices_seen": devices_seen})
    parsed.setdefault("cross_device_findings", parsed.pop("findings", []) if "findings" in parsed else [])
    parsed.setdefault("monitoring_gaps", [])
    parsed.setdefault("site_summary", parsed.pop("summary", "") if "summary" in parsed else "")
    parsed.setdefault("site_score", parsed.pop("score", 0) if "score" in parsed else 0)
    return parsed
