"""Declarative compliance rule engine — no LLM needed.

Rules are loaded from a YAML/JSON file describing required (or forbidden)
config patterns per platform. Each device is checked against every rule,
producing a pass/fail per (rule, device) pair.

Example rule:
  - id: ssh-v2-only
    name: "SSH must be version 2"
    severity: high
    platforms: [junos, eos]
    must_match: ["protocol-version v2", "ssh protocol v2"]
    description: "SSHv1 is cryptographically broken — enforce v2."
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class ComplianceCheck:
    rule_id: str
    rule_name: str
    severity: str
    device: str
    passed: bool
    reason: str
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id, "rule_name": self.rule_name,
            "severity": self.severity, "device": self.device,
            "passed": self.passed, "reason": self.reason,
            "description": self.description,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Built-in rules (always available; no YAML file needed for MVP)
# ─────────────────────────────────────────────────────────────────────────────

BUILTIN_RULES: list[dict[str, Any]] = [
    {
        "id": "ssh-v2-only",
        "name": "SSH protocol v2 required",
        "severity": "high",
        "platforms": ["junos", "eos", "frr"],
        "description": "SSHv1 is cryptographically broken — enforce v2.",
        "must_match_any": [r"protocol-version\s+v2", r"ssh\s+server\s+version\s+v2only", r"protocol\s+ssh\s+version\s+2"],
        "fail_if_present": [r"protocol-version\s+v1"],
    },
    {
        "id": "no-telnet",
        "name": "Telnet must be disabled",
        "severity": "critical",
        "platforms": ["junos", "eos", "frr"],
        "description": "Telnet is unencrypted; should never be enabled on management plane.",
        "fail_if_present": [r"^\s*set\s+system\s+services\s+telnet\b",
                             r"^\s*telnet\s+server\s+enable",
                             r"^\s*line\s+vty.*?\n.*?transport\s+input\s+all"],
    },
    {
        "id": "ntp-min-2-servers",
        "name": "At least 2 NTP servers configured",
        "severity": "medium",
        "platforms": ["junos", "eos", "frr"],
        "description": "Single NTP source = single point of failure for time sync.",
        "count_match_min": (r"\b(?:ntp\s+server|set\s+system\s+ntp\s+server)\b", 2),
    },
    {
        "id": "syslog-min-1-remote",
        "name": "Remote syslog server configured",
        "severity": "high",
        "platforms": ["junos", "eos", "frr"],
        "description": "Logs lost on reboot if no remote collector.",
        "must_match_any": [r"set\s+system\s+syslog\s+host\b", r"logging\s+host\s+", r"log\s+facility-name"],
    },
    {
        "id": "bgp-md5-auth",
        "name": "BGP MD5 authentication on peers",
        "severity": "medium",
        "platforms": ["junos", "eos", "frr"],
        "description": "MD5 auth prevents BGP-spoof attacks.",
        "if_present": [r"\bneighbor\s+\S+\s+remote-as\b", r"peer-as\s+\d+"],
        "must_match_any": [r"authentication-key", r"neighbor\s+\S+\s+password", r"md5-key"],
    },
    {
        "id": "snmp-v3-only",
        "name": "SNMPv3 — no v1/v2c community",
        "severity": "high",
        "platforms": ["junos", "eos", "frr"],
        "description": "SNMPv1/v2c sends community strings in clear text.",
        "fail_if_present": [r"snmp-server\s+community\s+\S+", r"set\s+snmp\s+community\b"],
    },
    {
        "id": "interface-mtu-9000",
        "name": "Inter-switch links should use MTU 9000+ (jumbo)",
        "severity": "low",
        "platforms": ["junos", "eos", "frr"],
        "description": "Jumbo frames improve throughput on backbone/leaf-spine links.",
        "if_present": [r"description.*?(ISL|UPLINK|SPINE|CORE)", r"description.*?(MLAG|peer-link)"],
        "must_match_any": [r"mtu\s+9\d{3}", r"mtu\s+9000"],
    },
    {
        "id": "lldp-enabled",
        "name": "LLDP enabled for neighbor discovery",
        "severity": "low",
        "platforms": ["junos", "eos", "frr"],
        "description": "LLDP makes topology auto-discoverable.",
        "must_match_any": [r"set\s+protocols\s+lldp", r"^lldp\s+run", r"lldp\s+timer"],
        "fail_if_present": [r"^no\s+lldp\s+run"],
    },
    {
        "id": "root-login-deny",
        "name": "SSH root-login deny (Junos) / no privilege 15 (EOS)",
        "severity": "high",
        "platforms": ["junos"],
        "description": "Restrict direct root logins; use named users.",
        "must_match_any": [r"root-login\s+deny", r"root-login\s+deny-password"],
    },
]


def check_device(config_text: str, platform: str, hostname: str,
                  rules: list[dict[str, Any]] = None) -> list[ComplianceCheck]:
    """Run all rules applicable to this platform against the config."""
    rules = rules or BUILTIN_RULES
    out: list[ComplianceCheck] = []
    platform = platform.lower()
    for rule in rules:
        if platform not in [p.lower() for p in rule.get("platforms", [])]:
            continue

        # Check `if_present` gating — skip rule entirely if gate doesn't match
        gates = rule.get("if_present", [])
        if gates and not any(re.search(g, config_text, re.M | re.I) for g in gates):
            continue

        passed, reason = _evaluate_rule(config_text, rule)
        out.append(ComplianceCheck(
            rule_id=rule["id"], rule_name=rule["name"],
            severity=rule.get("severity", "medium"),
            device=hostname, passed=passed, reason=reason,
            description=rule.get("description", ""),
        ))
    return out


def _evaluate_rule(text: str, rule: dict[str, Any]) -> tuple[bool, str]:
    # 1. fail_if_present: if any of these patterns hit → fail
    for pat in rule.get("fail_if_present", []):
        if re.search(pat, text, re.M | re.I):
            return False, f"Forbidden pattern matched: {pat[:60]}"

    # 2. count_match_min: count occurrences, fail if below threshold
    if "count_match_min" in rule:
        pat, threshold = rule["count_match_min"]
        count = len(re.findall(pat, text, re.M | re.I))
        if count < threshold:
            return False, f"Only {count} match(es) of '{pat[:40]}'; need ≥{threshold}"

    # 3. must_match_any: at least one of these must match
    any_pats = rule.get("must_match_any", [])
    if any_pats:
        if not any(re.search(p, text, re.M | re.I) for p in any_pats):
            return False, f"None of the required patterns matched"

    return True, "ok"


def check_bundle(devices: list[dict], rules: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Run compliance on every device in a bundle. Returns aggregate report."""
    all_checks: list[ComplianceCheck] = []
    for d in devices:
        all_checks.extend(check_device(
            d.get("config_text", ""), d.get("platform", "unknown"),
            d["hostname"], rules=rules,
        ))

    total = len(all_checks)
    passed = sum(1 for c in all_checks if c.passed)
    failed = total - passed
    by_rule: dict[str, dict] = {}
    for c in all_checks:
        b = by_rule.setdefault(c.rule_id, {
            "rule_id": c.rule_id, "rule_name": c.rule_name,
            "severity": c.severity, "description": c.description,
            "pass": 0, "fail": 0, "failing_devices": [],
        })
        if c.passed:
            b["pass"] += 1
        else:
            b["fail"] += 1
            b["failing_devices"].append({"device": c.device, "reason": c.reason})

    return {
        "total_checks": total,
        "passed": passed,
        "failed": failed,
        "pass_rate": round(100 * passed / total, 1) if total else 0.0,
        "rules": list(by_rule.values()),
        "checks": [c.to_dict() for c in all_checks],
    }
