"""Post-mortem search — given a pattern found on one device, sweep the fleet.

Inspired by NetBrain's "Post-Mortem Assessment": once we know what a bug looks
like, automatically check every other device for the same fingerprint.
"""
from __future__ import annotations

import re
import time

import regex

# The pattern comes from an operator-supplied request: bound its size and run it
# under the `regex` module's timeout so a catastrophic one (`(\s*\w*)*#Z`) cannot
# pin a worker. Same defence as the classifier's custom rules.
MAX_PATTERN_LENGTH = 512
SEARCH_TIMEOUT_SECONDS = 1.0     # per device
TOTAL_TIMEOUT_SECONDS = 10.0     # whole sweep


def _error(msg: str) -> dict:
    return {"error": msg, "matches": [], "total_matches": 0}


def search_fleet(
    devices: list[dict],
    pattern: str,
    case_insensitive: bool = True,
) -> dict:
    """Search every device's config for the given pattern. Returns a structured report.

    Args:
        devices: list of {hostname, platform, config_text}
        pattern: regex (or literal substring — auto-escaped if no regex chars)
    """
    if len(pattern) > MAX_PATTERN_LENGTH:
        return _error(f"pattern exceeds {MAX_PATTERN_LENGTH} characters")
    flags = regex.MULTILINE | (regex.IGNORECASE if case_insensitive else 0)

    # If pattern has no regex metacharacters, treat as literal
    if not re.search(r"[\\.*+?^$\[\](){}|]", pattern):
        compiled = regex.compile(regex.escape(pattern), flags)
    else:
        try:
            compiled = regex.compile(pattern, flags)
        except regex.error as e:
            # Report where the syntax error is, not the library's message text (kept out of API responses).
            pos = getattr(e, "pos", None)
            return _error("invalid regex" + (f" (syntax error at position {pos})" if isinstance(pos, int) else ""))

    deadline = time.monotonic() + TOTAL_TIMEOUT_SECONDS
    hits: list[dict] = []
    for d in devices:
        text = d.get("config_text", "")
        budget = min(SEARCH_TIMEOUT_SECONDS, deadline - time.monotonic())
        if budget <= 0:
            return _error("pattern search timed out; simplify the regular expression")
        try:
            matches = list(compiled.finditer(text, timeout=budget))
        except TimeoutError:
            return _error("pattern search timed out; simplify the regular expression")
        if not matches:
            continue
        snippets = []
        for m in matches[:5]:  # cap per device
            start = max(m.start() - 40, 0)
            end = min(m.end() + 40, len(text))
            snippets.append(text[start:end].replace("\n", " ⏎ "))
        hits.append({
            "device": d["hostname"],
            "platform": d.get("platform", "unknown"),
            "match_count": len(matches),
            "snippets": snippets,
        })

    return {
        "pattern": pattern,
        "total_devices_checked": len(devices),
        "devices_with_matches": len(hits),
        "total_matches": sum(h["match_count"] for h in hits),
        "matches": hits,
    }


def fingerprint_finding(finding: dict) -> str | None:
    """Extract a searchable fingerprint from an LLM finding.

    Looks at the `evidence` field for the most identifying snippet:
      - A specific config line like "no lldp run"
      - An IP / interface name
      - A version string

    Returns a regex/literal suitable for search_fleet().
    """
    ev = (finding.get("evidence") or "").strip()
    if not ev:
        return None

    # Prefer explicit quoted config lines
    quoted = re.findall(r"['\"]([^'\"]{4,80})['\"]", ev)
    for q in quoted:
        if re.search(r"\w{3,}", q):  # has something tokenish
            return q

    # Look for a config-y line (starts with set/no/router/interface/protocols)
    for line in ev.splitlines():
        line = line.strip()
        if re.match(r"^(set|no|router|interface|protocols|service|ip\s+|snmp|ssh|ntp|aaa)", line, re.IGNORECASE):
            return line[:120]

    # Look for an IPv4 / interface name
    ip = re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", ev)
    if ip:
        return ip.group(0)
    iface = re.search(r"\b(?:ge|xe|et|ae|Ethernet|Port-Channel)[-/\d.]+\b", ev)
    if iface:
        return iface.group(0)

    return None
