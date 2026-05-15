"""Snapshot diff — compare two configs of the same device over time.

Combines a structural diff (Python difflib) with an LLM-generated explanation
of meaningful behavior changes (Batfish-inspired).
"""
from __future__ import annotations

import difflib
import re
from typing import Iterable

from ai_log_analyzer import llm
from ai_log_analyzer.sanitize import sanitize


def text_diff(before: str, after: str, context: int = 3) -> str:
    """Unified-diff string with N lines of context."""
    bl = before.splitlines(keepends=False)
    al = after.splitlines(keepends=False)
    return "\n".join(difflib.unified_diff(
        bl, al, lineterm="", n=context,
        fromfile="before", tofile="after",
    ))


def structured_diff(before: str, after: str) -> dict:
    """Count additions, deletions, modifications, plus a small classification."""
    bl = before.splitlines()
    al = after.splitlines()

    differ = difflib.Differ()
    additions: list[str] = []
    deletions: list[str] = []
    for line in differ.compare(bl, al):
        if line.startswith("+ "):
            additions.append(line[2:])
        elif line.startswith("- "):
            deletions.append(line[2:])

    # Categorize lines by config section keyword
    def categorize(ls: list[str]) -> dict[str, int]:
        cats: dict[str, int] = {}
        keywords = [
            ("bgp", r"\bbgp\b"),
            ("ospf", r"\bospf\b"),
            ("interface", r"\binterface\b|\bset\s+interfaces\b"),
            ("acl/firewall", r"\bacl\b|\bfirewall\b|\bsecurity\s+policies\b"),
            ("snmp", r"\bsnmp\b"),
            ("ntp", r"\bntp\b"),
            ("syslog/logging", r"\bsyslog\b|\blogging\b"),
            ("user/auth", r"\buser\b|\busername\b|\baaa\b"),
            ("routing/static", r"\bip\s+route\b|\bstatic\s+route\b"),
            ("vlan/vxlan", r"\bvlan\b|\bvxlan\b|\bvni\b"),
        ]
        for line in ls:
            ll = line.lower()
            for label, pat in keywords:
                if re.search(pat, ll):
                    cats[label] = cats.get(label, 0) + 1
                    break
        return cats

    return {
        "lines_added": len(additions),
        "lines_removed": len(deletions),
        "additions_by_section": categorize(additions),
        "removals_by_section": categorize(deletions),
        "sample_additions": additions[:10],
        "sample_removals": deletions[:10],
    }


_DIFF_SYSTEM_PROMPT = """You are a senior network engineer reviewing a config snapshot diff. Output STRICT JSON only — no markdown fences, no preamble:

{
  "summary": "One-paragraph plain-language summary of what changed.",
  "risk": "critical|high|medium|low|none",
  "risk_explanation": "Why this risk level — be specific.",
  "behavior_changes": ["bullet 1", "bullet 2"],
  "rollback_hint": "How to revert if the change is bad."
}

BUDGET: ≤ 1500 tokens output. Focus on behavior, not whitespace."""


def explain_diff(before: str, after: str, hostname: str = "", platform: str = "junos") -> dict:
    """Combine structural diff + LLM behavior-impact analysis.

    Sanitizes both inputs before diffing so secrets never reach the LLM and
    never appear in the raw diff returned to the caller.
    """
    # CRITICAL: scrub before diff. Even the structured diff exposes
    # config line contents — if we don't sanitize first, an encrypted
    # password in the "before" config would surface in `raw_diff`.
    safe_before, red_b = sanitize(before, mask_pii=True)
    safe_after,  red_a = sanitize(after,  mask_pii=True)
    struct = structured_diff(safe_before, safe_after)
    raw = text_diff(safe_before, safe_after, context=2)
    truncated = raw[:8000]

    explanation: dict = {"summary": "", "risk": "low", "behavior_changes": [],
                          "rollback_hint": "", "llm_powered": False}

    if llm.get_state()["enabled"]:
        user_prompt = (
            f"DEVICE: {hostname or '(unknown)'}\n"
            f"PLATFORM: {platform}\n"
            f"LINES ADDED: {struct['lines_added']}  REMOVED: {struct['lines_removed']}\n"
            f"SECTIONS TOUCHED: {struct['additions_by_section']}\n\n"
            f"UNIFIED DIFF:\n```\n{truncated}\n```\n\nReturn the JSON now."
        )
        text = llm.query(_DIFF_SYSTEM_PROMPT, user_prompt, max_tokens=1500)
        if text:
            parsed = _try_parse_json(text)
            if parsed:
                explanation = {
                    "summary": parsed.get("summary", ""),
                    "risk": parsed.get("risk", "low"),
                    "risk_explanation": parsed.get("risk_explanation", ""),
                    "behavior_changes": parsed.get("behavior_changes", []),
                    "rollback_hint": parsed.get("rollback_hint", ""),
                    "llm_powered": True,
                }

    return {
        "hostname": hostname, "platform": platform,
        "structured": struct,
        "raw_diff": raw[:16000],
        "redactions_applied": red_b + red_a,
        "explanation": explanation,
    }


def _try_parse_json(text: str) -> dict | None:
    import json
    cleaned = re.sub(r"^```[a-z]*\n?", "", text.strip())
    cleaned = re.sub(r"\n?```$", "", cleaned.strip())
    try:
        obj = json.loads(cleaned)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        m = re.search(r"\{[\s\S]*\}", cleaned)
        if not m:
            return None
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            return None
