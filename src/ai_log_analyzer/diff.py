"""Snapshot diff — compare two configs of the same device over time.

Combines a structural diff (Python difflib) with an LLM-generated explanation
of meaningful behavior changes (Batfish-inspired).
"""
from __future__ import annotations

import difflib
import re
from collections import Counter
from dataclasses import dataclass, field

from ai_log_analyzer import llm
from ai_log_analyzer.sanitize import sanitize

# difflib is quadratic in what it has to align: SequenceMatcher in the line count, and Differ's
# intraline pass in (characters of a replaced block) x (characters of its counterpart) plus a fixed
# cost per line pair. Past these bounds a diff is answered by line content alone (linear), and the
# answer says it is approximate. Below them the output is exactly what Differ / ndiff produce.
MAX_DIFF_LINES = 10_000          # per side
_FANCY_BUDGET = 100_000_000      # about a second of Differ on a 3.12 interpreter
_PAIR_COST = 64                  # one line pair costs about as much as comparing two 8-character lines
_APPROX_NOTE = ("Diff is approximate: the input is too large to align line by line, so lines are matched by "
                "content only; order and moved-line context are not shown.")


def _unordered_changes(a: list[str], b: list[str]) -> list[tuple[str, str]]:
    """Lines present in only one side, by multiset difference. O(n); ignores order."""
    out: list[tuple[str, str]] = []
    for sign, mine, other in (("-", a, Counter(b)), ("+", b, Counter(a))):
        for line in mine:
            if other[line] > 0:
                other[line] -= 1
            else:
                out.append((sign, line))
    return out


def _block_cost(a: list[str], b: list[str]) -> int:
    return sum(map(len, a)) * sum(map(len, b)) + len(a) * len(b) * _PAIR_COST


def _changes(a: list[str], b: list[str], charjunk=None) -> tuple[list[tuple[str, str]], bool]:
    """Ordered ("+" | "-", line) pairs as ``Differ`` reports them, and whether they are approximate."""
    if len(a) > MAX_DIFF_LINES or len(b) > MAX_DIFF_LINES:
        return _unordered_changes(a, b), True
    if _block_cost(a, b) > _FANCY_BUDGET:   # whole-text bound; only then look at the replaced blocks
        ops = difflib.SequenceMatcher(None, a, b).get_opcodes()
        replaced = sum(_block_cost(a[i1:i2], b[j1:j2]) for tag, i1, i2, j1, j2 in ops if tag == "replace")
        if replaced > _FANCY_BUDGET:
            out: list[tuple[str, str]] = []
            for tag, i1, i2, j1, j2 in ops:
                out.extend(("-", line) for line in a[i1:i2] if tag in ("replace", "delete"))
                out.extend(("+", line) for line in b[j1:j2] if tag in ("replace", "insert"))
            return out, True
    compared = difflib.Differ(None, charjunk).compare(a, b)
    return [(d[0], d[2:]) for d in compared if d[:2] in ("+ ", "- ")], False


@dataclass
class ConfigDiff:
    """Before/after config lines used by the drift correlator.

    ``added`` and ``removed`` win when set. Otherwise changed lines are derived
    from ``before`` and ``after`` with the standard library differ.
    """

    before: str = ""
    after: str = ""
    hostname: str = ""
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)

    def diff_lines(self) -> tuple[list[str], bool]:
        """Changed lines, and whether they are approximate (input too large to align line by line)."""
        if self.added or self.removed:
            return [*self.added, *self.removed], False
        changes, approximate = _changes(
            self.before.splitlines(), self.after.splitlines(), difflib.IS_CHARACTER_JUNK)
        return [line for _sign, line in changes], approximate

    def changed_lines(self) -> list[str]:
        return self.diff_lines()[0]

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "added": list(self.added),
            "removed": list(self.removed),
            "changed_lines": self.changed_lines(),
        }


def text_diff(before: str, after: str, context: int = 3) -> str:
    """Unified-diff string with N lines of context."""
    bl = before.splitlines(keepends=False)
    al = after.splitlines(keepends=False)
    if len(bl) > MAX_DIFF_LINES or len(al) > MAX_DIFF_LINES:
        changes = _unordered_changes(bl, al)
        return "\n".join([f"# {_APPROX_NOTE}", *(f"{sign}{line}" for sign, line in changes)])
    return "\n".join(difflib.unified_diff(
        bl, al, lineterm="", n=context,
        fromfile="before", tofile="after",
    ))


def structured_diff(before: str, after: str) -> dict:
    """Count additions, deletions, modifications, plus a small classification."""
    bl = before.splitlines()
    al = after.splitlines()

    changes, approximate = _changes(bl, al)
    additions = [line for sign, line in changes if sign == "+"]
    deletions = [line for sign, line in changes if sign == "-"]

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
        for line in ls[:MAX_DIFF_LINES]:   # bounds the by-content path, where ls can hold every line
            ll = line.lower()
            for label, pat in keywords:
                if re.search(pat, ll):
                    cats[label] = cats.get(label, 0) + 1
                    break
        return cats

    out = {
        "lines_added": len(additions),
        "lines_removed": len(deletions),
        "additions_by_section": categorize(additions),
        "removals_by_section": categorize(deletions),
        "sample_additions": additions[:10],
        "sample_removals": deletions[:10],
    }
    if approximate:
        out["approximate"] = True
    return out


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
            f"UNIFIED DIFF:\n{llm.wrap_untrusted(truncated, 'config_diff')}\n\nReturn the JSON now."
        )
        with llm.entity_hints(hosts=[hostname] if hostname else []):
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

    result = {
        "hostname": hostname, "platform": platform,
        "structured": struct,
        "raw_diff": raw[:16000],
        "redactions_applied": red_b + red_a,
        "explanation": explanation,
    }
    if struct.get("approximate"):
        result["warning"] = _APPROX_NOTE
    return result


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
