"""LLM-as-Judge — score generated playbooks so quality regressions get caught.

The product's core output is a remediation playbook (root cause, phased
actions, CLI, monitoring). Nothing previously measured whether those
playbooks are any good — an LLM regression or a KB edit could silently gut
them. This module scores a playbook 0–10 on four dimensions:

  * **actionability** — are there phases with real, copy-pasteable CLI,
    expected outputs, preventive config?
  * **safety** — do disruptive commands (reload / clear / shutdown) come with
    context, and are secrets/placeholders handled properly?
  * **grounding** — does it reference the real devices it was asked about,
    not invented textbook names (R1, SW2, CR-01)?
  * **completeness** — root cause, risk, verify phase, monitoring rules with
    actual thresholds.

The core is a deterministic heuristic (zero dependencies, CI-safe). Pass
`use_llm=True` to blend in a real LLM judge via the configured provider —
it degrades silently back to the heuristic when no LLM is reachable.

CLI: `ai-log-analyzer eval` scores every playbook in the rule-based KB (a
built-in quality self-test); `--file result.json` scores a saved
/api/analyze result; `--min-score N` turns it into a CI gate.
"""
from __future__ import annotations

import json
import re
from typing import Any

from ai_log_analyzer import llm
from ai_log_analyzer.sanitize import sanitize

# Same placeholder pattern the analyzer scrubs — a playbook naming R1/SW2
# instead of real inventory is hallucinating.
_PLACEHOLDER_RE = re.compile(
    r"\b(?:R[1-9]\d?|SW[1-9]\d?|CR-?\d+|BR-?\d+|"
    r"spine-?[XYN]|leaf-?[XYN]|router-?[XYN]|switch-?[XYN])\b",
    re.IGNORECASE,
)

# Disruptive commands that deserve surrounding context (a note, an expected
# outcome, or a rollback) before an operator pastes them at 3am.
_DISRUPTIVE_RE = re.compile(
    r"\b(?:reload|reboot|restart\s+system|request\s+system\s+(?:reboot|halt)|"
    r"clear\s+(?:bgp|ospf|ip\s+route)|shutdown|write\s+erase|format|"
    r"delete\s+system)\b",
    re.IGNORECASE,
)

_EXPECTED_PHASES = ("diagnose", "mitigate", "remediate", "verify", "optimize")


def _clamp(x: float) -> float:
    return round(max(0.0, min(10.0, x)), 1)


def judge_playbook(deep: dict, devices: list[str] | None = None) -> dict[str, Any]:
    """Score one deep-analysis playbook. Deterministic, no network."""
    notes: list[str] = []
    phases = deep.get("phases") or []
    actions = [a for p in phases if isinstance(p, dict)
               for a in (p.get("actions") or []) if isinstance(a, dict)]
    clis = [c for a in actions for c in (a.get("cli") or {}).values() if c]

    # actionability ─ phases + CLI density + preventive config
    score = 0.0
    phase_names = {str(p.get("name", "")).lower() for p in phases if isinstance(p, dict)}
    score += 4.0 * (len(phase_names & set(_EXPECTED_PHASES)) / len(_EXPECTED_PHASES))
    if clis:
        score += 3.0
        multi_platform = any(len(a.get("cli") or {}) >= 2 for a in actions)
        if multi_platform:
            score += 1.0
    else:
        notes.append("no CLI commands in any phase")
    if deep.get("preventive_config"):
        score += 1.0
    if any(a.get("expected") for a in actions):
        score += 1.0
    actionability = _clamp(score)

    # An empty playbook must not ace safety/grounding "by absence" — with no
    # content to assess those dimensions are neutral, not perfect.
    has_content = bool(clis or (deep.get("root_cause") or "").strip())

    # safety ─ disruptive commands need context; secrets must not appear
    score = 10.0 if has_content else 5.0
    for a in actions:
        for cli in (a.get("cli") or {}).values():
            if cli and _DISRUPTIVE_RE.search(str(cli)):
                if not (a.get("note") or a.get("expected")):
                    score -= 3.0
                    notes.append(f"disruptive command without context: {str(cli)[:60]}")
                else:
                    score -= 0.5
    blob = json.dumps(deep)
    if re.search(r"\$[169]\$[\w./$]{8,}", blob):
        score -= 5.0
        notes.append("playbook contains what looks like a password hash")
    safety = _clamp(score)

    # grounding ─ real hostnames in, placeholders out
    score = 10.0 if has_content else 5.0
    placeholder_hits = len(_PLACEHOLDER_RE.findall(blob))
    if placeholder_hits:
        real = {d.lower() for d in (devices or [])}
        mentions_real = any(d and d in blob.lower() for d in real)
        score -= min(placeholder_hits * 2.0, 6.0) * (0.5 if mentions_real else 1.0)
        notes.append(f"{placeholder_hits} textbook placeholder name(s) (R1/SW2-style)")
    if devices:
        blob_lc = blob.lower()
        if not any(d.lower() in blob_lc for d in devices):
            score -= 2.0
            notes.append("does not mention any affected device by name")
    grounding = _clamp(score)

    # completeness ─ root cause, risk, verify, monitoring with thresholds
    score = 0.0
    if (deep.get("root_cause") or "").strip():
        score += 3.0
    else:
        notes.append("missing root_cause")
    if (deep.get("risk") or "").strip():
        score += 2.0
    if "verify" in phase_names:
        score += 2.0
    monitoring = deep.get("monitoring") or []
    if monitoring:
        score += 1.5
        if any(re.search(r"\d", str(m)) for m in monitoring):
            score += 1.5  # thresholds are numbers, not vibes
        else:
            notes.append("monitoring rules carry no numeric thresholds")
    completeness = _clamp(score)

    overall = _clamp(
        actionability * 0.35 + safety * 0.25 + grounding * 0.2 + completeness * 0.2
    )
    return {
        "scores": {
            "actionability": actionability,
            "safety": safety,
            "grounding": grounding,
            "completeness": completeness,
            "overall": overall,
        },
        "notes": notes[:8],
        "judge": "heuristic",
    }


_LLM_JUDGE_PROMPT = """You are a strict senior NOC engineer reviewing an incident playbook.
Score it 0-10 on: actionability (concrete runnable CLI), safety (disruptive
steps have context/rollback), grounding (real device names, no invented ones),
completeness (root cause, risk, verify steps, monitoring thresholds).
Output STRICT JSON only: {"actionability": N, "safety": N, "grounding": N, "completeness": N}"""


def judge_playbook_llm(deep: dict, devices: list[str] | None = None) -> dict[str, Any] | None:
    """LLM pass — returns None when no provider is reachable or output is junk."""
    if not llm.is_enabled():
        return None
    # Saved analysis results retain raw log samples for the local UI. Treat
    # every field as untrusted before sending the playbook to a provider.
    safe_devices, _ = sanitize(json.dumps(devices or ["unknown"]), mask_pii=True)
    safe_deep, _ = sanitize(json.dumps(deep, indent=1), mask_pii=True)
    prompt = (f"AFFECTED DEVICES: {safe_devices}\n\n"
              f"PLAYBOOK JSON:\n{safe_deep[:6000]}\n\nScore it now.")
    text = llm.query(_LLM_JUDGE_PROMPT, prompt, max_tokens=200)
    if not text:
        return None
    try:
        raw = json.loads(re.sub(r"^```[a-z]*\n?|\n?```$", "", text.strip()))
    except json.JSONDecodeError:
        return None
    if not isinstance(raw, dict):
        return None
    dims = ("actionability", "safety", "grounding", "completeness")
    try:
        scores = {d: _clamp(float(raw[d])) for d in dims}
    except (KeyError, TypeError, ValueError):
        return None
    scores["overall"] = _clamp(sum(scores[d] for d in dims) / 4)
    return {"scores": scores, "notes": [], "judge": "llm"}


def judge(deep: dict, devices: list[str] | None = None, use_llm: bool = False) -> dict[str, Any]:
    """Heuristic verdict, blended 50/50 with the LLM's when one is available."""
    heuristic = judge_playbook(deep, devices)
    if not use_llm:
        return heuristic
    llm_verdict = judge_playbook_llm(deep, devices)
    if llm_verdict is None:
        return heuristic
    blended = {
        k: _clamp((heuristic["scores"][k] + llm_verdict["scores"][k]) / 2)
        for k in heuristic["scores"]
    }
    return {"scores": blended, "notes": heuristic["notes"], "judge": "heuristic+llm"}


def judge_analysis_result(result: dict, use_llm: bool = False) -> dict[str, Any]:
    """Score every action item's playbook in a saved /api/analyze result."""
    items = result.get("action_items") or []
    verdicts = []
    for item in items:
        deep = item.get("deep_analysis") or {}
        if not deep:
            continue
        v = judge(deep, devices=item.get("devices"), use_llm=use_llm)
        verdicts.append({
            "description": item.get("description", ""),
            "severity": item.get("severity", ""),
            **v,
        })
    overall = (round(sum(v["scores"]["overall"] for v in verdicts) / len(verdicts), 1)
               if verdicts else 0.0)
    return {"overall": overall, "playbooks_scored": len(verdicts), "verdicts": verdicts}


def judge_kb(use_llm: bool = False) -> dict[str, Any]:
    """Built-in self-test: score the rule-based KB's playbook for every
    (category, description) the classifier can emit. This is the floor of
    quality users get with the LLM off."""
    from ai_log_analyzer import kb
    from ai_log_analyzer.classifier import _KB_PATTERNS

    seen: set[tuple[str, str]] = set()
    verdicts = []
    for _, severity, category, description in _KB_PATTERNS:
        if severity not in ("critical", "high", "medium"):
            continue
        key = (category, description)
        if key in seen:
            continue
        seen.add(key)
        deep = kb.lookup(category, description)
        v = judge(deep, use_llm=use_llm)
        verdicts.append({"category": category, "description": description, **v})
    verdicts.sort(key=lambda v: v["scores"]["overall"])
    overall = (round(sum(v["scores"]["overall"] for v in verdicts) / len(verdicts), 1)
               if verdicts else 0.0)
    return {"overall": overall, "playbooks_scored": len(verdicts), "verdicts": verdicts}
