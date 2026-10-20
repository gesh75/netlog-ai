"""AI Copilot — natural-language Q&A over a site or single device's config.

Inspired by Selector Copilot and NetBrain AI Bot. The operator asks a question
in plain English; the LLM answers using the sanitized config(s) as context.

Answers must be verifiable. Config lines are numbered (``L120|``) so the
answer can cite ``leaf1 L120-L134``, and when a retrieval index is available
the most relevant stanzas, golden-config drift, runbooks and past incidents
are added as numbered sources (``[S1]``). The response reports which
citations were valid and flags invented labels or out-of-range line numbers.
"""
from __future__ import annotations

import re

from ai_log_analyzer import llm, rag
from ai_log_analyzer.sanitize import sanitize

_LINE_REF_RE = re.compile(r"\b([A-Za-z0-9][\w.-]*)\s+L(\d+)(?:\s*-\s*L?(\d+))?\b")

_COPILOT_SYSTEM_PROMPT = """You are a senior network engineer and SRE acting as the on-shift expert. The user provides a network configuration (one or more devices) and asks a question. Answer concisely, citing specific config lines as evidence when possible. If the question can be answered with a CLI verification command, include that command at the end.

Style:
- 2-5 short paragraphs OR a numbered list. No fluff.
- Quote config lines using backticks.
- If the answer is "no" or "not configured", state that plainly.
- If you're unsure, say so — never invent.
- Suggest 1-2 verification CLI commands at the end labeled "Verify:"
- Config lines are prefixed with their line number (`L12|`). Cite them as `<hostname> L12` or
  `<hostname> L12-L20`; cite numbered EVIDENCE sources as [S1]. Never invent line numbers."""


def _numbered(text: str) -> str:
    return "\n".join(f"L{i}| {line}" for i, line in enumerate(text.splitlines(), 1))


def check_line_refs(text: str, line_counts: dict[str, int]) -> dict[str, list[str]]:
    """Validate ``host Lnn[-Lmm]`` references against the configs actually sent."""
    known = {h.lower(): n for h, n in line_counts.items()}
    valid: list[str] = []
    invalid: list[str] = []
    for host, a, b in _LINE_REF_RE.findall(text or ""):
        n = known.get(host.lower())
        if n is None:
            continue
        lo, hi = int(a), int(b or a)
        ref = f"{host} L{lo}" + (f"-L{hi}" if b else "")
        (valid if 1 <= lo <= hi <= n else invalid).append(ref)
    return {"valid": list(dict.fromkeys(valid)), "invalid": list(dict.fromkeys(invalid))}


def ask(question: str, context_blocks: list[dict], max_chars_per_device: int = 8000,
        *, rag_index: rag.RagIndex | None = None, retrieve: bool = True) -> dict:
    """Answer a question using one or more device configs.

    Args:
        question: user's free-form question
        context_blocks: list of {hostname, platform, config_text}
        max_chars_per_device: truncation per device to fit token budget
        rag_index: retrieval index (defaults to the configured one)
        retrieve: set False to skip retrieved evidence
    """
    if not llm.get_state()["enabled"]:
        return {"answer": "LLM is disabled — enable it via /api/llm/toggle.",
                "llm_powered": False}

    # CRITICAL: scrub secrets + PII before any external LLM sees the configs.
    # Caller might pass raw configs fetched via SSH — never trust input is safe.
    blocks = []
    total_redactions = 0
    line_counts: dict[str, int] = {}
    for cb in context_blocks:
        host = cb.get("hostname", "device")
        plat = cb.get("platform", "unknown")
        raw_cfg = cb.get("config_text") or ""
        safe_cfg, n = sanitize(raw_cfg, mask_pii=True)
        total_redactions += n
        # Number lines only when scrubbing kept the line count, so "L120"
        # still points at line 120 of the operator's file (a multi-line
        # secret block collapsed by sanitize() would shift the numbering).
        if safe_cfg.count("\n") == raw_cfg.count("\n"):
            cfg = _numbered(safe_cfg)[:max_chars_per_device]
            line_counts[host] = cfg.count("\n") + 1 if cfg else 0
        else:
            cfg = safe_cfg[:max_chars_per_device]
        blocks.append(f"\n========== {host} ({plat}) ==========\n"
                      f"{llm.wrap_untrusted(cfg, 'device_config')}")

    hosts = [cb.get("hostname", "") for cb in context_blocks]
    index = rag_index if rag_index is not None else (rag.get_index() if retrieve else None)
    evidence = (rag.retrieve_evidence(index, f"{question} {' '.join(hosts)}", hosts=hosts,
                                      mix={"config": 3, "drift": 3, "incident": 2, "runbook": 1, "topology": 1})
                if retrieve and index is not None else [])

    user_prompt = (
        f"QUESTION: {question}\n"
        f"\nCONTEXT — {len(context_blocks)} device config(s):\n"
        f"{''.join(blocks)}\n"
    )
    if evidence:
        safe_evidence, _ = sanitize(rag.evidence_block(evidence), mask_pii=True)
        user_prompt += (f"\nEVIDENCE (numbered sources):\n{llm.wrap_untrusted(safe_evidence, 'evidence')}\n"
                        f"{rag.CITATION_RULES}\n")
    user_prompt += "\nAnswer the question now."

    with llm.entity_hints(hosts=hosts):
        text = llm.query(_COPILOT_SYSTEM_PROMPT, user_prompt, max_tokens=1500)
    if not text:
        return {"answer": "LLM call failed — see /api/llm/status for last error.",
                "llm_powered": False, "evidence": rag.public_evidence(evidence)}
    return {"answer": text, "llm_powered": True,
            "context_devices": [cb.get("hostname") for cb in context_blocks],
            "redactions_applied": total_redactions,
            "evidence": rag.public_evidence(evidence),
            "citations": {**rag.check_citations(text, evidence),
                          "line_refs": check_line_refs(text, line_counts)}}
