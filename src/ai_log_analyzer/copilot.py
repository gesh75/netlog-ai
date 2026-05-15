"""AI Copilot — natural-language Q&A over a site or single device's config.

Inspired by Selector Copilot and NetBrain AI Bot. The operator asks a question
in plain English; the LLM answers using the sanitized config(s) as context.
"""
from __future__ import annotations

from ai_log_analyzer import llm
from ai_log_analyzer.sanitize import sanitize


_COPILOT_SYSTEM_PROMPT = """You are a senior network engineer and SRE acting as the on-shift expert. The user provides a network configuration (one or more devices) and asks a question. Answer concisely, citing specific config lines as evidence when possible. If the question can be answered with a CLI verification command, include that command at the end.

Style:
- 2-5 short paragraphs OR a numbered list. No fluff.
- Quote config lines using backticks.
- If the answer is "no" or "not configured", state that plainly.
- If you're unsure, say so — never invent.
- Suggest 1-2 verification CLI commands at the end labeled "Verify:" """


def ask(question: str, context_blocks: list[dict], max_chars_per_device: int = 8000) -> dict:
    """Answer a question using one or more device configs.

    Args:
        question: user's free-form question
        context_blocks: list of {hostname, platform, config_text}
        max_chars_per_device: truncation per device to fit token budget
    """
    if not llm.get_state()["enabled"]:
        return {"answer": "LLM is disabled — enable it via /api/llm/toggle.",
                "llm_powered": False}

    # CRITICAL: scrub secrets + PII before any external LLM sees the configs.
    # Caller might pass raw configs fetched via SSH — never trust input is safe.
    blocks = []
    total_redactions = 0
    for cb in context_blocks:
        host = cb.get("hostname", "device")
        plat = cb.get("platform", "unknown")
        raw_cfg = cb.get("config_text") or ""
        safe_cfg, n = sanitize(raw_cfg, mask_pii=True)
        total_redactions += n
        cfg = safe_cfg[:max_chars_per_device]
        blocks.append(f"\n========== {host} ({plat}) ==========\n{cfg}")

    user_prompt = (
        f"QUESTION: {question}\n"
        f"\nCONTEXT — {len(context_blocks)} device config(s):\n"
        f"{''.join(blocks)}\n"
        f"\nAnswer the question now."
    )

    text = llm.query(_COPILOT_SYSTEM_PROMPT, user_prompt, max_tokens=1500)
    if not text:
        return {"answer": "LLM call failed — see /api/llm/status for last error.",
                "llm_powered": False}
    return {"answer": text, "llm_powered": True,
            "context_devices": [cb.get("hostname") for cb in context_blocks],
            "redactions_applied": total_redactions}
