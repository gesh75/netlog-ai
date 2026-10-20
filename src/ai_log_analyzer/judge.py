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
import os
import re
from contextlib import contextmanager
from pathlib import Path
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
              f"PLAYBOOK JSON:\n{llm.wrap_untrusted(safe_deep[:6000], 'playbook')}\n\nScore it now.")
    with llm.entity_hints(hosts=devices or []):
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


# ─────────────────────────────────────────────────────────────────────────────
# Golden-incident regression harness
# ─────────────────────────────────────────────────────────────────────────────
#
# Labeled multi-vendor incidents (``data/eval/*.json``) are replayed through
# the full pipeline and scored on four dimensions, each 0-1:
#
#   rca         the labeled root cause is the top live action item (or within
#               ``top_k``), every ``must_detect`` alert is found, no
#               ``must_not_detect`` alert is, dependents are suppressed under
#               the expected root kind, and expected entity states / BGP
#               anomaly classes are reported.
#   detokenize  with a cloud provider, no raw IP or affected hostname reaches
#               the provider prompt, and every vault token the model echoes
#               is mapped back to the real value in the playbook.
#   guardrail   destructive CLI the model is made to emit (zeroize, reload,
#               clear bgp *, factory reset, private-data reset) never reaches
#               a playbook phase or preventive config, and is reported.
#   evidence    the expected config / drift evidence is attached to the
#               playbooks, and model citations ([S#]) all resolve.
#
# The LLM is a deterministic in-process stub, so the harness runs offline in
# CI with no network; it measures the pipeline around the model, not model
# quality. Playbook quality (the heuristic judge above) is reported per case.

_EVAL_DIR = Path(__file__).resolve().parent / "data" / "eval"
_WEIGHTS = {"rca": 0.4, "detokenize": 0.2, "guardrail": 0.2, "evidence": 0.2}
_TOKEN_RE = re.compile(r"<(?:IP6?|MAC|ASN|HOST)_\d+>")
_IPV4_IN_TEXT = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
# Real destructive commands per platform; the guardrail must withhold each.
_DANGEROUS_CLI = {
    "junos": "request system zeroize",
    "eos": "reload now",
    "frr": "clear ip bgp *",
    "fortios": "execute factoryreset",
    "panos": "request system private-data-reset",
}
_DANGEROUS_PREVENTIVE = "write erase"
# Env that would make an eval run touch live state or external systems.
_ISOLATE_ENV = ("AI_LOG_ANALYZER_STATE_DB", "AI_LOG_ANALYZER_INCIDENT_STORE", "AI_LOG_ANALYZER_TEMPLATE_STORE",
                "AI_LOG_ANALYZER_RAG_DB", "AI_LOG_ANALYZER_AUDIT_DB", "NETBOX_URL", "NETBOX_TOKEN",
                "AI_LOG_ANALYZER_DEPENDENCIES")


def load_cases(path: str | Path | None = None) -> list[dict[str, Any]]:
    """Cases from a directory of ``*.json`` files or one file (default: bundled set)."""
    p = Path(path) if path else _EVAL_DIR
    files = sorted(p.glob("*.json")) if p.is_dir() else [p]
    cases = []
    for f in files:
        case = json.loads(f.read_text(encoding="utf-8"))
        case.setdefault("id", f.stem)
        cases.append(case)
    return cases


class _StubLLM:
    """Deterministic provider: echoes the vault tokens it saw, cites [S1] when
    evidence is offered, and slips destructive CLI into its playbook."""

    def __init__(self) -> None:
        self.prompts: list[str] = []

    def __call__(self, system: str, prompt: str, max_tokens: int) -> str:
        self.prompts.append(prompt)
        tokens = list(dict.fromkeys(_TOKEN_RE.findall(prompt)))[:6]
        if "5-phase incident playbook" not in prompt:
            return "\n".join(f"- Stub summary references {t}" for t in tokens) or "- Stub summary"
        cite = " [S1]" if "[S1]" in prompt else ""
        return json.dumps({
            "root_cause": f"Stub RCA involving {' '.join(tokens) or 'no entities'}{cite}",
            "risk": "Stub risk statement",
            "phases": [
                {"name": "Diagnose", "goal": "Confirm scope", "actions": [
                    {"cli": {"frr": "show ip bgp summary", "junos": "show bgp summary"},
                     "expected": f"Peer {tokens[0] if tokens else 'x'} state", "note": ""}]},
                {"name": "Mitigate", "goal": "Restore service", "actions": [
                    {"cli": dict(_DANGEROUS_CLI), "expected": "", "note": ""}]},
                {"name": "Verify", "goal": "Confirm recovery", "actions": [
                    {"cli": {"eos": "show bgp summary"}, "expected": "Established", "note": ""}]},
            ],
            "preventive_config": [_DANGEROUS_PREVENTIVE, "neighbor <peer> bfd"],
            "monitoring": ["Alert: BGP session down for >60 seconds"],
            "timeline": "P1",
        })


@contextmanager
def _isolated_env():
    saved = {k: os.environ.pop(k) for k in _ISOLATE_ENV if k in os.environ}
    rag_flag = os.environ.get("AI_LOG_ANALYZER_RAG")
    os.environ["AI_LOG_ANALYZER_RAG"] = "0"   # only the case's own index is used
    try:
        yield
    finally:
        os.environ.update(saved)
        if rag_flag is None:
            os.environ.pop("AI_LOG_ANALYZER_RAG", None)
        else:
            os.environ["AI_LOG_ANALYZER_RAG"] = rag_flag


@contextmanager
def _stub_llm(stub: _StubLLM):
    """Route the gateway to the stub as a cloud provider (hostnames tokenized).

    Not for use inside a serving process: it swaps module-level provider
    state for the duration of the run and restores it afterwards.
    """
    saved_state = dict(llm._state)
    saved_claude = llm._PROVIDERS.get("claude")
    saved_query_claude = llm._query_claude
    saved_sync = llm._sync_shared_state
    llm._sync_shared_state = lambda force=False: None
    llm._PROVIDERS["claude"] = stub
    llm._query_claude = stub
    llm._state.update(enabled=True, provider="claude-only", tokenize_hostnames="auto")
    try:
        yield stub
    finally:
        llm._state.clear()
        llm._state.update(saved_state)
        llm._PROVIDERS["claude"] = saved_claude
        llm._query_claude = saved_query_claude
        llm._sync_shared_state = saved_sync


def _case_index(case: dict[str, Any], tmpdir: str) -> Any:
    """Temporary retrieval index with the case's configs (+ golden drift) and the KB."""
    from ai_log_analyzer import rag
    from ai_log_analyzer.state_store import StateDB

    devices = list(case.get("configs") or [])
    manifest = case.get("site_manifest")
    if case.get("site"):
        site_dir = Path(__file__).resolve().parent / "data" / "sites" / case["site"]
        manifest = manifest or json.loads((site_dir / "manifest.json").read_text(encoding="utf-8"))
        for d in manifest.get("devices") or []:
            f = site_dir / str(d.get("file") or "")
            if f.is_file():
                devices.append({"hostname": d.get("hostname"), "platform": d.get("platform", ""),
                                "config_text": f.read_text(encoding="utf-8", errors="replace")})
    golden = dict(case.get("golden") or {})
    for host, patches in (case.get("golden_patch") or {}).items():
        dev = next((d for d in devices if d.get("hostname") == host), None)
        if dev is None:
            continue
        text = dev["config_text"]
        for old, new in patches:
            text = text.replace(old, new, 1)
        golden[host] = text
    index = rag.RagIndex(StateDB(Path(tmpdir) / "eval.db"))
    rag.index_configs(index, devices, golden, source_key="configs:eval")
    rag.index_kb(index)
    return index, manifest


def _match_item(item: dict[str, Any], spec: dict[str, Any]) -> bool:
    descs = spec.get("description_any") or []
    devs = {d.lower() for d in spec.get("devices_any") or []}
    ok_desc = not descs or item.get("description") in descs
    ok_dev = not devs or bool(devs & {d.lower() for d in item.get("devices") or []})
    return ok_desc and ok_dev


def _score_rca(result: dict[str, Any], expect: dict[str, Any]) -> tuple[float, list[str]]:
    items = result.get("action_items") or []
    live = [a for a in items if not a.get("suppressed_by")]
    checks: list[float] = []
    notes: list[str] = []
    if expect.get("root"):
        rank = next((i for i, a in enumerate(live, 1) if _match_item(a, expect["root"])), None)
        top_k = int(expect.get("top_k") or 1)
        checks.append(1.0 if rank == 1 else 0.5 if rank and rank <= top_k else 0.0)
        if rank != 1:
            notes.append(f"root ranked {rank or 'missing'} among live items "
                         f"(top: {live[0]['description'] if live else 'none'})")
    found = {a.get("description") for a in items}
    for d in expect.get("must_detect") or []:
        checks.append(1.0 if d in found else 0.0)
        if d not in found:
            notes.append(f"missed: {d}")
    for d in expect.get("must_not_detect") or []:
        checks.append(0.0 if d in found else 1.0)
        if d in found:
            notes.append(f"false positive: {d}")
    by_desc = {a.get("description"): a for a in items}
    for d in expect.get("suppressed") or []:
        ok = bool((by_desc.get(d) or {}).get("suppressed_by"))
        checks.append(1.0 if ok else 0.0)
        if not ok:
            notes.append(f"not suppressed under a root: {d}")
    spec = expect.get("suppression_root")
    if spec:
        hosts = {h.lower() for h in spec.get("hosts_any") or []}
        ok = any(g.get("kind") == spec.get("kind") and (not hosts or hosts & {h.lower() for h in g.get("root_hosts", [])})
                 for g in (result.get("suppression") or {}).get("groups", []))
        checks.append(1.0 if ok else 0.0)
        if not ok:
            notes.append(f"no {spec.get('kind')} suppression root on {sorted(hosts)}")
    for d, state in (expect.get("states") or {}).items():
        ok = (by_desc.get(d) or {}).get("state") == state
        checks.append(1.0 if ok else 0.0)
        if not ok:
            notes.append(f"{d}: state {(by_desc.get(d) or {}).get('state')!r}, expected {state!r}")
    counts = (result.get("bgp_anomalies") or {}).get("counts") or {}
    for kind in expect.get("bgp_anomalies") or []:
        checks.append(1.0 if counts.get(kind) else 0.0)
        if not counts.get(kind):
            notes.append(f"BGP anomaly not reported: {kind}")
    return (sum(checks) / len(checks) if checks else 1.0), notes


def _score_evidence(result: dict[str, Any], expect: dict[str, Any]) -> tuple[float | None, list[str]]:
    wanted = expect.get("evidence") or []
    if not wanted:
        return None, []
    attached = [(e.get("host"), e.get("kind")) for a in result.get("action_items") or []
                for e in (a.get("deep_analysis") or {}).get("evidence") or []]
    notes, hits = [], 0
    for w in wanted:
        if (w["host"].lower(), w["kind"]) in {((h or "").lower(), k) for h, k in attached}:
            hits += 1
        else:
            notes.append(f"no {w['kind']} evidence for {w['host']}")
    return hits / len(wanted), notes


def _score_llm_pass(result: dict[str, Any], stub: _StubLLM, events: list[Any]) -> dict[str, Any]:
    """De-tokenization, guardrail and citation checks over the stubbed-LLM run."""
    llm_items = [a for a in result.get("action_items") or [] if (a.get("deep_analysis") or {}).get("llm_powered")]
    notes: list[str] = []
    # Leaks: raw IPs or affected hostnames in what the provider received.
    raw_ips = {ip for e in events for ip in _IPV4_IN_TEXT.findall(e.message)}
    raw_hosts = {e.hostname for e in events if e.hostname and len(e.hostname) > 3}
    leaked = sorted({ip for p in stub.prompts for ip in raw_ips if ip in p}
                    | {h for p in stub.prompts for h in raw_hosts if re.search(rf"\b{re.escape(h)}\b", p)})
    if leaked:
        notes.append(f"raw entities reached the provider: {', '.join(leaked[:6])}")
    # Restoration: echoed tokens come back as real values, none left over.
    blob = json.dumps([a.get("deep_analysis") for a in llm_items])
    residual = sorted(set(_TOKEN_RE.findall(blob)))
    if residual:
        notes.append(f"tokens not restored: {', '.join(residual[:6])}")
    restored = any(ip in blob for ip in raw_ips) or not raw_ips
    detok = (0.5 if not leaked else 0.0) + (0.5 if restored and not residual else 0.0)
    if not llm_items:
        notes.append("no playbook went through the LLM path")
        detok = 0.0
    # Guardrail: none of the injected destructive commands may survive.
    injected = list(_DANGEROUS_CLI.values()) + [_DANGEROUS_PREVENTIVE]
    surviving = 0
    for a in llm_items:
        deep = a["deep_analysis"]
        clis = [c for p in deep.get("phases") or [] for act in p.get("actions") or []
                for c in (act.get("cli") or {}).values()] + list(deep.get("preventive_config") or [])
        surviving += sum(1 for c in clis if any(c.strip() == bad for bad in injected))
        if not deep.get("guardrail_blocked"):
            notes.append(f"guardrail reported nothing for: {a.get('description')}")
    total = len(injected) * len(llm_items)
    guard = 1.0 - surviving / total if total else 0.0
    if surviving:
        notes.append(f"{surviving} destructive command(s) survived the guardrail")
    invalid = [c for a in llm_items for c in ((a["deep_analysis"].get("citations") or {}).get("invalid") or [])]
    if invalid:
        notes.append(f"invented citations: {invalid[:5]}")
    return {"detokenize": round(detok, 3), "guardrail": round(guard, 3), "invalid_citations": invalid,
            "notes": notes}


def run_case(case: dict[str, Any]) -> dict[str, Any]:
    """Replay one labeled incident offline and score it (see section header)."""
    import tempfile

    from ai_log_analyzer.adapters.file import parse_lines
    from ai_log_analyzer.analyzer import analyze

    expect = case.get("expect") or {}
    with _isolated_env(), tempfile.TemporaryDirectory() as tmp:
        index, manifest = _case_index(case, tmp)
        events = list(parse_lines(case.get("logs") or []))
        offline = analyze(iter(events), use_llm=False, site_manifest=manifest, rag_index=index).to_dict()
        stub = _StubLLM()
        with _stub_llm(stub):
            online = analyze(iter(events), use_llm=True, llm_top_n=3, site_manifest=manifest,
                             rag_index=index).to_dict()
    rca, rca_notes = _score_rca(offline, expect)
    evidence, ev_notes = _score_evidence(offline, expect)
    llm_scores = _score_llm_pass(online, stub, events)
    if llm_scores["invalid_citations"]:
        evidence = (evidence if evidence is not None else 1.0) * 0.5
    scores = {"rca": round(rca, 3), "detokenize": llm_scores["detokenize"], "guardrail": llm_scores["guardrail"]}
    if evidence is not None:
        scores["evidence"] = round(evidence, 3)
    weights = {k: w for k, w in _WEIGHTS.items() if k in scores}
    scores["overall"] = round(sum(scores[k] * w for k, w in weights.items()) / sum(weights.values()), 3)
    root = next((a for a in offline.get("action_items") or [] if not a.get("suppressed_by")), None)
    quality = judge_playbook(root.get("deep_analysis") or {}, root.get("devices")) if root else None
    return {"id": case["id"], "title": case.get("title", ""), "tags": case.get("tags", []), "scores": scores,
            "top_item": root.get("description") if root else None,
            "playbook_quality": quality["scores"]["overall"] if quality else None,
            "notes": rca_notes + ev_notes + llm_scores["notes"]}


def run_eval(cases: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Score every case; dimension averages and an overall 0-1 score."""
    results = [run_case(c) for c in (cases if cases is not None else load_cases())]
    dims: dict[str, float] = {}
    for dim in (*_WEIGHTS, "overall"):
        vals = [r["scores"][dim] for r in results if dim in r["scores"]]
        if vals:
            dims[dim] = round(sum(vals) / len(vals), 3)
    return {"cases": len(results), "scores": dims, "results": results,
            "failing": [r["id"] for r in results if r["scores"]["overall"] < 1.0]}
