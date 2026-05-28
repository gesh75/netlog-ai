# Scoring Split — Fabric Design vs Operational Readiness

**Status:** shipped 2026-05-27
**Affects:** `POST /api/optimize/site-wide/<site>` and the Site-Wide Strategic
Optimization widget in the web UI.

## Why

The old UI displayed a single `maturity_score` (0–100) for the entire site.
This conflated two independent failure modes:

1. **Fabric design issues** — single ISP, missing HA, EOL software, no overlay,
   weak BGP tuning. These are *architectural* — fixing them needs hardware,
   circuits, or topology change.
2. **Operational hygiene gaps** — missing NTP / syslog / AAA / SNMPv3, weak
   monitoring, failing compliance checks. These are *process* — fixing them
   is config-only, days of work at most.

When a site scored 28/100, it was impossible to tell from the headline whether
the fabric was wrong or just the day-2 operations layer. After the split, a
site like `clab-clos-evpn` now reads **fabric 80 / ops 0** — instantly readable
as "topology is fine, ops layer is missing."

## What changed

### Backend (`src/ai_log_analyzer/site_optimize.py`)

- New `_CATEGORY_VECTOR` mapping each gap category to one of two vectors:
  - `fabric_design`: `isp_redundancy`, `ha`, `software_lifecycle`,
    `bgp_tuning`, `overlay_fabric`, `capacity`
  - `operational_readiness`: `security`, `monitoring`, `aaa`, `compliance`
- New `_score_vector(gaps, vector)` and `_score_split(gaps)` helpers reuse the
  same severity-penalty table as `_score_maturity`.
- `analyze_site_wide()` now returns both new fields alongside the original
  `maturity_score` (kept for backward compatibility with any existing
  consumers — same penalty calculation, no change in value).
- LLM success path **recomputes the split scores deterministically** from
  validated gaps — the LLM cannot drift the per-vector numbers even if it
  emits a hallucinated `maturity_score`.

### Frontend (`src/ai_log_analyzer/web/static/app.js`)

- The score row in the Site-Wide widget now shows **two score tiles** (Fabric
  Design / 100, Operational Readiness / 100) with independent letter grades
  and tooltips, plus the tier classification on the right.
- Status bar and toast surface both numbers: `fabric 80/100 · ops 0/100`.

## Response shape (added fields)

```jsonc
{
  "site_id": "CLAB-CLOS-EVPN",
  "site_summary": "...",
  "maturity_score": 28,              // composite (back-compat)
  "fabric_design_score": 80,         // NEW
  "operational_readiness_score": 0,  // NEW
  "maturity_tier": "Tier 2",
  "gaps": [...],
  "facts": {...}
}
```

## Validation

| Site | Fabric | Ops | Composite | Tier |
|---|---|---|---|---|
| clab-clos-evpn | 80 | 0  | 28 | Tier 2 |
| dcn-lab        | 80 | 18 | 15 | Tier 1 |
| lab-alpha      | 80 | 18 | 32 | Tier 1 |
| lab-bravo      | 80 | 18 | 15 | Tier 1 |

Across all four sites, the fabric layer is consistently good (80/100) while
ops hygiene is the binding constraint — a finding the old composite score
fully hid.

---

# Hostname Anchoring (LLM Prompt Hardening)

## Why

The LLM occasionally emitted invented hostnames like `CR-01`, `BR-01`, or
`spine-X` in `config_changes`, even though the inventory (`facts.devices`)
contained the real hostnames (`leaf1`, `spine2`, etc.). Operators copying
those `config_changes` blocks would paste commands referencing nonexistent
devices.

## What changed

- New `_allowed_hostnames(facts)` helper extracts the canonical hostname list
  from `facts.devices` as a sorted, lowercased array.
- `_build_user_prompt` and `_build_retry_prompt` now prepend an explicit
  `ALLOWED_HOSTNAMES` array to the LLM input.
- The system prompt has a new **HOSTNAME ANCHORING** section forbidding
  invented names and explaining that unknown hosts will be silently dropped.
- `_validate_gaps(raw, allowed_hostnames=...)` performs case-insensitive
  membership filtering: any key in `config_changes` not in the inventory is
  dropped before the response is returned to the client.

## Validation

Stress test across 4 sites (28 devices total) with LLM enabled: **0 invented
hostnames** leaked into any `config_changes` block. Filter behavior verified
by `test_llm_hostname_anchoring_drops_invented_hosts` (synthetic LLM response
with `CR-01` and `BR-99` — both stripped, real `x-fw-01` retained).

## Architecture diagram

```
                      POST /api/optimize/site-wide/<id>
                                  │
                                  ▼
              ┌───────────────────────────────────────┐
              │  collect_site_facts(site_id, devices) │
              │  → facts {devices, isps, bgp, ops…}   │
              └────────────────┬──────────────────────┘
                               │
                               ▼
                ┌─────────────────────────────┐
                │  _allowed_hostnames(facts)  │  ◀── single source of truth
                │  → ["leaf1","spine2",…]     │
                └────────────────┬────────────┘
                                 │
                                 ▼
           ┌───────────────────────────────────────────┐
           │  _build_user_prompt(facts)                │
           │  prepends: ALLOWED_HOSTNAMES = [...]      │
           └────────────────┬──────────────────────────┘
                            │
                            ▼
                    ┌────────────────┐
                    │  llm.query(…)  │
                    └───────┬────────┘
                            │ raw JSON
                            ▼
                  ┌─────────────────────┐
                  │  _try_parse_json    │
                  └──────────┬──────────┘
                             │
                             ▼
       ┌─────────────────────────────────────────────┐
       │  _validate_analysis(obj, allowed_hostnames) │
       │   └─ _validate_gaps(raw, allowed_hostnames) │
       │      └─ drops config_changes keys ∉ inventory│
       └────────────────────┬────────────────────────┘
                            │ validated dict
                            ▼
              ┌───────────────────────────────┐
              │  _score_split(validated.gaps) │
              │  → fabric_design_score        │
              │  → operational_readiness_score│
              │  → maturity_score (composite) │
              └────────────────┬──────────────┘
                               │
                               ▼
                       JSON response
                               │
                               ▼
                 ┌─────────────────────────┐
                 │  app.js renderSiteWide()│
                 │  two score tiles + tier │
                 └─────────────────────────┘
```

## Test coverage

`tests/test_site_optimize.py` (11/11 pass):

- `test_split_scores_present_in_deterministic_path`
- `test_split_scores_categorize_correctly`
- `test_llm_hostname_anchoring_drops_invented_hosts`
- `test_allowed_hostnames_helper_extracts_from_facts`

Full repo suite: **219 passed, 0 failed**.
