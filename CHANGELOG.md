# Changelog

All notable changes to **netlog-ai** are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); this project uses
loose semantic versioning.

## [0.4.0] - 2026-07-13

### Added

- **Fabric stability engine** (`stability.py`) — per-device flap detection
  (down↔up oscillation of interfaces / BGP peers / OSPF neighbors / LAG
  members / VPN tunnels), event-rate burst detection against each device's
  own baseline, rising/stable/falling trend, and a deterministic 24h risk
  band. Surfaces as `stability` in `/api/analyze` + MCP and a **📶 Fabric
  Stability** panel in the UI (worst devices first, actionable
  recommendations). Streaming-safe: O(devices × entity classes) memory,
  minute-prefix bucketing with arrival-order fallback so unreliable syslog
  timestamps can't break it.
- **LLM-as-Judge playbook scoring** (`judge.py` + `ai-log-analyzer eval`) —
  scores generated playbooks 0–10 on actionability / safety / grounding /
  completeness with a deterministic heuristic core (empty playbooks can't
  ace safety "by absence"; disruptive commands without context are
  penalized; R1/SW2-style placeholder names hurt grounding). Optional
  `--use-llm` blends a real LLM judge via the configured provider, falling
  back silently. `eval` self-tests every rule-based KB playbook by default,
  scores a saved analyze result with `--file`, and `--min-score` makes it a
  CI quality gate.

- **Unknown-pattern template mining** (`patterns.py`) — every line the regex KB
  can't match is mined into templates with a dependency-free Drain-style
  streaming clusterer (variables masked as `<ip>/<mac>/<hex>/<if>/<n>/<ts>`,
  similar shapes merged into `<*>` wildcards, LRU-bounded memory). The
  analyzer surfaces the top templates — error-smelling shapes ranked first —
  as `unknown_patterns` in `/api/analyze`, the MCP `analyze_logs` tool, and a
  new **🔭 Unknown Patterns** panel in the UI. Novel failure modes no longer
  vanish as `info` noise.
- **Custom classification rules** — operators can extend/override the built-in
  KB: a JSON rules file loaded at startup (`AI_LOG_ANALYZER_CUSTOM_RULES`) and
  a runtime API (`GET/POST /api/rules`). Custom rules are checked before the
  built-in patterns, so a known-noise event can be demoted or a site-specific
  failure promoted.
- **Cross-run template persistence** — set `AI_LOG_ANALYZER_TEMPLATE_STORE`
  to a path and the miner remembers every template shape across runs
  (FIFO-bounded JSON store, atomic writes, corrupt-file tolerant). Templates
  never seen in *any* prior run are flagged `is_new` (🆕 in the UI panel,
  `new_template_count` in the API) — the classic AIOps early-warning signal.
- **Coverage wave for phases 0–12 leftovers** — `reports.py` (MD/CSV/HTML
  exporters), `runbook.py` (Ansible/netmiko generation + command extraction),
  `topology.py` (build/exports/finding overlay), and the previously untested
  web routes `/api/report`, `/api/runbook`, `/api/topology`, plus the
  validation paths of `/api/diff` and `/api/copilot`. Suite 294 → 325 tests.

### Security

- **Log lines now pass the sanitize gate before LLM calls.** `deep_analyze()`
  sent raw sample log lines (and severity-promoted raw descriptions) to the
  LLM unsanitized — configs were always scrubbed but logs were not,
  contradicting the sanitize-before-LLM guarantee. Both are now scrubbed, as
  is the executive-summary item list.
- **`/api/sources/<id>/test` and `/api/sources/<id>/fetch` now require the API
  token** — they were the only POST data routes missing the auth gate.
- **`Authorization: Bearer <token>` accepted** everywhere `X-API-Token` is
  (the README documented Bearer; the code only accepted the custom header).

### Fixed

- **MCP server finds bundled sites on pip installs** — `list_sites` /
  `analyze_site` resolved only the repo-root `sites/` symlink and returned
  empty from a `pip install netlog-ai[mcp]` wheel; now uses the same
  env-override → packaged-data → repo-root resolution as the web app.
- **`/api/optimize/site` no longer mislabels device platforms on mixed-vendor
  sites** — it stamped every device with the manifest-level vendor string
  (e.g. `multi (Nokia SRL + Arista cEOS + FRR)`); it now uses the shared
  loader that keeps per-device `platform`.
- **Syslog connector `fetch()` is idempotent** — it used to drain the ring
  buffer, so a correlate → triage sequence on the same source saw zero events
  on the second call. It now snapshots; the deque's `maxlen` bounds memory.
- **Default Ollama model corrected** to `qwen2.5-coder:latest` (was
  `gemma4:latest`, which doesn't exist, breaking the out-of-box default
  provider).
- Env-configured sources no longer leak `verify_tls`/`timeout_seconds` into
  `extra`; `.env.example` and README now document the real security env vars
  (`AI_LOG_ANALYZER_API_TOKEN`, `AI_LOG_ANALYZER_CORS_ORIGINS`,
  `ANALYZER_HOST`, `AI_LOG_ANALYZER_FILE_ROOTS`) and the `ollama` provider.

## [0.3.1] - 2026-06-10

- UI header version badge is now populated live from `/api/health` (the 0.3.0
  wheel shipped a hardcoded "v0.2" badge; the static value is only a fallback).

## [0.3.0] - 2026-06-10

First PyPI release: `pip install netlog-ai`. Headline features: cross-source correlation + per-device triage (12 MCP tools), alert webhooks, streaming analyze (flat memory at any log size), 2.3× faster classification, fully air-gapped UI, self-contained wheels.

### Tests

- **LLM transport + fallback-chain coverage** (llm.py 54% → 69%): provider
  fallback order, claude-only no-fallback contract, prompt-caching payload,
  per-provider error recording, `<think>`-block cleaning — all with a network
  tripwire so no test can ever hit the real (paid) Anthropic API. Suite
  278 → 294.

### Performance

- **Streaming analyze — flat memory at any input size.** `analyze()` now
  consumes any iterable in a single bounded pass (per-severity top-300 heaps,
  action-item groups bounded by the KB table, per-device counters). Measured
  on a 100MB syslog: **651MB → 40MB peak RSS** (16×), identical results.
  `classifier.iter_classify()` is the new lazy building block;
  `classify_events()` keeps its sorted/materialized contract. The web file
  route and the CLI both pass generators end-to-end; the web route gains a
  size guard (`AI_LOG_ANALYZER_MAX_FILE_MB`, default 200 — CPU must fit the
  HTTP worker timeout; the CLI streams multi-GB files without limit).

### Added

- **Alert webhooks** — analyses that find events at/above a severity threshold
  fire a webhook: Slack incoming-webhook or generic JSON POST
  (`AI_LOG_ANALYZER_WEBHOOK_URL` / `_MIN_SEVERITY` / `_FORMAT`). Wired into
  `POST /api/analyze` and per-source analysis; delivery is best-effort (5s
  timeout, failures logged, never breaks the analysis response).

### Repository

- **History rewritten** (2026-06-10): pre-pseudonymization identifiers scrubbed
  from all historical sample blobs, and 21MB of demo videos purged from history
  (now release assets on `media-2026-06`). Clone pack: 26MB → 3.4MB. Old clones
  must be re-cloned or hard-reset.

### Performance

- **Classifier literal gate: 2.3× faster classification** (1.2 → 2.7 MB/s on the
  sample corpus, identical results). Guaranteed literal keywords are extracted
  from each KB pattern's parse tree at import; lines containing none of them
  (the vast majority of real syslog) skip the ordered 75-regex loop entirely.
  Sound by construction — patterns with no provable literal stay always-checked —
  and self-maintaining as KB rules are added. Equivalence + invariants pinned by
  `tests/test_classifier_gate.py`.

### Distribution & data privacy (wave 3)

- **Wheels are now self-contained**: `samples/`, `sites/`, and the entire web UI
  ship as package data (`ai_log_analyzer/data/`, `web/static/`). Previously a
  pip-installed netlog-ai had **no UI and no demo data** (package-data was never
  configured); Docker images booted to an empty sites list. Top-level `samples/`
  and `sites/` remain as symlinks for checkout workflows;
  `AI_LOG_ANALYZER_SAMPLES_DIR` / `AI_LOG_ANALYZER_SITES_DIR` override.
- **Release pipeline**: pushing a `v*` tag builds sdist+wheel, smoke-tests that
  the wheel carries data + UI, publishes to PyPI via trusted publishing, and
  cuts a GitHub release (`.github/workflows/release.yml`).
- **Samples fully re-pseudonymized**: the RIR-assigned local ASN, seven real
  peer ASNs, transit/CDN/IXP provider names, a real circuit ID, and six real
  site codes were replaced with private-range ASNs and neutral identifiers —
  guarded by a regression test so they can't reappear.
- **Air-gapped UI**: cytoscape/elkjs/cytoscape-elk are vendored into
  `web/static/vendor/` (the topology tab previously needed 2.3MB from a CDN);
  a test asserts the UI loads no external scripts.

### Security

- **Closed the `analyze_site()` sanitize bypass** — site-wide cross-device analysis
  sent raw `config_text` to the LLM provider; it now routes every device config
  through `sanitize(mask_pii=True)` like the other LLM paths, locked in by a
  regression test (`tests/test_site_sanitize.py`).
- **Confined `POST /api/analyze {source:"file"}`** to allowlisted roots
  (home + `/var/log` + the checkout; override with `AI_LOG_ANALYZER_FILE_ROOTS`).
  Previously any reachable caller could read arbitrary files via the API.
- `GET /api/llm/status` no longer exposes `last_errors` (upstream error bodies) to
  anonymous callers when an API token is configured.
- CDN `<script>` tags now carry Subresource Integrity hashes.

### Changed

- **Anthropic prompt caching**: system prompts are sent with
  `cache_control: ephemeral` — repeat analyses bill cached input at ~10% price.
- Static text assets use `Cache-Control: no-cache` (ETag revalidation → 304s)
  instead of `no-store` re-downloading ~200KB per page view.
- Dropped the unused D3 bundle (280KB on every page load; `app.js` never used it).
- Version is reported from package metadata (fixed the `ai-log-analyzer` →
  `netlog-ai` distribution-name mismatch that pinned `/api/health` to a hardcoded
  fallback); `pyproject.toml` bumped to 0.2.0 to match.
- Added `CONTRIBUTING.md` (the README already linked it; the file didn't exist).
- `tests/test_sources.py` no longer depends on test execution order
  (registry registration is now a per-test fixture). Suite: 237 → 246 tests.

### Added — DCN AI Intelligence port (cross-source correlation + per-device triage)

Four capabilities harvested from the legacy DCN AI Intelligence tool and re-targeted
to netlog-ai's `LogEvent` / `SourceManager` model. Each is exposed three ways: a Python
library function, an **MCP tool**, and a **web GUI** surface in the **Device** tab.

- **Cross-source correlation** — `correlate.py` · MCP tool `correlate_sources` ·
  `POST /api/correlate` · Device-tab "🔗 Cross-Source Correlation".
  Classifies each source independently and groups by device: a host with actionable
  events in **≥2 sources is `confirmed`**, in **1 source is `suspected`**. Results are
  ranked worst-severity-first with per-source coverage. Pure, O(N) over events,
  FQDN→short-host normalization, never mutates input.
- **Per-device triage** — `device_triage.py` · MCP tool `analyze_device` ·
  `POST /api/triage` · Device-tab "🔬 Device Triage".
  Per-host verdict (HARDWARE / ROUTING / LAG / LICENSE / MEMORY / SECURITY / …), a
  0–100 health score, severity histogram, top-process breakdown, and **frequency-deduped
  error patterns** that normalize hex addresses, IPs, and PIDs (e.g. 120 near-identical
  BGP errors collapse to one pattern). The `sshd` verdict only fires on real error-grade
  events, so healthy login-only devices are not mislabelled.
- **Richer root-cause knowledge base** — `kb.py`.
  Merged the DCN `_AI_KB` content (root cause / risk / resolution steps / Junos + EOS CLI)
  additively into the existing phased entries, plus new `vpn`, `redundancy`, `fpc`, and
  `chassis` categories. Backward compatible — existing KB consumers and tests unaffected.
- **Expanded classifier patterns** — `classifier.py`.
  Backfilled the missing fleet-validated syslog pattern (`inetd` / `xinetd` / `ftpd` →
  `low` / `system`), first-match ordering preserved.

### Added — web GUI wiring

- `POST /api/correlate` and `POST /api/triage` thin-wrapper routes (token-gated when
  `AI_LOG_ANALYZER_API_TOKEN` is set; ok-envelope passthrough; `400` on bad
  `min_severity` / missing `hostname`).
- Device-tab UI for both features, reusing the existing side-section / card / severity
  components — confirmed/suspected badges, per-source coverage pips, verdict banner,
  health ring, severity histogram, and deduped-pattern list.

### Security

- Both new routes validate input at the boundary; correlation/triage never raise for a
  single failing source (errors captured under `skipped`). MCP tools wrap calls so a
  backend failure returns `{ok: false, error}` rather than crashing the session.

### Tests

- 45 new tests across `test_correlate.py`, `test_device_triage.py`, `test_kb_rca.py`,
  `test_mcp_tools.py`, and `test_web_correlate_triage.py`. Full suite: **237 passing**,
  `ruff` clean. Stress-tested: correlation over 1,200 devices in ~0.02 s, triage over
  10,000 events in ~0.008 s.

### Reference

- New capabilities and both MCP tools are documented in
  [`docs/PORTED_FROM_DCN_AI.md`](docs/PORTED_FROM_DCN_AI.md), with the connector / MCP /
  HTTP surface in [`docs/CONNECTORS.md`](docs/CONNECTORS.md).

## [0.1.0]

- Initial public release: multi-vendor network log analyzer with a pluggable LLM backend
  (local Docker Model Runner or Anthropic Claude), source connectors
  (Kibana, Splunk, Loki, LibreNMS, syslog), site-bundle analysis, topology inference from
  config, compliance scanning, and a built-in MCP server.
