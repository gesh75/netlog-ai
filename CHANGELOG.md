# Changelog

All notable changes to **netlog-ai** are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); this project uses
loose semantic versioning.

## [Unreleased]

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
