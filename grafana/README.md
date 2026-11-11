# Grafana dashboard for netlog-ai

`netlog-ai.json` visualises the self-telemetry that `GET /api/metrics`
exposes in Prometheus format (P4 item 14): ingest rate, spool depth,
dropped datagrams, LLM latency/errors and analysis time. It queries only
metric names that endpoint actually exposes — `tests/test_grafana_dashboard.py`
cross-checks every PromQL expression in this file against the live output
of `ai_log_analyzer.metrics.render()`.

## Panels

| Section | Panel | Query (essence) |
|---|---|---|
| Ingest | Ingest rate (EPS) | `rate(netlog_ingested_datagrams_total[5m])` by source |
| Ingest | Spool depth | `netlog_spool_rows` by source + `netlog_spool_rows_total` (warn 25k / crit 45k rows; default buffer is 50k lines/source) |
| Ingest | Dropped datagrams (5m) / Dropped (1h) | `increase(netlog_dropped_datagrams_total[5m])` by source/reason; red above 0 |
| LLM gateway | LLM latency (mean) | `rate(netlog_llm_call_seconds_total[5m]) / rate(netlog_llm_calls_total[5m])` by provider (warn 5 s / crit 15 s) |
| LLM gateway | LLM error rate | error share of `netlog_llm_calls_total` by provider (warn 5% / crit 20%) |
| LLM gateway | LLM calls | `rate(netlog_llm_calls_total[5m])` by provider/status |
| LLM gateway | LLM enabled / Last LLM call | `netlog_llm_enabled`, `netlog_llm_last_call_ok` |
| Analysis & process | Analysis duration (mean) | `rate(netlog_analysis_seconds_total[5m]) / rate(netlog_analysis_runs_total[5m])` (warn 10 s / crit 60 s) |
| Analysis & process | Analysis runs | `rate(netlog_analysis_runs_total[5m])` |
| Analysis & process | Uptime / Build info | `netlog_uptime_seconds`, `netlog_build_info{version}` |

Template variables `$source` and `$provider` filter the panels that carry
those labels. The scrape-window gauge `netlog_events_per_second` is an
alternative to the `rate()` over `netlog_ingested_datagrams_total` used for
EPS; it only appears once two scrapes exist.

## Prerequisites

1. **Prometheus scraping the app.** Add the job from `docs/OPERATIONS.md`
   ("Dashboard (V2)" → "Prometheus metrics") to `prometheus.yml` — the
   dashboard expects `job="netlog-ai"`:

   ```yaml
   scrape_configs:
     - job_name: netlog-ai
       static_configs:
         - targets: ['127.0.0.1:6060']
       metrics_path: /api/metrics
       # With RBAC on, add: authorization: {credentials: "<viewer-token>"}
   ```

   Verify the scrape works before importing: `curl -s
   http://127.0.0.1:6060/api/metrics` (or with
   `-H "Authorization: Bearer <viewer-token>"`) should return Prometheus
   text, and Prometheus → Status → Targets should show the `netlog-ai`
   job as UP.
2. **A Prometheus datasource in Grafana** pointing at that Prometheus.
   The dashboard uses the `${DS_PROMETHEUS}` variable, so Grafana asks
   which datasource to use on import.

## Import

Grafana → Dashboards → New → Import → paste the contents of
`netlog-ai.json` (or upload the file) → pick the Prometheus datasource
when asked → Import. No other setup is needed; panels that have no data
yet (e.g. no LLM calls since process start) stay empty rather than
erroring — a missing metric means "unknown", not zero.

## Alerts

This is a dashboard, not an alerting system: it carries panel thresholds
(see the table above) but no alert rules — Grafana's dashboard-JSON
`alert` field is the removed legacy alerting format, so rules belong in
Grafana Alerting (or provisioning), not in this file. Three suggested
rules, all against the same `netlog-ai` job:

- **Drops:** `sum(increase(netlog_dropped_datagrams_total{job="netlog-ai"}[5m])) > 0`
  for 5m — any lost line means logs never reached the classifier.
- **Spool not draining:** `netlog_spool_rows_total{job="netlog-ai"} > 45000`
  for 10m — the triage worker is behind the ingest rate.
- **LLM failing:** `sum by (provider) (rate(netlog_llm_calls_total{job="netlog-ai",status="error"}[5m])) / sum by (provider) (rate(netlog_llm_calls_total{job="netlog-ai"}[5m])) > 0.2`
  for 10m — a provider is erroring on more than a fifth of calls.

## Validating changes

```sh
.venv/bin/python -m pytest tests/test_grafana_dashboard.py -q
```

The test loads this JSON, asserts it parses and every panel has a
Prometheus target, and asserts every metric name in every PromQL
expression (panels and template variables) is one the `/api/metrics`
endpoint actually emits. If you add a panel, add the metric to
`metrics.py` first — never invent a name in the dashboard.
