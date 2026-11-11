"""Validate the Grafana dashboard against the real /api/metrics output.

``grafana/netlog-ai.json`` must only query metric names the endpoint
actually exposes — a dashboard that invents a name shows empty panels
with no error, so this test cross-checks every PromQL expression in the
file (panel targets and template variables) against the output of
``ai_log_analyzer.metrics.render()`` with a full fixture. It also
asserts the dashboard covers the five required areas (EPS, spool depth,
analysis time, LLM latency/errors, dropped datagrams) and that every
panel has a Prometheus target.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ai_log_analyzer import metrics

REPO_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = REPO_ROOT / "grafana" / "netlog-ai.json"

_METRIC_RE = re.compile(r"\b(netlog_[a-z_]+)\b")

# The five areas the dashboard must cover (v2.3.0 feature 4).
REQUIRED_METRICS = {
    "netlog_ingested_datagrams_total",  # EPS (rate over the counter)
    "netlog_spool_rows",  # spool depth
    "netlog_analysis_seconds_total",  # analysis time
    "netlog_llm_calls_total",  # LLM latency/errors
    "netlog_llm_call_seconds_total",
    "netlog_dropped_datagrams_total",  # dropped datagrams
}


def _load_dashboard() -> dict:
    return json.loads(DASHBOARD.read_text(encoding="utf-8"))


def _promql_strings(node: object) -> list[str]:
    """Every PromQL string in the dashboard: panel exprs and variables."""
    found: list[str] = []
    if isinstance(node, dict):
        expr = node.get("expr")
        if isinstance(expr, str):
            found.append(expr)
        query = node.get("query")
        if isinstance(query, str):
            found.append(query)
        for value in node.values():
            found.extend(_promql_strings(value))
    elif isinstance(node, list):
        for value in node:
            found.extend(_promql_strings(value))
    return found


def _exposed_metric_names() -> set[str]:
    """Metric names the /api/metrics endpoint really emits.

    Rendered from a full fixture so every family appears, including the
    EPS gauge (which needs two samples) and the LLM counters (which need
    observed calls). Two renders share the module's in-process state.
    """
    metrics.reset()
    try:
        metrics.observe_llm_call("openai", 1.5, True)
        metrics.observe_llm_call("openai", 0.5, False)
        metrics.observe_analysis(2.0)
        first = metrics.render(
            version="9.9.9",
            spool=[{"source": "syslog", "rows": 3}],
            drops={"sources": [{"source": "syslog", "udp_drops": 1,
                                "spool_lines_lost": 0, "queue_overflow": 0,
                                "dropped_oversize": 0,
                                "udp_rcvbuf_errors_system": 0}]},
            listeners=[{"id": "syslog", "received": 10}],
            llm_state={"enabled": True, "last_call": {"ok": True}},
            now=100.0,
        )
        second = metrics.render(
            version="9.9.9",
            spool=[],
            drops={"sources": []},
            listeners=[{"id": "syslog", "received": 12}],
            llm_state={"enabled": True, "last_call": {"ok": True}},
            now=110.0,
        )
    finally:
        metrics.reset()
    names: set[str] = set()
    for line in (first + second).splitlines():
        if not line or line.startswith("#"):
            continue
        names.add(re.split(r"[{ ]", line, 1)[0])
    return names


def test_dashboard_parses_and_has_identity():
    dash = _load_dashboard()
    assert dash["title"] == "netlog-ai"
    assert dash["uid"] == "netlog-ai"
    assert dash["schemaVersion"] >= 39
    assert dash["panels"]


def test_every_panel_has_prometheus_targets():
    dash = _load_dashboard()
    panels = [p for p in dash["panels"] if p.get("type") != "row"]
    assert panels, "dashboard has no data panels"
    for panel in panels:
        targets = panel.get("targets") or []
        assert targets, f"panel {panel.get('id')} ({panel.get('title')}) has no targets"
        for target in targets:
            assert target.get("datasource", {}).get("type") == "prometheus", (
                f"panel {panel.get('id')} target is not Prometheus"
            )
            assert target.get("expr"), f"panel {panel.get('id')} has an empty expr"


def test_every_query_uses_only_exposed_metrics():
    dash = _load_dashboard()
    used: set[str] = set()
    for query in _promql_strings(dash):
        used |= set(_METRIC_RE.findall(query))
    assert used, "no metric names found in dashboard queries"
    exposed = _exposed_metric_names()
    assert used <= exposed, (
        f"dashboard queries metric names the endpoint never exposes: "
        f"{sorted(used - exposed)}"
    )


def test_dashboard_covers_required_areas():
    dash = _load_dashboard()
    used: set[str] = set()
    for query in _promql_strings(dash):
        used |= set(_METRIC_RE.findall(query))
    assert REQUIRED_METRICS <= used, (
        f"dashboard is missing required metrics: "
        f"{sorted(REQUIRED_METRICS - used)}"
    )


def test_panel_ids_are_unique():
    dash = _load_dashboard()
    ids = [p["id"] for p in dash["panels"]]
    assert len(ids) == len(set(ids)), "duplicate panel ids"
