"""Prometheus telemetry for netlog-ai itself (P4 item 14).

The tool watches the network; this module lets Prometheus watch the tool.
It is deliberately stdlib-only and takes plain data in :func:`render`, so the
exposition format is unit-testable without booting the web app.

What is exposed
----------------
* ``netlog_spool_rows{source}`` — syslog spool depth per source, from
  ``StateDB.spool_stats()`` (a cheap ``spool_meta`` read, never ``COUNT(*)``).
* ``netlog_dropped_datagrams_total{source,reason}`` — cumulative lost lines
  per source and reason, from the durable P3 backpressure counters
  (``udp_drops``, ``spool_lines_lost``, ``queue_overflow``,
  ``dropped_oversize``, ``udp_rcvbuf_errors_system``).
* ``netlog_ingested_datagrams_total{source}`` — cumulative datagrams received
  per listener, from the listener's in-memory ``stats()``; Prometheus
  ``rate()`` over this counter is the ingest rate.
* ``netlog_events_per_second{source}`` — gauge over the window between two
  scrapes, computed from successive ``received`` samples kept in this module.
  It appears only once two samples exist, so the first scrape never reports
  a misleading 0.
* ``netlog_llm_calls_total{provider,status}`` and
  ``netlog_llm_call_seconds_total{provider}`` — per-provider call counts
  (``ok``/``error``) and summed latency, recorded in :func:`llm.query` via
  :func:`observe_llm_call`. There was no LLM latency/error counter before
  P4; this is the single place that keeps one.
* ``netlog_analysis_runs_total`` and ``netlog_analysis_seconds_total`` —
  completed ``/api/analyze`` runs and their summed wall time, recorded via
  :func:`observe_analysis`. Only runs that reach the analyzer count.
* ``netlog_llm_enabled`` / ``netlog_llm_last_call_ok`` — 0/1 gauges from
  ``llm.get_state()``; ``netlog_build_info{version}`` and
  ``netlog_process_start_time_seconds`` for the scrape target itself.

All state here is in-process and resets on restart; the counters are meant
to be scraped, not persisted. A scrape never writes to the state DB and
never probes an LLM provider.
"""
from __future__ import annotations

import threading
import time
from collections.abc import Mapping
from typing import Any

# Process start, for netlog_process_start_time_seconds.
_STARTED_AT = time.time()
_STARTED_MONO = time.monotonic()

_LOCK = threading.Lock()

# (provider, status) -> calls; provider -> summed seconds. status is "ok"/"error".
_llm_calls: dict[tuple[str, str], int] = {}
_llm_seconds: dict[str, float] = {}

# Completed /api/analyze runs and their summed wall time.
_analysis_runs = 0
_analysis_seconds = 0.0

# Last (monotonic time, cumulative received) per listener source, for the
# events-per-second gauge. Filled by render() on each scrape.
_ingest_samples: dict[str, tuple[float, int]] = {}


def reset() -> None:
    """Clear all in-process counters (tests only)."""
    global _analysis_runs, _analysis_seconds
    with _LOCK:
        _llm_calls.clear()
        _llm_seconds.clear()
        _analysis_runs = 0
        _analysis_seconds = 0.0
        _ingest_samples.clear()


def observe_llm_call(provider: str, seconds: float, ok: bool) -> None:
    """Record one finished provider call (success or failure)."""
    with _LOCK:
        key = (provider, "ok" if ok else "error")
        _llm_calls[key] = _llm_calls.get(key, 0) + 1
        _llm_seconds[provider] = _llm_seconds.get(provider, 0.0) + max(0.0, seconds)


def observe_analysis(seconds: float) -> None:
    """Record one completed /api/analyze run."""
    global _analysis_runs, _analysis_seconds
    with _LOCK:
        _analysis_runs += 1
        _analysis_seconds += max(0.0, seconds)


def uptime_seconds() -> float:
    """Seconds since this process started."""
    return max(0.0, time.monotonic() - _STARTED_MONO)


def _escape(value: str) -> str:
    """Escape a Prometheus label value."""
    return value.replace("\\", r"\\").replace('"', r"\"").replace("\n", r"\n")


def _fmt(value: float) -> str:
    """Format a sample value (integers without a decimal point)."""
    if value == int(value) and abs(value) < 1e15:
        return str(int(value))
    return repr(value)


def _gauge(lines: list[str], name: str, help_text: str, value: float,
           labels: Mapping[str, str] | None = None) -> None:
    label_str = ""
    if labels:
        label_str = "{" + ",".join(f'{k}="{_escape(str(v))}"' for k, v in labels.items()) + "}"
    lines.append(f"# HELP {name} {help_text}")
    lines.append(f"# TYPE {name} gauge")
    lines.append(f"{name}{label_str} {_fmt(value)}")


def _counter(lines: list[str], name: str, help_text: str, value: float,
             labels: Mapping[str, str] | None = None) -> None:
    label_str = ""
    if labels:
        label_str = "{" + ",".join(f'{k}="{_escape(str(v))}"' for k, v in labels.items()) + "}"
    lines.append(f"# HELP {name} {help_text}")
    lines.append(f"# TYPE {name} counter")
    lines.append(f"{name}{label_str} {_fmt(value)}")


def render(*, version: str,
           spool: list[dict[str, Any]] | None = None,
           drops: dict[str, Any] | None = None,
           listeners: list[dict[str, Any]] | None = None,
           llm_state: dict[str, Any] | None = None,
           now: float | None = None) -> str:
    """Render the full Prometheus exposition text from plain input data.

    ``spool`` is ``StateDB.spool_stats()`` rows, ``drops`` is
    ``StateDB.backpressure_status()``, ``listeners`` is a list of listener
    ``stats()`` dicts (each with at least ``id`` and ``received``), and
    ``llm_state`` is ``llm.get_state()``. Any of them may be ``None`` when
    the source is unavailable — its metrics are then omitted, never faked.
    ``now`` is the monotonic clock, injectable for tests.
    """
    now = time.monotonic() if now is None else now
    lines: list[str] = []

    _gauge(lines, "netlog_build_info", "Build info for this netlog-ai process.", 1,
           {"version": version})
    _gauge(lines, "netlog_process_start_time_seconds",
           "Start time of this netlog-ai process, in unixtime.", _STARTED_AT)
    _gauge(lines, "netlog_uptime_seconds",
           "Seconds since this netlog-ai process started.", uptime_seconds())

    # ── Spool depth ──────────────────────────────────────────────────
    if spool is not None:
        total_rows = 0
        for row in spool:
            rows = int(row.get("rows", 0) or 0)
            total_rows += rows
            _gauge(lines, "netlog_spool_rows", "Syslog spool depth, in rows.",
                   rows, {"source": str(row.get("source", "?"))})
        _gauge(lines, "netlog_spool_rows_total", "Total syslog spool depth, in rows.",
               total_rows)

    # ── Dropped datagrams (durable P3 backpressure counters) ────────
    if drops is not None:
        for src in drops.get("sources", []) or []:
            source = str(src.get("source", "?"))
            for reason in ("udp_drops", "spool_lines_lost", "queue_overflow",
                           "dropped_oversize", "udp_rcvbuf_errors_system"):
                if reason in src:
                    _counter(lines, "netlog_dropped_datagrams_total",
                             "Lost syslog lines, by source and reason.",
                             float(int(src[reason] or 0)),
                             {"source": source, "reason": reason})

    # ── Ingest counters + events-per-second gauge ────────────────────
    if listeners is not None:
        with _LOCK:
            for listener in listeners:
                source = str(listener.get("id", "?"))
                received = listener.get("received")
                if received is None:
                    continue
                received = int(received)
                _counter(lines, "netlog_ingested_datagrams_total",
                         "Datagrams received by the listener, cumulative.",
                         received, {"source": source})
                prev = _ingest_samples.get(source)
                _ingest_samples[source] = (now, received)
                if prev is not None:
                    dt = now - prev[0]
                    if dt > 0:
                        eps = max(0.0, (received - prev[1]) / dt)
                        _gauge(lines, "netlog_events_per_second",
                               "Ingest rate over the window between scrapes.",
                               eps, {"source": source})

    # ── LLM calls: latency + errors ──────────────────────────────────
    with _LOCK:
        llm_calls = dict(_llm_calls)
        llm_seconds = dict(_llm_seconds)
        analysis_runs = _analysis_runs
        analysis_seconds = _analysis_seconds
    providers = sorted({p for (p, _s) in llm_calls} | set(llm_seconds))
    for provider in providers:
        for status in ("ok", "error"):
            _counter(lines, "netlog_llm_calls_total",
                     "LLM provider calls, by provider and outcome.",
                     llm_calls.get((provider, status), 0),
                     {"provider": provider, "status": status})
        _counter(lines, "netlog_llm_call_seconds_total",
                 "Summed LLM provider call latency, in seconds.",
                 llm_seconds.get(provider, 0.0), {"provider": provider})
    _counter(lines, "netlog_analysis_runs_total",
             "Completed /api/analyze runs.", analysis_runs)
    _counter(lines, "netlog_analysis_seconds_total",
             "Summed /api/analyze wall time, in seconds.", analysis_seconds)

    # ── LLM state ────────────────────────────────────────────────────
    if llm_state is not None:
        _gauge(lines, "netlog_llm_enabled",
               "1 when the LLM gateway is enabled, else 0.",
               1 if llm_state.get("enabled") else 0)
        last_call = llm_state.get("last_call")
        last_ok: float | None = None
        if isinstance(last_call, dict) and "ok" in last_call:
            last_ok = 1 if last_call["ok"] else 0
        if last_ok is not None:
            _gauge(lines, "netlog_llm_last_call_ok",
                   "1 when the last LLM call succeeded, 0 when it failed.",
                   last_ok)

    return "\n".join(lines) + "\n"
