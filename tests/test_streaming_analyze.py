"""Streaming analyze: bounded-memory pipeline must match the materialized one.

analyze() now consumes any iterable in a single bounded pass. These tests pin
(1) exact equivalence with the classify_events() sorted/materialized contract,
(2) the aggregator's memory bounds, (3) the web size-guard, (4) CLI streaming.
"""
from __future__ import annotations

import argparse
import io
import json
from pathlib import Path

import pytest

from ai_log_analyzer.adapters.file import parse_file
from ai_log_analyzer.analyzer import _aggregate_stream, analyze, build_action_items
from ai_log_analyzer.classifier import LogEvent, classify_events, iter_classify
from ai_log_analyzer.cli import cmd_analyze

SAMPLES = Path(__file__).resolve().parents[1] / "src" / "ai_log_analyzer" / "data" / "samples"


def _corpus() -> list[LogEvent]:
    events: list[LogEvent] = []
    for f in sorted(SAMPLES.glob("*.txt")):
        events.extend(parse_file(f))
    assert events
    return events


# ── equivalence with the materialized pipeline ──────────────────────────────

@pytest.mark.unit
def test_streamed_analyze_matches_classify_events_contract():
    events = _corpus()
    classified, sev_counts, cat_counts = classify_events(events)

    result = analyze(iter(events), use_llm=False)

    assert result.severity_counts == sev_counts
    assert result.category_counts == cat_counts
    # top-300 ordering must reproduce the sorted-materialized list exactly
    assert result.classified_events == classified[:300]


@pytest.mark.unit
def test_generator_and_list_inputs_identical():
    events = _corpus()
    a = analyze(list(events), use_llm=False).to_dict()
    b = analyze(iter(events), use_llm=False).to_dict()
    a.pop("generated_at"), b.pop("generated_at")
    assert a == b


@pytest.mark.unit
def test_build_action_items_unchanged_contract():
    """Legacy callers feed the sorted list; grouping must produce the same
    counts/devices and newest-first sample messages."""
    classified, _, _ = classify_events(_corpus())
    items = build_action_items(classified, llm_top_n=0)
    assert items, "sample corpus should produce action items"
    assert all(i.severity in ("critical", "high", "medium") for i in items)
    assert all(len(i.sample_messages) <= 3 for i in items)


# ── memory bounds ────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_aggregate_stream_is_bounded():
    def synth(n: int):
        for i in range(n):
            yield LogEvent(
                timestamp=f"2026-01-01T{i % 24:02d}:{i % 60:02d}:{i % 60:02d}",
                hostname=f"h{i % 7}", appname="cron", severity_raw="info",
                message=f"job {i} completed",
            )

    top, sev, cat, groups, by_host, miner, tracker = _aggregate_stream(iter_classify(synth(20_000)), top_k=300)
    assert sev["info"] == 20_000
    assert len(top) <= 300
    assert len(by_host) == 7
    assert not groups  # info events never become action items
    # 20k unmatched lines share one shape once numbers are masked → 1 template
    assert miner.cluster_count <= 2
    assert miner.to_dict()["total_unclassified"] == 20_000
    # stability tracker stays bounded too: 7 hosts, capped buckets each
    report = tracker.report()
    assert report["device_count"] == 7
    assert all(len(s.buckets) <= 512 for s in tracker._devices.values())


# ── web size guard + generator path ─────────────────────────────────────────

@pytest.mark.unit
def test_web_file_over_limit_is_413(monkeypatch, tmp_path):
    import ai_log_analyzer.web.app as web_app
    monkeypatch.setattr(web_app, "FILE_ROOTS", [tmp_path])
    monkeypatch.setattr(web_app, "MAX_FILE_MB", 0.0001)  # ~100 bytes
    log = tmp_path / "big.log"
    log.write_text("Jan  1 00:00:01 r1 rpd[1]: bgp peer down hold timer\n" * 20)
    app = web_app.create_app()
    app.config.update(TESTING=True)
    r = app.test_client().post(
        "/api/analyze", json={"source": "file", "path": str(log), "use_llm": False})
    assert r.status_code == 413
    assert "CLI" in r.get_json()["error"]


@pytest.mark.unit
def test_web_empty_file_still_404(monkeypatch, tmp_path):
    import ai_log_analyzer.web.app as web_app
    monkeypatch.setattr(web_app, "FILE_ROOTS", [tmp_path])
    log = tmp_path / "empty.log"
    log.write_text("")
    app = web_app.create_app()
    app.config.update(TESTING=True)
    r = app.test_client().post(
        "/api/analyze", json={"source": "file", "path": str(log), "use_llm": False})
    assert r.status_code == 404


# ── CLI streaming path (was 0% covered) ─────────────────────────────────────

def _ns(**kw) -> argparse.Namespace:
    base = {"frr": None, "file": None, "stdin": False, "tail": 200, "no_llm": True}
    base.update(kw)
    return argparse.Namespace(**base)


@pytest.mark.unit
def test_cli_analyze_file_no_llm(tmp_path, capsys):
    log = tmp_path / "dev.log"
    log.write_text("Jan  1 00:00:01 rt-01 rpd[9]: bgp peer 192.0.2.1 down hold timer expired\n")
    rc = cmd_analyze(_ns(file=[str(log)]))
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["severity_counts"]["high"] == 1


@pytest.mark.unit
def test_cli_analyze_empty_stdin_exits_2(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    rc = cmd_analyze(_ns(stdin=True))
    assert rc == 2
    assert "no input" in capsys.readouterr().err
