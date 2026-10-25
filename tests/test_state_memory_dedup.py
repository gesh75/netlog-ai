"""Incident memory (timestamps, store cache, incremental reload) and dedup cluster bounds."""
from __future__ import annotations

import pytest

from ai_log_analyzer import memory
from ai_log_analyzer.dedup import NetworkLogDeduplicator, deduplicate_logs
from ai_log_analyzer.state_store import StateDB

pytestmark = pytest.mark.unit


# ── memory ──────────────────────────────────────────────────────────────────

def test_parse_stamp_accepts_a_trailing_z():
    stamp = memory._parse_stamp("2026-10-22T10:00:00Z")
    assert stamp is not None and stamp.utcoffset().total_seconds() == 0
    assert memory._parse_stamp("2026-10-22T10:00:00.123z") is not None
    assert memory._parse_stamp("2026-10-22T10:00:00+02:00").utcoffset().total_seconds() == 7200


def test_get_store_returns_one_cached_store_per_database(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_STATE_DB", str(tmp_path / "s.db"))
    assert memory.get_store() is memory.get_store()
    monkeypatch.setenv("AI_LOG_ANALYZER_STATE_DB", str(tmp_path / "other.db"))
    assert memory.get_store().db.path != StateDB(tmp_path / "s.db").path


def test_recording_does_not_reload_the_whole_journal(tmp_path, monkeypatch):
    """Regression: every analyze() rebuilt the store and re-read up to 5000 rows twice."""
    monkeypatch.setenv("AI_LOG_ANALYZER_STATE_DB", str(tmp_path / "s.db"))
    store = memory.get_store()
    loads = {"n": 0}
    real = store.db.incidents_all

    def counting(limit):
        loads["n"] += 1
        return real(limit)

    store.db.incidents_all = counting
    for i in range(5):
        memory.annotate_and_record([{"description": f"issue {i}", "devices": ["r1"], "severity": "high"}],
                                   f"2026-10-22T10:00:0{i}+00:00")
    assert loads["n"] == 0
    assert len(store) == 5 and store.recurrence("issue 3")["count"] == 1
    assert len(store.records()) == 5


def test_cached_store_sees_other_workers_writes_and_resolutions(tmp_path):
    path = tmp_path / "s.db"
    mine = memory.SqliteIncidentStore(StateDB(path))
    assert mine.recurrence("x") is None
    other = memory.SqliteIncidentStore(StateDB(path))              # another worker: its own connection
    other.record([{"description": "x", "devices": ["r2"]}], "2026-10-22T10:00:00Z")
    assert mine.recurrence("x")["count"] == 1                      # visible without any reload call
    inc = mine.records()[0]["incident_id"]
    assert other.resolve(inc, "swapped the optic", "ops") is not None
    assert mine.get(inc)["resolution"] == "swapped the optic"
    mine.record([{"description": "y", "devices": ["r3"]}], "2026-10-22T11:00:00Z")
    assert {r["description"] for r in other.records()} == {"x", "y"}
    assert mine.get(inc)["resolution"] == "swapped the optic"


# ── dedup bounds ────────────────────────────────────────────────────────────

def _words(i: int) -> str:
    out = ""
    while True:
        out = chr(97 + i % 26) + out
        i //= 26
        if not i:
            return out


def test_cluster_host_set_is_bounded_but_counts_stay_exact():
    lines = [f"Oct 20 10:00:00 host{i} app: link flap" for i in range(3000)]
    result = NetworkLogDeduplicator().deduplicate(lines)
    (cluster,) = result.clusters
    assert cluster.count == 3000 and len(cluster.hosts) <= 1000 and cluster.hosts_truncated
    assert "more" in cluster.to_compact_line()


def test_variable_counters_are_bounded_per_kind():
    lines = [f"Oct 20 10:00:00 r1 app: neighbor 10.{i // 250}.{i % 250}.1 down" for i in range(3000)]
    (cluster,) = NetworkLogDeduplicator().deduplicate(lines).clusters
    assert cluster.count == 3000 and len(cluster.variable_counts["IPV4"]) <= 500


def test_distinct_template_count_is_bounded_with_an_overflow_cluster():
    lines = [f"Oct 20 10:00:00 r1 app: unique {_words(i)} words {_words(i + 7)}" for i in range(400)]
    result = NetworkLogDeduplicator(max_clusters=50).deduplicate(lines)
    assert result.total_lines == 400 and len(result.clusters) <= 51
    assert sum(c.count for c in result.clusters) == 400
    assert any(c.cluster_id == "overflow" for c in result.clusters)


def test_text_input_is_split_like_splitlines_without_materialising_it():
    text = "Oct 20 10:00:00 r1 a: one\r\nOct 20 10:00:01 r1 a: two\rOct 20 10:00:02 r1 a: one\n\n"
    result = deduplicate_logs(text)
    assert result.total_lines == 3 and result.unique_templates == 2
