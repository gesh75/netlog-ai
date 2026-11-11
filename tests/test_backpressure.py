"""Backpressure signalling (P3 item 13): summaries, audit watermarks,
durable publishing, the overview feed and the dashboard warning."""
from __future__ import annotations

from collections import Counter

import pytest

import ai_log_analyzer.web.app as web_app
from ai_log_analyzer.backpressure import (
    next_audit_watermark,
    publish,
    summarize,
)
from ai_log_analyzer.state_store import StateDB, open_db
from ai_log_analyzer.web.app import create_app

pytestmark = pytest.mark.unit


# ── pure logic ────────────────────────────────────────────────────────────

def test_summarize_zero_is_quiet():
    out = summarize({})
    assert out["total"] == 0 and out["warning"] is False
    assert "No syslog drops" in out["message"]


def test_summarize_totals_drop_keys_only():
    out = summarize({"udp_drops": 12, "queue_overflow": 3, "received": 9999,
                     "udp_rcvbuf_errors_system": 50})
    assert out["total"] == 15 and out["warning"] is True
    assert "udp drops 12" in out["message"] and "queue overflow 3" in out["message"]


def test_next_audit_watermark():
    assert next_audit_watermark(0, 0) is None
    assert next_audit_watermark(5, 0) == 5          # first drop audits at once
    assert next_audit_watermark(5, 5) is None
    assert next_audit_watermark(999, 5) is None
    assert next_audit_watermark(1_000, 5) == 1_000
    assert next_audit_watermark(1_500, 1_000) is None
    assert next_audit_watermark(2_500, 1_000) == 2_000


# ── durable publishing + audit ────────────────────────────────────────────

@pytest.fixture
def db(tmp_path, monkeypatch):
    path = tmp_path / "state.db"
    monkeypatch.setenv("AI_LOG_ANALYZER_STATE_DB", str(path))
    return StateDB(path)


def _audit_rows(db):
    return db.audit_query(action="syslog_backpressure", limit=100)


def test_publish_persists_and_audits_first_drop(db):
    summary = publish(db, "syslog", {"udp_drops": 7})
    assert summary is not None and summary["total"] == 7 and summary["warning"] is True
    status = db.backpressure_status()
    assert status["warning"] is True and status["total_drops"] == 7
    assert status["sources"][0]["source"] == "syslog"
    rows = _audit_rows(db)
    assert len(rows) == 1 and rows[0]["target"] == "syslog"
    assert rows[0]["detail"]["total_drops"] == 7


def test_publish_unchanged_is_silent(db):
    publish(db, "syslog", {"udp_drops": 7})
    assert publish(db, "syslog", {"udp_drops": 7}) is None
    assert len(_audit_rows(db)) == 1


def test_publish_audits_again_per_thousand(db):
    publish(db, "syslog", {"udp_drops": 5})
    publish(db, "syslog", {"udp_drops": 900})
    assert len(_audit_rows(db)) == 1
    publish(db, "syslog", {"udp_drops": 1_500})
    assert len(_audit_rows(db)) == 2
    assert _audit_rows(db)[0]["detail"]["total_drops"] == 1_500


def test_backpressure_status_aggregates_sources(db):
    db.backpressure_report("a", {"udp_drops": 2})
    db.backpressure_report("b", {"spool_lines_lost": 3, "queue_overflow": 1})
    status = db.backpressure_status()
    assert status["total_drops"] == 6 and status["warning"] is True
    assert {s["source"] for s in status["sources"]} == {"a", "b"}


def test_backpressure_status_empty_is_quiet(db):
    assert db.backpressure_status() == {
        "enabled": True, "sources": [], "total_drops": 0, "warning": False}


# ── listener wiring (no socket: stub the attributes _publish_backpressure needs) ──

def test_listener_heartbeat_publishes_counters(db, monkeypatch):
    from ai_log_analyzer.sources.syslog import SyslogListenerSource

    monkeypatch.setenv("AI_LOG_ANALYZER_STATE_DB", str(db.path))
    listener = object.__new__(SyslogListenerSource)
    listener._db = db
    listener.name = "syslog"
    listener.role = "listener"
    listener.proto = "udp"
    listener._stats = Counter({"udp_drops": 4, "spool_lines_lost": 1})
    listener._snmp_base = None
    listener._publish_backpressure()
    status = db.backpressure_status()
    assert status["total_drops"] == 5 and status["warning"] is True
    assert len(_audit_rows(db)) == 1


def test_reader_never_publishes(db):
    from ai_log_analyzer.sources.syslog import SyslogListenerSource

    listener = object.__new__(SyslogListenerSource)
    listener._db = db
    listener.name = "syslog"
    listener.role = "reader"
    listener.proto = "udp"
    listener._stats = Counter({"udp_drops": 4})
    listener._snmp_base = None
    listener._publish_backpressure()
    assert db.backpressure_status()["total_drops"] == 0


# ── overview feed + dashboard ─────────────────────────────────────────────

@pytest.fixture
def client(tmp_path, monkeypatch):
    path = tmp_path / "state.db"
    monkeypatch.setenv("AI_LOG_ANALYZER_STATE_DB", str(path))
    open_db(path)
    monkeypatch.setattr(web_app, "API_TOKEN", "")
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


def test_overview_carries_backpressure(client, tmp_path):
    body = client.get("/api/status/overview").get_json()
    assert body["backpressure"] == {
        "enabled": True, "sources": [], "total_drops": 0, "warning": False}
    db = open_db(str(list(tmp_path.glob("state.db"))[0]))
    db.backpressure_report("syslog", {"udp_drops": 9})
    body = client.get("/api/status/overview").get_json()
    assert body["backpressure"]["warning"] is True
    assert body["backpressure"]["total_drops"] == 9


def test_dashboard_renders_backpressure_warning():
    import re
    from pathlib import Path

    js = (Path(web_app.STATIC_DIR) / "v2.js").read_text()
    assert re.search(r"paintBackpressure\(s\.backpressure", js)
    assert "Spool: dropping!" in js
