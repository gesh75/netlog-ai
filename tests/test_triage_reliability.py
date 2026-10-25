"""Triage worker reliability: drain throughput, spool gap accounting, durability across a
crash, sink backoff / partial delivery, lease fencing, dedup semantics and shutdown."""
from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest

from ai_log_analyzer import triage_worker as tw
from ai_log_analyzer.state_store import StateDB
from ai_log_analyzer.triage_worker import MemorySink, StreamingTriageWorker, TriageConfig

pytestmark = pytest.mark.unit

T0 = 1_800_000_000.0
LINK_DOWN = "Oct 20 10:00:00 leaf-07 Ebra: %LINK-3-UPDOWN: Interface Ethernet7, changed state to down"
CONSERVE = ('<185>date=2026-10-20 time=07:05:30 devname="FGT-BR-07" devid="FG60FTK21000007" tz="+0000" vd="root" '
            'logid="0100022011" type="event" subtype="system" level="critical" logdesc="Memory conserve mode entered" '
            'msg="Kernel enters memory conserve mode"')


@pytest.fixture
def db(tmp_path):
    return StateDB(tmp_path / "state.db")


def _feed(db, lines, at, source="syslog-1", sender="10.9.9.9"):
    db.spool_append(source, [(at, sender, ln) for ln in lines], cap=1_000_000)


def _worker(db, sinks=None, owner="w1", **cfg):
    w = StreamingTriageWorker(db, sinks or [MemorySink()], TriageConfig(**cfg), clock=lambda: T0, owner=owner)
    w._rand = lambda: 0.5          # jitter factor 1.0: deterministic backoff
    return w


class _Flaky:
    """A sink that fails until ``ok`` is set; counts every call."""

    def __init__(self, name="flaky", ok=False):
        self.name, self.ok, self.calls = name, ok, 0

    def upsert_incident(self, payload):
        self.calls += 1
        if not self.ok:
            raise ConnectionError("itsm down")
        return {"action": "created", "ref": payload.fingerprint}


# ── throughput and spool gap ────────────────────────────────────────────────

def test_one_tick_drains_a_backlog_larger_than_one_batch(db):
    """Regression: one batch per source per tick capped triage at batch/poll_s rows per second."""
    _feed(db, [f"Oct 20 10:00:00 r1 app: informational message {i}" for i in range(1700)], T0)
    w = _worker(db, batch=500)
    tick = w.run_once(T0)
    assert w.totals["lines_read"] == 1700 and not tick["backlog"]
    assert w.status()["cursors"]["syslog-1"] == 1700


def test_time_budget_bounds_a_tick_and_flags_the_backlog(db):
    _feed(db, [f"Oct 20 10:00:00 r1 app: informational message {i}" for i in range(1200)], T0)
    w = _worker(db, batch=500, tick_budget_s=0.0)
    tick = w.run_once(T0)
    assert tick["backlog"] and w.totals["lines_read"] == 500
    assert w._next_wait() < 1.0                      # the loop re-polls at once instead of sleeping poll_s
    while w.run_once(T0)["backlog"]:
        pass
    assert w.totals["lines_read"] == 1200 and w._next_wait() == w.config.poll_s


def test_rows_pruned_before_triage_read_them_are_counted_and_warned(db, caplog):
    _feed(db, ["Oct 20 10:00:00 r1 app: first"], T0)
    w = _worker(db)
    w.run_once(T0)                                   # registers the cursor
    db.spool_append("syslog-1", [(T0, "10.9.9.9", f"Oct 20 10:00:00 r1 app: m{i}") for i in range(40)], cap=10)
    with caplog.at_level(logging.WARNING):
        tick = w.run_once(T0 + 1)
    assert tick["gap_rows"] == 30 and w.totals["gap_rows"] == 30
    assert w.status()["spool_gap_rows"] == {"syslog-1": 30}
    assert any("pruned" in r.getMessage() for r in caplog.records)
    assert w.run_once(T0 + 2)["gap_rows"] == 0       # reported once


# ── durability ──────────────────────────────────────────────────────────────

def test_critical_event_survives_a_failing_sink_and_a_worker_crash(db):
    """Regression: cursor committed before the send and the window only in memory, so a crash
    after a failed delivery lost the incident for good."""
    _feed(db, [CONSERVE], T0)
    w1 = _worker(db, [_Flaky("dry-run")], owner="w1")
    tick = w1.run_once(T0)
    assert tick["errors"] and not tick["opened"]
    # w1 dies without releasing its lease; its window is gone. The window slides past the event too.
    sink2 = MemorySink()
    w2 = _worker(db, [sink2], owner="w2")
    assert w2.run_once(T0 + 30)["role"] == "standby"           # lease still held
    tick2 = w2.run_once(T0 + 1000)
    assert len(tick2["opened"]) == 1 and len(sink2.sent) == 1


def test_takeover_rebuilds_the_window_from_the_spool_without_counting_it_as_new(db):
    _feed(db, [CONSERVE], T0)
    _worker(db, owner="w1").run_once(T0)
    w2 = _worker(db, owner="w2")
    tick = w2.run_once(T0 + 100)
    assert tick["new_events"] == 0 and tick["window_events"] == 1 and not tick["opened"]


def test_rate_limit_survives_a_restart(db):
    _feed(db, [CONSERVE], T0)
    w1 = _worker(db, max_tickets_per_hour=1)
    assert len(w1.run_once(T0)["opened"]) == 1
    w1.stop()
    _feed(db, [LINK_DOWN], T0 + 10)
    w2 = _worker(db, owner="w2", max_tickets_per_hour=1)
    tick = w2.run_once(T0 + 20)
    assert not tick["opened"] and tick["deferred"] == 1


def test_critical_incidents_are_sent_before_lower_severities_under_the_rate_limit(db):
    _feed(db, [LINK_DOWN, CONSERVE], T0)
    sink = MemorySink()
    w = _worker(db, [sink], max_tickets_per_hour=1, min_severity="high")
    tick = w.run_once(T0)
    assert len(tick["opened"]) == 1 and tick["opened"][0]["severity"] == "critical"
    assert tick["deferred"] == 1


# ── sinks ───────────────────────────────────────────────────────────────────

def test_failing_sink_backs_off_instead_of_retrying_every_tick(db, caplog):
    _feed(db, [CONSERVE], T0)
    sink = _Flaky()
    w = _worker(db, [sink], cooldown_s=900)
    with caplog.at_level(logging.WARNING):
        w.run_once(T0)
    assert sink.calls == 1 and any("flaky" in r.getMessage() for r in caplog.records)
    w.run_once(T0 + 15)
    w.run_once(T0 + 25)
    assert sink.calls == 1                                      # inside the backoff window
    sink.ok = True
    tick = w.run_once(T0 + 31)
    assert sink.calls == 2 and len(tick["opened"]) == 1


def test_circuit_breaker_stretches_the_backoff_after_repeated_failures(db):
    _feed(db, [CONSERVE], T0)
    sink = _Flaky()
    w = _worker(db, [sink], sink_breaker_threshold=3, sink_backoff_s=10, sink_backoff_max_s=600)
    t = T0
    for _ in range(3):
        w.run_once(t)
        t += 11 * (2 ** _)
    st = w.status()["sink_state"]["flaky"]
    assert st["fails"] == 3 and st["open"] is True
    assert st["retry_in_s"] > 100                                # parked well beyond the plain backoff


def test_partial_delivery_retries_only_the_failed_sink(db):
    _feed(db, [CONSERVE], T0)
    good, bad = _Flaky("good", ok=True), _Flaky("bad")
    w = _worker(db, [good, bad], cooldown_s=900)
    tick = w.run_once(T0)
    assert len(tick["opened"]) == 1 and tick["errors"]           # one sink took it, one did not
    assert good.calls == 1 and bad.calls == 1
    bad.ok = True
    w.run_once(T0 + 40)
    assert good.calls == 1 and bad.calls == 2                    # only the failed sink is retried
    w.run_once(T0 + 100)
    assert bad.calls == 2                                        # and then it is settled
    refs = db.triage_get(tick["opened"][0]["fingerprint"])["refs"]
    assert any(r.startswith("good:") for r in refs)


def test_failures_count_toward_the_rate_limit(db):
    _feed(db, [CONSERVE, LINK_DOWN], T0)
    sink = _Flaky()
    w = _worker(db, [sink], max_tickets_per_hour=1)
    tick = w.run_once(T0)
    assert sink.calls == 1 and tick["deferred"] == 1


def test_lost_lease_aborts_the_tick_and_keeps_the_cursor(db):
    _feed(db, [CONSERVE, LINK_DOWN], T0)

    class Thief(MemorySink):
        def upsert_incident(self, payload):
            res = super().upsert_incident(payload)
            db.kv_set("lease", "triage-worker", {"owner": "other", "expires": T0 + 1000})   # a successor took over
            return res

    sink = Thief()
    w = _worker(db, [sink], min_severity="high")
    tick = w.run_once(T0)
    assert tick["aborted"] and len(sink.sent) == 1
    assert w.status()["cursors"] == {}                           # never committed: the successor replays


def test_webhook_sink_sends_the_fingerprint_as_idempotency_key(monkeypatch):
    seen = {}

    def post(url, json=None, timeout=None, headers=None):
        seen.update(json=json, headers=headers or {})
        return SimpleNamespace(status_code=200)

    import requests
    monkeypatch.setattr(requests, "post", post)
    payload = tw.TriageIncidentPayload(site="s", root_device="r1", root_layer="bgp", root_interface=None,
                                       summary_title="t", rca_rationale="r", confidence=0.5)
    tw.WebhookSink("http://hook.invalid/x").upsert_incident(payload)
    assert seen["json"]["idempotency_key"] == payload.fingerprint
    assert seen["headers"]["Idempotency-Key"] == payload.fingerprint


def test_itsm_sink_sanitizes_the_payload_text():
    got = {}

    class Client:
        def upsert_incident(self, payload):
            got["p"] = payload
            return {"issue_key": "NET-1"}

    payload = tw.TriageIncidentPayload(
        site="s", root_device="r1", root_layer="bgp", root_interface=None, summary_title="t",
        rca_rationale="enable secret 7 0822455D0A16 leaked", confidence=0.5,
        attachments={"Sample events": "username admin password 7 0822455D0A16"})
    res = tw._ItsmSink("jira", Client()).upsert_incident(payload)
    assert res["ref"] == "NET-1"
    assert "0822455D0A16" not in got["p"].rca_rationale
    assert "0822455D0A16" not in got["p"].attachments["Sample events"]
    assert got["p"].fingerprint == payload.fingerprint


# ── dedup ───────────────────────────────────────────────────────────────────

def test_a_message_repeating_every_two_seconds_keeps_the_incident_alive(db):
    """Regression: the dedup timestamp was refreshed by dropped duplicates, so a steady repeat
    produced one ticket and then an empty window for as long as it kept repeating."""
    sink = MemorySink()
    w = _worker(db, [sink], cooldown_s=60, window_s=30, dedup_s=5)
    for t in range(0, 300, 2):
        _feed(db, [CONSERVE], T0 + t)
        w.run_once(T0 + t)
    assert w.status()["window_events"] > 0
    rec = db.triage_all()[0]
    assert rec["sends"] >= 4 and rec["last_event_at"] > T0 + 200


def test_dropped_duplicates_are_counted_on_the_incident(db):
    _feed(db, [CONSERVE, CONSERVE, CONSERVE], T0)
    w = _worker(db, dedup_s=5)
    w.run_once(T0)
    assert w.totals["duplicates_dropped"] == 2
    assert db.triage_all()[0]["event_count"] == 3


# ── retention, shutdown ─────────────────────────────────────────────────────

def test_worker_prunes_old_resolved_tickets(db):
    db.triage_put({"fingerprint": "OLD", "first_seen": 1.0, "last_seen": 1.0, "last_sent": 1.0, "sends": 1,
                   "held": 0, "state": "recovered"})
    _feed(db, [CONSERVE], T0)
    _worker(db, retention_days=30).run_once(T0)
    assert db.triage_get("OLD") is None


def test_start_registers_an_idempotent_exit_hook(db, monkeypatch):
    calls = []
    monkeypatch.setattr(tw._shutdown, "register", lambda obj, method: calls.append((obj, method)))
    w = _worker(db, poll_s=0.05)
    try:
        assert w.start() is True
    finally:
        w.stop()
        w.stop()                                                 # idempotent
    assert calls and calls[0][1] == "stop"
