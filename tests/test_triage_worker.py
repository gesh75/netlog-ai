"""Streaming triage worker: spool cursor, sliding window, dedup, suppression,
per-incident cooldowns, rate limiting, leases and ticket payloads."""
from __future__ import annotations

from pathlib import Path

import pytest

from ai_log_analyzer import audit
from ai_log_analyzer.state_store import StateDB
from ai_log_analyzer.suppression import Topology
from ai_log_analyzer.triage_worker import MemorySink, StreamingTriageWorker, TriageConfig, sinks_from_env

FIXTURES = Path(__file__).parent / "fixtures" / "multivendor"
T0 = 1_800_000_000.0

LINK_DOWN = "Oct 20 10:00:00 leaf-07 Ebra: %LINK-3-UPDOWN: Interface Ethernet7, changed state to down"
LINK_UP = "Oct 20 10:00:40 leaf-07 Ebra: %LINK-3-UPDOWN: Interface Ethernet7, changed state to up"
CONSERVE = ('<185>date=2026-10-20 time=07:05:30 devname="FGT-BR-07" devid="FG60FTK21000007" tz="+0000" vd="root" '
            'logid="0100022011" type="event" subtype="system" level="critical" logdesc="Memory conserve mode entered" '
            'msg="Kernel enters memory conserve mode"')


def _lines(name: str, idx: list[int] | None = None) -> list[str]:
    rows = [ln for ln in (FIXTURES / name).read_text().splitlines() if ln.strip()]
    return [rows[i - 1] for i in idx] if idx else rows


@pytest.fixture
def db(tmp_path):
    return StateDB(tmp_path / "state.db")


def _feed(db, lines, at, source="syslog-1", sender="10.9.9.9"):
    db.spool_append(source, [(at, sender, ln) for ln in lines], cap=100_000)


def _worker(db, sink=None, **cfg):
    sink = sink or MemorySink()
    w = StreamingTriageWorker(db, [sink], TriageConfig(**cfg), clock=lambda: T0, owner="test-worker")
    return w, sink


def test_topology_suppression_turns_a_cascade_into_one_root_ticket(db):
    _feed(db, _lines("fortigate_sdwan_ipsec_bgp_cascade.log", [1, 2, 3, 4, 5, 6, 7]), T0)
    w, sink = _worker(db)
    w.topology = Topology(relays={"10.9.9.9"})   # one collector forwards every device: it vouches for the names
    tick = w.run_once(T0)
    titles = [o["title"] for o in tick["opened"]]
    assert len(tick["opened"]) == 1, titles
    assert titles[0].startswith("SD-WAN SLA violation / member out of SLA on fgt-hq-01")
    body = sink.sent[0]["body"]
    assert "Suppressed Downstream Alarms:** `6`" in body
    assert "### RCA playbook" in body and "**Root cause:**" in body


def test_cursor_persists_so_a_restarted_worker_never_reprocesses(db):
    _feed(db, [CONSERVE], T0)
    w1, sink1 = _worker(db)
    assert len(w1.run_once(T0)["opened"]) == 1
    w1.stop()                                     # releases the lease
    w2, sink2 = _worker(db)                       # same DB, fresh process state
    tick = w2.run_once(T0 + 5)
    assert tick["new_events"] == 0 and not tick["opened"] and not sink2.sent
    assert w2.status()["cursors"]["syslog-1"] == 1


def test_window_drops_backlog_older_than_window(db):
    _feed(db, [CONSERVE], T0 - 1000)              # outside a 300 s window
    w, _ = _worker(db, window_s=300)
    tick = w.run_once(T0)
    assert tick["new_events"] == 0 and tick["window_events"] == 0
    _feed(db, [CONSERVE], T0)
    assert w.run_once(T0)["window_events"] == 1
    assert w.run_once(T0 + 301)["window_events"] == 0   # slides out


def test_exact_duplicates_within_dedup_interval_are_dropped(db):
    _feed(db, [CONSERVE, CONSERVE, CONSERVE], T0)
    w, _ = _worker(db, dedup_s=5)
    assert w.run_once(T0)["new_events"] == 1
    assert w.totals["duplicates_dropped"] == 2


def test_cooldown_holds_updates_then_releases_only_with_new_events(db):
    w, sink = _worker(db, cooldown_s=900)
    _feed(db, [CONSERVE], T0)
    assert len(w.run_once(T0)["opened"]) == 1
    _feed(db, [CONSERVE.replace("07:05:30", "07:06:30")], T0 + 60)
    tick = w.run_once(T0 + 60)
    assert tick["held"] == 1 and not tick["updated"]        # inside cooldown
    _feed(db, [CONSERVE.replace("07:05:30", "07:07:30")], T0 + 200)
    tick = w.run_once(T0 + 200)
    assert tick["held"] == 1                                 # still cooling down
    _feed(db, [CONSERVE.replace("07:05:30", "07:20:30")], T0 + 1000)
    tick = w.run_once(T0 + 1000)
    assert len(tick["updated"]) == 1                         # cooled down + new events
    assert len(sink.sent) == 2 and sink.sent[1]["action"] == "updated"
    rec = db.triage_get(tick["updated"][0]["fingerprint"])
    assert rec["sends"] == 2 and rec["held"] == 2


def test_no_update_after_cooldown_without_new_events(db):
    w, sink = _worker(db, cooldown_s=60, window_s=3600)
    _feed(db, [CONSERVE], T0)
    w.run_once(T0)
    # Unrelated event triggers a re-evaluation; the conserve-mode incident has nothing new.
    _feed(db, [LINK_DOWN], T0 + 120)
    tick = w.run_once(T0 + 120)
    assert all("conserve" not in u["title"].lower() for u in tick["updated"])
    assert tick["held"] >= 1


def test_severity_escalation_bypasses_cooldown(db):
    w, sink = _worker(db, cooldown_s=900, min_severity="high")
    _feed(db, [LINK_DOWN], T0)
    opened = w.run_once(T0)["opened"]
    assert opened and opened[0]["severity"] == "high"
    fp = opened[0]["fingerprint"]
    rec = db.triage_get(fp)
    db.triage_put({**rec, "severity": "medium"})            # pretend it was opened at a lower severity
    _feed(db, [LINK_DOWN.replace("10:00:00", "10:00:10")], T0 + 10)
    tick = w.run_once(T0 + 10)
    assert [u["fingerprint"] for u in tick["updated"]] == [fp]


def test_self_healed_flap_opens_no_ticket(db):
    _feed(db, [LINK_DOWN, LINK_UP], T0)
    w, sink = _worker(db)
    tick = w.run_once(T0)
    assert not tick["opened"] and tick["skipped_recovered"] == 1 and not sink.sent


def test_recovery_of_an_open_incident_sends_one_update(db):
    w, sink = _worker(db, cooldown_s=900)
    _feed(db, [LINK_DOWN], T0)
    assert w.run_once(T0)["opened"]
    _feed(db, [LINK_UP], T0 + 40)
    tick = w.run_once(T0 + 40)                               # state change bypasses cooldown
    assert len(tick["updated"]) == 1
    assert "All affected entities have recovered" in sink.sent[-1]["body"]


def test_interface_incident_attaches_guarded_drain_and_ansible_check_mode(db):
    _feed(db, [LINK_DOWN], T0)
    w, sink = _worker(db)
    w.run_once(T0)
    body = sink.sent[0]["body"]
    assert "Ansible (run with --check --diff first)" in body
    assert "arista.eos" in body and "check_mode: true" in body
    assert "Ethernet7" in body


def test_global_rate_limit_defers_instead_of_dropping(db):
    _feed(db, _lines("bgp_anomalies.log"), T0)
    w, sink = _worker(db, max_tickets_per_hour=2)
    tick = w.run_once(T0)
    assert len(tick["opened"]) == 2 and tick["deferred"] >= 1
    deferred = tick["deferred"]
    _feed(db, [CONSERVE], T0 + 3700)                        # an hour later, new activity
    tick2 = w.run_once(T0 + 3700)
    assert tick2["opened"]                                  # the limiter has refilled
    assert deferred


def test_only_the_lease_holder_processes_the_spool(db):
    _feed(db, [CONSERVE], T0)
    a, sink_a = _worker(db)
    b = StreamingTriageWorker(db, [MemorySink()], TriageConfig(), clock=lambda: T0, owner="other-worker")
    assert a.run_once(T0)["role"] == "active"
    assert b.run_once(T0)["role"] == "standby"
    assert b.run_once(T0 + 120)["role"] == "active"        # lease expired (60 s TTL)


class _BrokenSink:
    name = "broken"

    def upsert_incident(self, payload):
        raise ConnectionError("ITSM unreachable")


def test_failed_delivery_keeps_state_so_the_next_tick_retries(db):
    _feed(db, [CONSERVE], T0)
    w = StreamingTriageWorker(db, [_BrokenSink()], TriageConfig(), clock=lambda: T0, owner="t")
    tick = w.run_once(T0)
    assert not tick["opened"] and "ITSM unreachable" in tick["errors"][0]
    assert db.triage_all() == []
    w.sinks = [MemorySink()]
    _feed(db, [CONSERVE.replace("07:05:30", "07:05:31")], T0 + 1)
    assert len(w.run_once(T0 + 1)["opened"]) == 1


def test_ticket_actions_are_audited_as_the_triage_worker(db, monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_STATE_DB", str(db.path))
    _feed(db, [CONSERVE], T0)
    w, _ = _worker(db)
    w.run_once(T0)
    rows = audit.query(action="triage.ticket.*")
    assert rows and rows[0]["actor"] == "triage-worker" and rows[0]["role"] == "system"


def test_sinks_default_to_dry_run_and_skip_unconfigured(monkeypatch):
    assert [s.name for s in sinks_from_env()] == ["dry-run"]
    monkeypatch.setenv("AI_LOG_ANALYZER_TRIAGE_SINKS", "jira,webhook")
    monkeypatch.delenv("JIRA_URL", raising=False)
    monkeypatch.delenv("AI_LOG_ANALYZER_WEBHOOK_URL", raising=False)
    assert [s.name for s in sinks_from_env()] == ["dry-run"]   # nothing configured → never silent-drop


def test_incident_keeps_one_ticket_when_it_becomes_a_suppression_root(db):
    """Regression: a repeat alert turned the group into a suppression root with
    a different fingerprint, which opened a duplicate ticket."""
    w, sink = _worker(db, cooldown_s=900)
    _feed(db, [LINK_DOWN], T0)
    w.run_once(T0)
    _feed(db, [LINK_DOWN.replace("10:00:00", "10:00:10")], T0 + 10)
    tick = w.run_once(T0 + 10)
    assert not tick["opened"] and tick["held"] == 1
    assert len(db.triage_all()) == 1 and len(sink.sent) == 1
