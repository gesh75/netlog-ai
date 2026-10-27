"""The triage worker must not let one syslog sender speak for another device: when the inventory
(dependency map) says which host a sender address belongs to, a line from it naming a different known
device is attributed to the sender, so it cannot suppress, recover or open that device's incident."""
from __future__ import annotations

import pytest

from ai_log_analyzer.state_store import StateDB
from ai_log_analyzer.suppression import Topology
from ai_log_analyzer.triage_worker import MemorySink, StreamingTriageWorker, TriageConfig

pytestmark = pytest.mark.unit

T0 = 1_800_000_000.0
LINK_DOWN = "Oct 20 10:00:00 leaf-07 Ebra: %LINK-3-UPDOWN: Interface Ethernet7, changed state to down"
LINK_UP = "Oct 20 10:00:40 leaf-07 Ebra: %LINK-3-UPDOWN: Interface Ethernet7, changed state to up"
VICTIM_IP, ROGUE_IP, STRANGER_IP = "192.0.2.11", "192.0.2.10", "192.0.2.99"
INVENTORY = {VICTIM_IP: "leaf-07", ROGUE_IP: "leaf-08"}


@pytest.fixture
def db(tmp_path):
    return StateDB(tmp_path / "state.db")


def _feed(db, lines, at, sender):
    db.spool_append("syslog-1", [(at, sender, ln) for ln in lines], cap=100_000)


def _worker(db, topology=None, **cfg):
    sink = MemorySink()
    w = StreamingTriageWorker(db, [sink], TriageConfig(**cfg), clock=lambda: T0, owner="w", topology=topology)
    return w, sink


def test_a_forged_up_from_another_device_does_not_suppress_the_real_fault(db):
    w, sink = _worker(db, Topology(ips=dict(INVENTORY)))
    _feed(db, [LINK_DOWN], T0, VICTIM_IP)
    _feed(db, [LINK_UP], T0 + 1, ROGUE_IP)                      # leaf-08 claims leaf-07 recovered
    tick = w.run_once(T0 + 2)
    assert len(tick["opened"]) == 1 and tick["skipped_recovered"] == 0
    assert tick["opened"][0]["devices"] == ["leaf-07"]
    assert w.totals["hostname_mismatch"] == 1


def test_a_forged_up_does_not_add_a_close_note_to_a_live_ticket(db):
    w, sink = _worker(db, Topology(ips=dict(INVENTORY)), cooldown_s=900)
    _feed(db, [LINK_DOWN], T0, VICTIM_IP)
    assert w.run_once(T0)["opened"]
    _feed(db, [LINK_UP], T0 + 40, ROGUE_IP)
    tick = w.run_once(T0 + 40)
    assert not tick["updated"] and len(sink.sent) == 1
    assert "recovered" not in sink.sent[-1]["body"]


def test_the_device_itself_can_still_report_its_recovery(db):
    w, sink = _worker(db, Topology(ips=dict(INVENTORY)), cooldown_s=900)
    _feed(db, [LINK_DOWN], T0, VICTIM_IP)
    assert w.run_once(T0)["opened"]
    _feed(db, [LINK_UP], T0 + 40, VICTIM_IP)
    assert len(w.run_once(T0 + 40)["updated"]) == 1
    assert w.totals["hostname_mismatch"] == 0


def test_a_listed_relay_may_name_any_device(db):
    w, sink = _worker(db, Topology(ips=dict(INVENTORY), relays={ROGUE_IP}))
    _feed(db, [LINK_DOWN], T0, ROGUE_IP)
    _feed(db, [LINK_UP], T0 + 1, ROGUE_IP)
    tick = w.run_once(T0 + 2)
    assert not tick["opened"] and tick["skipped_recovered"] == 1 and w.totals["hostname_mismatch"] == 0


def test_without_a_mapping_for_the_sender_behaviour_is_unchanged(db):
    w, sink = _worker(db, Topology(ips=dict(INVENTORY)))
    _feed(db, [LINK_DOWN], T0, STRANGER_IP)                     # unmapped sender: nothing to check against
    _feed(db, [LINK_UP], T0 + 1, STRANGER_IP)
    tick = w.run_once(T0 + 2)
    assert not tick["opened"] and tick["skipped_recovered"] == 1


def test_no_inventory_means_no_change(db):
    w, sink = _worker(db, Topology())
    _feed(db, [LINK_DOWN], T0, VICTIM_IP)
    _feed(db, [LINK_UP], T0 + 1, ROGUE_IP)
    tick = w.run_once(T0 + 2)
    assert tick["skipped_recovered"] == 1 and w.totals["hostname_mismatch"] == 0


def test_a_mapped_sender_naming_a_device_the_inventory_does_not_know_is_left_alone(db):
    w, sink = _worker(db, Topology(ips=dict(INVENTORY)))
    _feed(db, [LINK_DOWN.replace("leaf-07", "lab-switch-99")], T0, ROGUE_IP)
    tick = w.run_once(T0 + 1)
    assert w.totals["hostname_mismatch"] == 0
    assert [o["devices"] for o in tick["opened"]] == [["lab-switch-99"]]
