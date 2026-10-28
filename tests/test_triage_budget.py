"""The hourly ticket budget must not be one counter a single sender or device can drain: each sender and
each device gets a bounded share, parked incidents are served oldest first, and the number of
incidents one sender can keep parked is bounded."""
from __future__ import annotations

import pytest

from ai_log_analyzer.state_store import StateDB
from ai_log_analyzer.triage_worker import MemorySink, StreamingTriageWorker, TriageConfig

pytestmark = pytest.mark.unit

T0 = 1_800_000_000.0
ROGUE_IP, GENUINE_IP = "198.51.100.66", "192.0.2.11"
GENUINE = "Oct 20 10:00:00 leaf-07 Ebra: %LINK-3-UPDOWN: Interface Ethernet7, changed state to down"


@pytest.fixture
def db(tmp_path):
    return StateDB(tmp_path / "state.db")


def _worker(db, **cfg):
    sink = MemorySink()
    return StreamingTriageWorker(db, [sink], TriageConfig(**cfg), clock=lambda: T0, owner="w"), sink


def _forged_critical_root(i: int) -> list[str]:
    """A conserve-mode line plus a BGP line with the same invented devname: a critical platform root."""
    dev = f"FGT-FAKE-{i:03d}"
    return [
        f'<185>date=2026-10-20 time=07:05:30 devname="{dev}" devid="FG60FTK21000007" tz="+0000" vd="root" '
        'logid="0100022011" type="event" subtype="system" level="critical" '
        'logdesc="Memory conserve mode entered" msg="Kernel enters memory conserve mode"',
        f'<189>date=2026-10-20 time=07:05:40 devname="{dev}" devid="FG100FTK19000001" tz="+0000" vd="root" '
        'logid="0103020300" type="event" subtype="router" level="warning" '
        'logdesc="BGP neighbor status changed" '
        f'msg="BGP: %BGP-5-ADJCHANGE: VRF 0 neighbor 169.254.{i % 250}.1 Down Hold Timer Expired"',
    ]


def _feed(db, lines, at, sender):
    db.spool_append("syslog-1", [(at, sender, ln) for ln in lines], cap=100_000)


def test_one_sender_flooding_critical_incidents_cannot_starve_another_device(db):
    _feed(db, [ln for i in range(40) for ln in _forged_critical_root(i)], T0, ROGUE_IP)
    _feed(db, [GENUINE], T0, GENUINE_IP)
    w, sink = _worker(db)                                       # ceiling 30 per hour
    tick = w.run_once(T0)
    devices = [d for o in tick["opened"] for d in o["devices"]]
    assert "leaf-07" in devices                                 # the genuine, lower-severity one went out
    rogue_sent = [d for d in devices if d.startswith("FGT-FAKE")]
    assert len(rogue_sent) <= 15 and len(tick["opened"]) <= 30  # the sender's share, inside the ceiling
    assert tick["capped"] >= 25


def test_a_single_sender_still_gets_its_share_when_nobody_else_competes(db):
    _feed(db, [ln for i in range(40) for ln in _forged_critical_root(i)], T0, ROGUE_IP)
    w, sink = _worker(db, max_per_sender_per_hour=30)           # operator raises the share to the ceiling
    assert len(w.run_once(T0)["opened"]) == 30


def test_the_budget_survives_a_restart_per_sender(db):
    _feed(db, [ln for i in range(40) for ln in _forged_critical_root(i)], T0, ROGUE_IP)
    w1, _ = _worker(db)
    first = len(w1.run_once(T0)["opened"])
    w1.stop()
    w2 = StreamingTriageWorker(db, [MemorySink()], TriageConfig(), clock=lambda: T0, owner="w2")
    tick = w2.run_once(T0 + 30)
    assert first == 15 and not tick["opened"]                   # the sender's share is still spent


def _synthetic(name: str, layer: str = "routing", sender: str = ROGUE_IP, severity: str = "critical"):
    return {"kind": "group", "severity": severity, "category": layer, "description": f"{layer} on {name}",
            "summary": f"{layer} on {name}", "root_device": name, "layer": layer, "interface": None,
            "devices": [name], "suppressed": 0, "count": 1, "messages": [f"{name}: {layer}"],
            "state": "active", "vendor": "", "confidence": 0.9, "latest": T0,
            "senders": [sender] if sender else []}


def _with_candidates(w, db, cands, at=T0):
    """Replace what the window yields; one real event is fed so the tick evaluates candidates at all."""
    _feed(db, [GENUINE], at, "10.9.9.9")
    w._candidates = lambda: [dict(c) for c in cands]


def test_one_device_cannot_use_more_than_its_share(db):
    w, sink = _worker(db)
    layers = [f"layer{i}" for i in range(10)]
    _with_candidates(w, db, [_synthetic("busy-01", lyr, sender="") for lyr in layers]
                     + [_synthetic("quiet-02", "routing", sender="", severity="high")])
    tick = w.run_once(T0)
    devices = [o["devices"][0] for o in tick["opened"]]
    assert devices.count("busy-01") == 6 and "quiet-02" in devices   # a fifth of the ceiling per device
    assert tick["capped"] == 4


def test_parked_incidents_are_served_oldest_first_among_equal_severities(db):
    w, sink = _worker(db, max_tickets_per_hour=1)
    def fp(name):
        return w._fingerprint(_synthetic(name, sender=""))

    pool = sorted((f"dev-{i:03d}" for i in range(60)), key=fp)
    old_first, old_second, newcomers = pool[40], pool[50], pool[:10]    # newcomers sort first by fingerprint
    _with_candidates(w, db, [_synthetic(old_first, sender=""), _synthetic(old_second, sender="")])
    tick0 = w.run_once(T0)
    sent0 = tick0["opened"][0]["devices"][0]
    parked = old_second if sent0 == old_first else old_first
    assert tick0["deferred"] == 1
    later = T0 + 3700                                           # budget refilled; the old log lines expired
    _with_candidates(w, db, [_synthetic(n, sender="") for n in newcomers], at=later)
    tick1 = w.run_once(later)
    assert [o["devices"][0] for o in tick1["opened"]] == [parked]      # not overtaken by newer incidents


def test_the_number_of_incidents_one_sender_can_keep_parked_is_bounded(db):
    w, sink = _worker(db, max_pending_per_sender=20)
    _with_candidates(w, db, [_synthetic(f"fake-{i:03d}") for i in range(120)])
    tick = w.run_once(T0)
    assert len(tick["opened"]) == 15
    assert len(db.kv_get_all("triage_pending")) == 20 and tick["dropped"] == 120 - 15 - 20


def test_parked_incidents_of_a_flooding_sender_do_not_push_out_another_sender(db):
    w, sink = _worker(db, max_pending_per_sender=20)
    cands = [_synthetic(f"fake-{i:03d}") for i in range(60)]
    cands.append(_synthetic("leaf-07", sender=GENUINE_IP, severity="high"))
    _with_candidates(w, db, cands)
    tick = w.run_once(T0)
    assert "leaf-07" in [o["devices"][0] for o in tick["opened"]]
