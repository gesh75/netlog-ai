"""Device-controlled digits and failing plugins must never make a line raise: one crafted
syslog row used to fail every triage tick and source fetch until it aged out."""
from __future__ import annotations

import pytest

from ai_log_analyzer.parsers import parse_line, registry
from ai_log_analyzer.state_store import StateDB
from ai_log_analyzer.triage_worker import MemorySink, StreamingTriageWorker, TriageConfig

pytestmark = pytest.mark.unit

T0 = 1_800_000_000.0
HUGE = "1" * 5000   # past CPython's 4300-digit int() conversion limit
CONSERVE = ('<185>date=2026-10-20 time=07:05:30 devname="FGT-BR-07" devid="FG60FTK21000007" tz="+0000" vd="root" '
            'logid="0100022011" type="event" subtype="system" level="critical" logdesc="Memory conserve mode entered" '
            'msg="Kernel enters memory conserve mode"')


@pytest.mark.parametrize("line", [
    f"<{HUGE}>Oct 22 10:15:01 h app: m",
    f"<{HUGE}>1 2026-10-22T10:15:01Z h app - - - m",
    f"<{HUGE}>Oct 22 10:15:01 h 1,2,3",
    '{"message":"x","severity":"²"}',
    f'{{"message":"x","severity":"{"9" * 5000}"}}',
    "CEF:0|V|P|1|100|name|²|msg=hi",
    f"CEF:0|V|P|1|100|name|{'9' * 5000}|msg=hi",
    "LEEF:1.0|V|P|1|E1|sev=²\tmsg=hi",
], ids=["rfc3164-pri", "rfc5424-pri", "loose-pri", "json-sev-sup2", "json-sev-huge", "cef-sev-sup2",
        "cef-sev-huge", "leef-sev-sup2"])
def test_crafted_digits_parse_instead_of_raising(line):
    ev = parse_line(line, "dflt")
    assert ev is not None and isinstance(ev.severity_raw, str)


def test_oversized_pri_keeps_the_header_and_drops_only_the_pri():
    ev = parse_line(f"<{HUGE}>Oct 22 10:15:01 h app: m", "dflt")
    assert (ev.hostname, ev.appname, ev.message) == ("h", "app", "m")


def test_unicode_digit_severity_uses_the_default():
    assert parse_line('{"message":"x","severity":"²"}').severity_raw == "info"
    assert parse_line('{"message":"x","severity":"3"}').severity_raw == "err"


class _Boom:
    name = "boom"
    priority = 5

    def parse(self, line, env, default_host):
        if "BOOM" in line:
            raise ValueError("crafted")


@pytest.fixture
def boom():
    registry.register(_Boom())
    yield
    assert registry.unregister("boom")


def test_a_raising_plugin_hands_the_line_to_the_next_one(boom):
    ev = parse_line("Oct 22 10:15:01 h app: BOOM", "dflt")
    assert ev is not None and ev.message == "BOOM"


@pytest.mark.parametrize("bad", [f"<{HUGE}>Oct 22 10:15:01 h app: m", "Oct 22 10:15:01 h app: BOOM"],
                         ids=["huge-pri", "raising-plugin"])
def test_triage_tick_moves_past_a_bad_row(tmp_path, boom, bad):
    db = StateDB(tmp_path / "state.db")
    db.spool_append("syslog-1", [(T0, "10.9.9.9", bad), (T0, "10.9.9.9", CONSERVE)], cap=100_000)
    w = StreamingTriageWorker(db, [MemorySink()], TriageConfig(), clock=lambda: T0, owner="test-worker")
    tick = w.run_once(T0)
    assert len(tick["opened"]) == 1             # the row after the bad one was triaged
    assert w.status()["cursors"]["syslog-1"] == 2
