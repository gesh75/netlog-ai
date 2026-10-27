"""Device-controlled digits and failing plugins must never make a line raise: one crafted
syslog row used to fail every triage tick and source fetch until it aged out."""
from __future__ import annotations

import logging

import pytest

from ai_log_analyzer.classifier import LogEvent, classify_events
from ai_log_analyzer.parsers import ensure_structured, parse_line, registry
from ai_log_analyzer.parsers.base import ParserRegistry, split_envelope
from ai_log_analyzer.parsers.generic import FallbackParser
from ai_log_analyzer.sources.syslog import SyslogListenerSource
from ai_log_analyzer.state_store import StateDB
from ai_log_analyzer.triage_worker import MemorySink, StreamingTriageWorker, TriageConfig

pytestmark = pytest.mark.unit

T0 = 1_800_000_000.0
HUGE = "1" * 5000   # past CPython's 4300-digit int() conversion limit
CONSERVE = ('<185>date=2026-10-20 time=07:05:30 devname="FGT-BR-07" devid="FG60FTK21000007" tz="+0000" vd="root" '
            'logid="0100022011" type="event" subtype="system" level="critical" logdesc="Memory conserve mode entered" '
            'msg="Kernel enters memory conserve mode"')

CRAFTED = [
    f"<{HUGE}>Oct 22 10:15:01 h app: m",
    f"<{HUGE}>1 2026-10-22T10:15:01Z h app - - - m",
    f"<{HUGE}>Oct 22 10:15:01 h 1,2,3",
    f"<{HUGE}>Oct 22 10:15:01 h app: msg",
    f"<{HUGE}>plain body",
    '{"message":"x","severity":"²"}',
    f'{{"message":"x","severity":"{"9" * 5000}"}}',
    '{"message":"x","severity":"٣"}',
    "CEF:0|V|P|1|100|name|²|msg=hi",
    f"CEF:0|V|P|1|100|name|{'9' * 5000}|msg=hi",
    "LEEF:1.0|V|P|1|E1|sev=²\tmsg=hi",
    f"LEEF:1.0|V|P|1|E1|sev={'9' * 5000}\tmsg=hi",
]
CRAFTED_IDS = ["rfc3164-pri", "rfc5424-pri", "loose-pri", "rfc3164-pri-body", "pri-only", "json-sev-sup2",
               "json-sev-huge", "json-sev-arabic", "cef-sev-sup2", "cef-sev-huge", "leef-sev-sup2",
               "leef-sev-huge"]


@pytest.mark.parametrize("line", CRAFTED, ids=CRAFTED_IDS)
def test_crafted_digits_parse_instead_of_raising(line):
    ev = parse_line(line, "dflt")
    assert ev is not None and isinstance(ev.severity_raw, str)


@pytest.mark.parametrize("line", CRAFTED, ids=CRAFTED_IDS)
def test_crafted_digits_never_reach_a_plugin_as_an_exception(line):
    """Contained by the parser, not just swallowed by the registry's per-line guard."""
    before = registry.errors
    parse_line(line, "dflt")
    assert registry.errors == before


def test_split_envelope_itself_does_not_raise_on_an_oversized_pri():
    assert split_envelope(f"<{HUGE}>Oct 22 10:15:01 h app: m").pri is None
    assert split_envelope(f"<{HUGE}>1 2026-10-22T10:15:01Z h app - - - m").pri is None
    assert split_envelope("<189>Oct 22 10:15:01 h app: m").pri == 189


def test_oversized_pri_keeps_the_header_and_drops_only_the_pri():
    ev = parse_line(f"<{HUGE}>Oct 22 10:15:01 h app: m", "dflt")
    assert (ev.hostname, ev.appname, ev.message) == ("h", "app", "m")


@pytest.mark.parametrize("text, expected", [
    ("189", 189), ("0", 0), ("٣", 3), (None, None), ("", None), ("²", None), ("-1", None), ("1.5", None),
    ("1" * 11, None), ("9" * 5000, None),
])
def test_to_int_is_total(text, expected):
    from ai_log_analyzer.parsers.base import _to_int

    assert _to_int(text) == expected


def test_unicode_digit_severity_uses_the_default():
    assert parse_line('{"message":"x","severity":"²"}').severity_raw == "info"
    assert parse_line('{"message":"x","severity":"3"}').severity_raw == "err"
    assert parse_line("CEF:0|V|P|1|100|name|²|msg=hi").severity_raw == "info"
    assert parse_line("CEF:0|V|P|1|100|name|9|msg=hi").severity_raw == "crit"
    # a digit string too long to convert is still "above 8", as before; JSON numbers above 7 take the default
    assert parse_line(f"CEF:0|V|P|1|100|name|{'9' * 5000}|msg=hi").severity_raw == "crit"
    assert parse_line(f'{{"message":"x","severity":"{"9" * 5000}"}}').severity_raw == "info"


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
    assert parse_line("Oct 22 10:15:01 h app: fine", "dflt").message == "fine"


def test_plugin_failures_are_counted_and_the_first_is_logged(caplog):
    reg = ParserRegistry()
    reg.register(_Boom())
    reg.register(FallbackParser())
    assert reg.errors == 0
    with caplog.at_level(logging.WARNING, logger="ai_log_analyzer.parsers.base"):
        ev = reg.parse("Oct 22 10:15:01 h app: BOOM", "dflt")
    assert ev is not None and ev.message == "Oct 22 10:15:01 h app: BOOM"
    assert reg.errors == 1
    assert any("boom" in r.getMessage() for r in caplog.records)
    reg.parse("fine", "dflt")
    assert reg.errors == 1
    for _ in range(3):
        reg.parse("BOOM", "dflt")
    assert reg.errors == 4


def test_a_failing_envelope_split_parses_the_line_without_an_envelope(monkeypatch):
    from ai_log_analyzer.parsers import base

    def explode(line):
        raise ValueError("crafted")

    monkeypatch.setattr(base, "split_envelope", explode)
    before = registry.errors
    ev = parse_line("Oct 22 10:15:01 h app: whole line", "dflt")
    assert ev is not None and ev.message == "Oct 22 10:15:01 h app: whole line"
    assert registry.errors == before + 1


def test_connector_events_survive_a_raising_body_parser(monkeypatch):
    from ai_log_analyzer import parsers

    class _Bad:
        name = "bad"

        def parse(self, line, env, default_host):
            raise ValueError("crafted")

    monkeypatch.setattr(parsers, "_BODY_PLUGINS", (_Bad(),))
    ev = ensure_structured(LogEvent("", "h", "app", "info", "peer 192.0.2.1 down"))
    assert ev.attrs["parser"] == "enrich"


def test_classify_events_survives_every_crafted_line():
    events = [parse_line(line, "dflt") for line in CRAFTED]
    out, _, _ = classify_events([e for e in events if e is not None])
    assert len(out) == len(CRAFTED)


def test_syslog_source_events_skip_nothing_and_raise_nothing():
    """``SyslogListenerSource._events`` is what fetch / fetch_new / analyze call on spooled rows."""
    items = [(line, "192.0.2.9") for line in CRAFTED] + [("<13>Oct 22 10:15:01 h app: after", "192.0.2.9")]
    events = SyslogListenerSource._events(None, items)
    assert len(events) == len(items) and events[-1].message == "after"


@pytest.mark.parametrize("bad", [f"<{HUGE}>Oct 22 10:15:01 h app: m", "BOOM"], ids=["huge-pri", "raising-plugin"])
def test_triage_tick_moves_past_a_bad_row(tmp_path, boom, bad):
    db = StateDB(tmp_path / "state.db")
    db.spool_append("syslog-1", [(T0, "198.51.100.9", bad), (T0, "198.51.100.9", CONSERVE)], cap=100_000)
    w = StreamingTriageWorker(db, [MemorySink()], TriageConfig(), clock=lambda: T0, owner="test-worker")
    tick = w.run_once(T0)
    assert not tick["errors"] and not tick["aborted"]
    assert len(tick["opened"]) == 1             # the row after the bad one was triaged
    assert w.status()["cursors"]["syslog-1"] == 2
