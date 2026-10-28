"""Edge-of-range timestamps must never abort analysis or a triage tick.

Year-1 / year-9999 stamps overflow ``datetime`` once a UTC offset or a Dec/Jan restamp is applied.
One such line used to fail ``analyze()`` for the whole batch and every ``StreamingTriageWorker`` tick
while it stayed in the window; the JSON/CEF/LEEF parsers keep ISO stamps verbatim, so they reach
the analyzer unchanged.
"""
from __future__ import annotations

from datetime import datetime

import pytest

from ai_log_analyzer.adapters.file import parse_lines
from ai_log_analyzer.analyzer import analyze
from ai_log_analyzer.causal import _parse_event_ts, _restamp_yearless, _with_year, event_time
from ai_log_analyzer.classifier import ClassifiedEvent, LogEvent
from ai_log_analyzer.ingest import clean_timestamp
from ai_log_analyzer.parsers import parse_line
from ai_log_analyzer.servicenow_sync import _parse_when
from ai_log_analyzer.state_store import StateDB
from ai_log_analyzer.triage_worker import MemorySink, StreamingTriageWorker, TriageConfig

pytestmark = pytest.mark.unit

T0 = 1_800_000_000.0
EDGE_STAMPS = ("0001-01-01T00:00:00+01:00", "9999-12-31T23:30:00-01:00", "0001-01-01T00:00:00+23:59",
               "9999-12-31T23:59:59.999999-23:59")
CONSERVE = ('<185>date=2026-10-20 time=07:05:30 devname="FGT-BR-07" devid="FG60FTK21000007" tz="+0000" vd="root" '
            'logid="0100022011" type="event" subtype="system" level="critical" logdesc="Memory conserve mode entered" '
            'msg="Kernel enters memory conserve mode"')


def _ce(**kw) -> ClassifiedEvent:
    defaults = dict(
        timestamp="2026-08-29T10:00:00", hostname="spine-01", appname="rpd", severity="high",
        severity_raw="err", category="routing", description="BGP peer down / connect failure",
        action="check", message="bgp peer 10.0.0.1 down", sample_message="bgp peer 10.0.0.1 down",
        confidence=0.9,
    )
    defaults.update(kw)
    return ClassifiedEvent(**defaults)


@pytest.mark.parametrize("stamp", EDGE_STAMPS)
def test_event_time_edge_of_range_offset_stamp_is_untimed(stamp):
    assert _parse_event_ts(stamp) is None
    assert event_time(_ce(timestamp=stamp)) is None


@pytest.mark.parametrize("stamp, expected", [
    ("0001-01-01T00:00:00+00:00", datetime(1, 1, 1)),
    ("0001-01-01T05:00:00+05:00", datetime(1, 1, 1)),
    ("9999-12-31T23:59:59Z", datetime(9999, 12, 31, 23, 59, 59)),
    ("9999-12-31T20:00:00-03:00", datetime(9999, 12, 31, 23)),
])
def test_stamps_that_stay_in_range_after_the_offset_still_parse(stamp, expected):
    assert event_time(_ce(timestamp=stamp)) == expected


@pytest.mark.parametrize(("stamp", "ref", "expected"), [
    ("Dec 31 23:59:00", datetime(1, 1, 1, 0, 5), datetime(1, 12, 31, 23, 59)),
    ("Jan  1 00:01:00", datetime(9999, 12, 31, 23, 0), datetime(9999, 1, 1, 0, 1)),
    ("Feb 29 00:01:00", datetime(9999, 12, 31, 23, 0), datetime(9999, 2, 28, 0, 1)),
])
def test_rollover_restamp_skips_out_of_range_years(stamp, ref, expected):
    assert event_time(_ce(timestamp=stamp), ref) == expected


@pytest.mark.parametrize("year", [0, -5, 10000, 10**9])
def test_literal_year_out_of_range_is_clamped_not_raised(year):
    got = event_time(_ce(timestamp="Aug 29 10:00:00"), year)
    assert got is not None and 1 <= got.year <= 9999
    assert _with_year(datetime(4, 2, 29), year).year in (1, 9999)
    assert _restamp_yearless(datetime(4, 12, 31), datetime(1, 1, 1)).year == 1


def _poison_events():
    events = [LogEvent(stamp, "r1", "bgpd", "err", "%BGP-5-ADJCHANGE: neighbor 10.0.0.1 Down")
              for stamp in EDGE_STAMPS]
    return events + [
        # a dated 9999 anchor plus an RFC 3164 Dec/Jan pair: the restamp tried year 10000
        LogEvent("9999-12-31T23:00:00", "r2", "bgpd", "err", "%BGP-5-ADJCHANGE: neighbor 10.0.0.2 Down"),
        LogEvent("Dec 31 23:59:00", "r3", "bgpd", "err", "%BGP-5-ADJCHANGE: neighbor 10.0.0.3 Down"),
        LogEvent("Jan  1 00:01:00", "r4", "bgpd", "err", "%BGP-5-ADJCHANGE: neighbor 10.0.0.4 Down"),
    ]


def test_analyze_survives_edge_of_range_stamps():
    result = analyze(_poison_events(), use_llm=False)
    devices = {d for item in result.action_items for d in item.devices}
    assert {"r1", "r2", "r3", "r4"} <= devices


def test_analyze_survives_edge_stamps_arriving_through_the_parsers():
    lines = [
        f'{{"timestamp": "{ts}", "host": "r1", "message": "%BGP-5-ADJCHANGE: neighbor 10.0.0.1 Down"}}'
        for ts in (*EDGE_STAMPS, "0001-01-01T00:00:00", "9999-12-31T23:59:59")
    ] + [
        f"CEF:0|v|p|1|100|bgp|5|rt={EDGE_STAMPS[0]} msg=neighbor 10.0.0.9 Down dvchost=r9",
        "Dec 31 23:59:00 r3 bgpd: %BGP-5-ADJCHANGE: neighbor 10.0.0.3 Down",
        "Jan  1 00:01:00 r4 bgpd: %BGP-5-ADJCHANGE: neighbor 10.0.0.4 Down",
    ]
    events = list(parse_lines(lines))
    assert len(events) == len(lines)
    result = analyze(events, use_llm=False)
    assert {"r3", "r4"} <= {d for item in result.action_items for d in item.devices}


def _feed(db, lines, at, source="syslog-1", sender="198.51.100.9"):
    db.spool_append(source, [(at, sender, ln) for ln in lines], cap=100_000)


def test_edge_of_range_stamps_do_not_blind_triage_for_other_devices(tmp_path):
    db = StateDB(tmp_path / "state.db")
    poison = [
        f'{{"timestamp": "{ts}", "host": "r1", "message": "%BGP-5-ADJCHANGE: neighbor 10.0.0.1 Down"}}'
        for ts in (*EDGE_STAMPS, "9999-12-31T23:00:00")
    ] + [
        "Dec 31 23:59:00 r3 bgpd: %BGP-5-ADJCHANGE: neighbor 10.0.0.3 Down",
        "Jan  1 00:01:00 r4 bgpd: %BGP-5-ADJCHANGE: neighbor 10.0.0.4 Down",
    ]
    _feed(db, [*poison, CONSERVE], T0)
    w = StreamingTriageWorker(db, [MemorySink()], TriageConfig(), clock=lambda: T0, owner="test-worker")
    tick = w.run_once(T0)
    assert not tick["errors"] and not tick["aborted"]
    titles = [o["title"] for o in tick["opened"]]
    assert "FortiGate memory conserve mode" in titles, titles


@pytest.mark.parametrize("stamp, kept", [
    ("0001-01-01T00:00:00+01:00", False),
    ("9999-12-31T23:30:00-01:00", False),
    ("0000-06-01T00:00:00", False),
    ("0001-01-01 00:00:00", False),
    ("0002-01-01T00:00:00Z", True),
    ("9998-12-31T23:59:59Z", True),
    ("2026-10-22T10:15:01Z", True),
])
def test_clean_timestamp_blanks_years_that_cannot_survive_an_offset(stamp, kept):
    assert clean_timestamp(stamp) == (stamp if kept else "")


def test_syslog_lines_with_edge_years_lose_only_the_stamp():
    for line in ("<189>1 0001-01-01T00:00:00+01:00 r1 bgpd - - - %BGP-5-ADJCHANGE: neighbor 10.0.0.1 Down",
                 "<189>Oct 22 9999 10:15:01 r1 bgpd: %BGP-5-ADJCHANGE: neighbor 10.0.0.1 Down"):
        ev = parse_line(line)
        assert ev is not None and ev.timestamp == "" and ev.hostname == "r1"


@pytest.mark.parametrize("stamp", EDGE_STAMPS)
def test_servicenow_clock_parse_treats_an_overflowing_stamp_as_unknown(stamp):
    assert _parse_when(stamp) is None
    assert _parse_when("2026-10-22T10:15:01+02:00") == datetime.fromisoformat("2026-10-22T08:15:01+00:00")


@pytest.mark.parametrize("stamp", ["0001-01-01T00:00:00+01:00", "9999-12-31T23:30:00-01:00"])
def test_deep_report_survives_edge_of_range_stamp(stamp):
    from ai_log_analyzer.deep_report import run_deep_report

    log_text = "\n".join([
        f"{stamp} r1 %BGP-5-ADJCHANGE: neighbor 10.0.0.1 Down",
        "2026-10-16T14:00:00Z leaf01 %BGP-5-ADJCHANGE: neighbor 10.0.0.2 Down",
    ])
    assert run_deep_report(log_text=log_text).payload


def test_untimed_rows_after_a_year_9999_anchor_keep_order_and_spacing():
    from datetime import timedelta

    from ai_log_analyzer.analytics import _parse_ts

    ref = datetime(9999, 12, 31, 23, 0)
    stamps = [_parse_ts("", index, ref, 3600.0) for index in (8759, 8760, 40000)]
    assert stamps == sorted(stamps)
    assert stamps[1] - stamps[0] == timedelta(hours=1)
