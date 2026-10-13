"""Ingestion hardening: encoding, caps, timestamps, control characters."""
from __future__ import annotations

import pytest

from ai_log_analyzer.adapters.file import parse_file, parse_lines
from ai_log_analyzer.ingest import (
    clean_timestamp,
    decode_bytes,
    sanitize_raw_line,
)
from ai_log_analyzer.sources.syslog import SyslogListenerSource


@pytest.mark.unit
def test_decode_bytes_replaces_invalid_utf8():
    text = decode_bytes(b"cafe \xff espresso")
    assert "cafe" in text
    assert "espresso" in text
    assert "\ufffd" in text


@pytest.mark.unit
def test_parse_file_survives_encoding_errors(tmp_path):
    path = tmp_path / "latin.log"
    path.write_bytes(b"Mar  3 12:00:01 router1 rpd: bgp peer 10.0.0.1 down \xff\n")
    events = list(parse_file(path))
    assert len(events) == 1
    assert events[0].hostname == "router1"
    assert "bgp peer" in events[0].message


@pytest.mark.unit
def test_parse_lines_accepts_raw_bytes():
    events = list(parse_lines([b"Mar  3 12:00:01 router1 rpd: hello \xff"]))
    assert len(events) == 1
    assert events[0].hostname == "router1"


@pytest.mark.unit
def test_oversized_line_is_truncated():
    payload = "x" * 200
    line = f"Mar  3 12:00:01 router1 rpd: {payload}"
    events = list(parse_lines([line], max_line_bytes=40))
    assert len(events) == 1
    assert len(events[0].message.encode("utf-8")) < 200
    assert events[0].message.startswith("x") or "rpd" in events[0].appname


@pytest.mark.unit
def test_sanitize_raw_line_caps_utf8_bytes():
    line = "a" * 100
    assert len(sanitize_raw_line(line, max_line_bytes=16).encode("utf-8")) <= 16


@pytest.mark.unit
def test_oversized_file_stops_after_cap(tmp_path):
    path = tmp_path / "big.log"
    path.write_text(
        "Mar  3 12:00:01 router1 rpd: first event here\n"
        "Mar  3 12:00:02 router1 rpd: second event here\n"
        "Mar  3 12:00:03 router1 rpd: third event here\n",
        encoding="utf-8",
    )
    events = list(parse_file(path, max_file_bytes=60))
    assert 1 <= len(events) < 3
    assert "first" in events[0].message


@pytest.mark.unit
def test_malformed_timestamp_blanked_event_kept():
    events = list(parse_lines([
        "Mar  3 25:61:99 router1 rpd: bgp peer 10.0.0.1 down",
    ]))
    assert len(events) == 1
    assert events[0].timestamp == ""
    assert events[0].hostname == "router1"
    assert "bgp peer" in events[0].message


@pytest.mark.unit
def test_valid_timestamps_preserved():
    assert clean_timestamp("Mar  3 12:00:01") == "Mar  3 12:00:01"
    assert clean_timestamp("2026-05-09T10:00:00Z") == "2026-05-09T10:00:00Z"
    assert clean_timestamp("20:24:08.08") == "20:24:08.08"
    assert clean_timestamp("2026-13-01T10:00:00Z") == ""
    assert clean_timestamp("25:00:00.00") == ""


@pytest.mark.unit
def test_blank_and_control_chars_skipped():
    events = list(parse_lines([
        "",
        "   ",
        "\x00\x01\x07",
        "\x00Mar  3 12:00:01 router1 rpd: still parsed\x07\x1b",
    ]))
    assert len(events) == 1
    assert events[0].hostname == "router1"
    assert "still parsed" in events[0].message
    assert "\x00" not in events[0].message
    assert "\x07" not in events[0].message


@pytest.mark.unit
def test_control_only_line_does_not_become_an_event():
    assert list(parse_lines(["\x00\x01\x02", "\t"])) == []


@pytest.mark.unit
def test_syslog_ingest_strips_controls_and_skips_blank():
    src = object.__new__(SyslogListenerSource)
    src._buffer = []
    src._total_ingested = 0

    class _Lock:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    src._lock = _Lock()
    src._ingest(b"\x00Mar  3 12:00:01 router1 rpd: hello\x07")
    src._ingest(b"\x00\x01")
    src._ingest(b"")
    assert src._total_ingested == 1
    assert src._buffer == ["Mar  3 12:00:01 router1 rpd: hello"]
