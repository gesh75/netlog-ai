"""Generic syslog/file adapter — parse RFC3164 / RFC5424 / freeform log files."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from ai_log_analyzer.classifier import LogEvent

# RFC3164: "<PRI>Mmm dd HH:MM:SS host appname[pid]: message"
_RFC3164_RE = re.compile(
    r"^(?:<(?P<pri>\d+)>)?"
    r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<app>[\w\-./]+)(?:\[\d+\])?:\s*"
    r"(?P<msg>.*)$"
)

# RFC5424: "<PRI>1 timestamp host appname pid msgid sd msg"
_RFC5424_RE = re.compile(
    r"^<(?P<pri>\d+)>1\s+"
    r"(?P<ts>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+"
    r"(?P<pid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?:-|\[.*?\])\s+"
    r"(?P<msg>.*)$"
)

# Junos-style: "Mmm dd HH:MM:SS host process: tag: message"
_JUNOS_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<app>\S+?):\s+"
    r"(?:%-?\w+-\d+-\w+:\s+)?"
    r"(?P<msg>.*)$"
)

# SecureCRT terminal session recordings: "HH:MM:SS.ss §<output line>".
# The § character is what SecureCRT uses to separate its synthetic timestamp
# from the captured terminal data. Match either § or the (rare) plain space-
# delimited variant.
_SCRT_RE = re.compile(
    r"^(?P<ts>\d{1,2}:\d{2}:\d{2}\.\d{2})\s*§\s*(?P<msg>.*)$"
)

# Filename pattern SecureCRT uses: "<hostname> (<ip>) -- YYYY-MM-DD_HH-MM"
_SCRT_FILENAME_RE = re.compile(r"^(?P<host>[A-Za-z0-9][\w.\-]*)\s*\(")


def parse_lines(lines: Iterable[str], default_host: str = "") -> Iterable[LogEvent]:
    """Parse any iterable of log lines, picking the first format that matches."""
    for line in lines:
        ev = _parse_line(line.rstrip("\n"), default_host)
        if ev:
            yield ev


def parse_file(path: str | Path, default_host: str = "") -> Iterable[LogEvent]:
    p = Path(path)
    # If the caller didn't pass a host, derive one. For SecureCRT recordings
    # the filename is `hostname (ip) -- YYYY-MM-DD_HH-MM.log` — extract just
    # the hostname so devices group together in the dashboard.
    if not default_host:
        scrt = _SCRT_FILENAME_RE.match(p.stem)
        default_host = scrt.group("host") if scrt else p.stem
    with p.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            ev = _parse_line(line.rstrip("\n"), default_host)
            if ev:
                yield ev


def _parse_line(line: str, default_host: str) -> LogEvent | None:
    # Strip BOM and any leading/trailing whitespace.
    line = line.lstrip("﻿").strip()
    if not line:
        return None

    # Try standard syslog formats first.
    for regex in (_RFC5424_RE, _RFC3164_RE, _JUNOS_RE):
        m = regex.match(line)
        if m:
            return _from_match(m, default_host)

    # SecureCRT terminal recording — strip the synthetic timestamp + § and
    # treat the captured terminal text as the message. The downstream
    # classifier still runs its regexes against `appname + " " + message`
    # so BGP/OSPF/license patterns in captured `show` command output will
    # fire correctly.
    m = _SCRT_RE.match(line)
    if m:
        msg = (m.group("msg") or "").strip()
        if not msg:
            return None  # empty `§` line — just terminal padding
        return LogEvent(
            timestamp=m.group("ts"),
            hostname=default_host,
            appname="scrt-session",
            severity_raw="info",
            message=msg,
        )

    # Fallback: whole line as the message, preserve hostname guess
    return LogEvent(
        timestamp="",
        hostname=default_host,
        appname="syslog",
        severity_raw="info",
        message=line,
    )


def _from_match(m: re.Match[str], default_host: str) -> LogEvent:
    pri = m.groupdict().get("pri")
    sev_raw = _pri_to_severity(int(pri)) if pri else "info"
    return LogEvent(
        timestamp=m.group("ts"),
        hostname=m.group("host") or default_host,
        appname=m.group("app"),
        severity_raw=sev_raw,
        message=m.group("msg").strip(),
    )


# Syslog priority → severity-text mapping
_SEV_NAMES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]


def _pri_to_severity(pri: int) -> str:
    return _SEV_NAMES[pri & 0x07]
