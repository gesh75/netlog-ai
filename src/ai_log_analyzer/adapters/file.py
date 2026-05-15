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


def parse_lines(lines: Iterable[str], default_host: str = "") -> Iterable[LogEvent]:
    """Parse any iterable of log lines, picking the first format that matches."""
    for line in lines:
        ev = _parse_line(line.rstrip("\n"), default_host)
        if ev:
            yield ev


def parse_file(path: str | Path, default_host: str = "") -> Iterable[LogEvent]:
    p = Path(path)
    with p.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            ev = _parse_line(line.rstrip("\n"), default_host or p.stem)
            if ev:
                yield ev


def _parse_line(line: str, default_host: str) -> LogEvent | None:
    line = line.strip()
    if not line:
        return None

    # Try formats in order
    for regex in (_RFC5424_RE, _RFC3164_RE, _JUNOS_RE):
        m = regex.match(line)
        if m:
            return _from_match(m, default_host)

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
