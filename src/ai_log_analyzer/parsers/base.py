"""Parser plugin registry + syslog envelope splitting.

Parsing is two steps:

1. ``split_envelope(line)`` peels the transport header (PRI, RFC 5424,
   RFC 3164, Junos, or a loose ``<ts> <host> <body>`` relay header).
2. Registered ``ParserPlugin`` objects are tried in priority order. Vendor
   plugins (FortiOS key=value, PAN-OS CSV, Cisco SD-WAN) only claim lines
   that are unambiguously theirs; the generic syslog plugin keeps the legacy
   field semantics byte-for-byte and adds entity enrichment; the fallback
   plugin always produces an event.

A plugin returns a ``LogEvent`` (claimed), ``None`` (not mine — try the next
plugin) or ``SKIP`` (mine, but drop the line — e.g. an empty terminal row).
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Protocol

from ai_log_analyzer.classifier import LogEvent

log = logging.getLogger(__name__)

# Stamps seen in front of the host: BSD ("Oct 22 10:15:01"), optionally with a
# year (IOS "Oct 22 2026 10:15:01"), microseconds (SONiC) and a timezone
# abbreviation ("... UTC"), or rsyslog's ISO-8601 with fractions and offset.
_TZ_ABBR = r"(?:UTC|GMT|UT|[ECMP][SD]T|CES?T|EES?T|BST|IST|JST)"
_BSD_TS = (r"[A-Z][a-z]{2}\s+\d{1,2}(?:\s+\d{4})?\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?"
           rf"(?:\s+{_TZ_ABBR}(?=[\s:]))?")
_ISO_TS = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
_TS = rf"(?:{_BSD_TS}|{_ISO_TS})"
# SONiC native severity word between host and tag: "leaf1 NOTICE bgp#bgpd[12]: ..."
_SEV_WORD = r"(?:(?P<sev>EMERG|ALERT|CRIT|ERR(?:OR)?|WARN(?:ING)?|NOTICE|INFO|DEBUG)\s+)?"

# RFC3164: "<PRI>Mmm dd HH:MM:SS host appname[pid]: message". The tag may be a
# Cisco "%FAC-SEV-MNEM" or SONiC "container#proc"; "host:" (IOS) loses its colon.
RFC3164_RE = re.compile(
    r"^(?:<(?P<pri>\d+)>)?"
    rf"(?P<ts>{_TS})\s+"
    r"(?P<host>\S+?):?\s+"
    rf"{_SEV_WORD}"
    r"(?P<app>[\w\-./%#]+)(?:\[\d+\])?:\s*"
    r"(?P<msg>.*)$"
)

# RFC5424: "<PRI>1 timestamp host appname pid msgid sd msg"
RFC5424_RE = re.compile(
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
JUNOS_RE = re.compile(
    r"^(?:<(?P<pri>\d+)>)?"
    rf"(?P<ts>{_TS})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<app>\S+?):\s+"
    r"(?:%-?\w+-\d+-\w+:\s+)?"
    r"(?P<msg>.*)$"
)

# Relay header without an app tag (PAN-OS CSV, FortiOS kv behind rsyslog):
# "<PRI>Mmm dd HH:MM:SS host <body>" or ISO timestamp.
_LOOSE_RE = re.compile(
    r"^(?:<(?P<pri>\d+)>)?"
    rf"(?P<ts>{_TS})\s+"
    r"(?P<host>[A-Za-z0-9][\w.\-]*)\s+"
    r"(?P<body>.+)$"
)
_PRI_ONLY_RE = re.compile(r"^<(?P<pri>\d{1,3})>(?P<body>.*)$")

SEV_NAMES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
_SEV_BY_WORD = {"EMERG": "emerg", "ALERT": "alert", "CRIT": "crit", "ERR": "err", "ERROR": "err",
                "WARN": "warning", "WARNING": "warning", "NOTICE": "notice", "INFO": "info",
                "DEBUG": "debug"}
_MONTHS = ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec")
_BSD_PARTS_RE = re.compile(
    r"^([A-Z][a-z]{2})\s+(\d{1,2})(?:\s+(\d{4}))?\s+(\d{2}:\d{2}:\d{2})(\.\d+)?(?:\s+(\w+))?$")
# IOS-XR wraps the tag: "RP/0/RP0/CPU0:Oct 22 10:15:01.1 UTC: bgp[1052]: %ROUTING-BGP-5-..."
_XR_LOC_RE = re.compile(r"^(?:RP|LC|SC|FC)/\d+/[\w/]+$")
_XR_LOC_PREFIX_RE = re.compile(r"^(?:RP|LC|SC|FC)/\d+/[\w/]+:")
_XR_INNER_RE = re.compile(
    rf"^(?:\*?{_BSD_TS}\s*:\s*)?(?P<app>[\w\-./#]+)(?:\[\d+\])?:\s*(?P<msg>.*)$")


def pri_to_severity(pri: int) -> str:
    return SEV_NAMES[pri & 0x07]


def _to_int(text: str | None) -> int | None:
    """``int(text)``, or None when empty or not convertible ("²", or past int()'s 4300-digit limit)."""
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def _canon_ts(ts: str) -> str:
    """Reduce an extended BSD stamp to a shape downstream code can order.

    Fractions are dropped, a year turns the stamp into ISO-8601, a trailing
    UTC/GMT is dropped. A non-UTC abbreviation (offset unknown) is left as
    written so it is never mis-dated. Plain "Mmm dd HH:MM:SS" is untouched.
    """
    m = _BSD_PARTS_RE.match(ts)
    if not m:
        return ts
    mon, day, year, hms, frac, tz = m.groups()
    if not (year or frac or tz):
        return ts
    if tz and tz not in ("UTC", "GMT", "UT"):
        return ts
    month = _MONTHS.index(mon.lower()) + 1 if mon.lower() in _MONTHS else 0
    if year and month:
        return f"{year}-{month:02d}-{int(day):02d}T{hms}"
    return f"{mon} {day} {hms}"


def _unwrap_xr(app: str, msg: str) -> tuple[str, str]:
    """IOS-XR: replace the "RP/0/RP0/CPU0" location tag by the real process tag."""
    if app.isdigit():
        m = _XR_LOC_PREFIX_RE.match(msg)
        if not m:
            return app, msg
        msg = msg[m.end():]
    elif not _XR_LOC_RE.match(app):
        return app, msg
    inner = _XR_INNER_RE.match(msg)
    return (inner.group("app"), inner.group("msg")) if inner else (app, msg)


@dataclass(frozen=True)
class Envelope:
    fmt: str            # rfc5424 | rfc3164 | junos | loose | pri | none
    pri: int | None
    timestamp: str
    hostname: str
    appname: str
    body: str
    severity: str = ""  # syslog severity word carried without a PRI (SONiC "NOTICE")


def split_envelope(line: str) -> Envelope:
    for fmt, regex in (("rfc5424", RFC5424_RE), ("rfc3164", RFC3164_RE), ("junos", JUNOS_RE)):
        m = regex.match(line)
        if m:
            g = m.groupdict()
            pri = g.get("pri")
            ts, app, msg = m.group("ts"), m.group("app") or "", m.group("msg")
            if fmt == "rfc5424":
                ts = "" if ts == "-" else ts   # RFC 5424 NILVALUE
            else:
                ts = _canon_ts(ts)
            if fmt == "rfc3164":
                app, msg = _unwrap_xr(app, msg)
            return Envelope(fmt, _to_int(pri), ts, m.group("host") or "", app, msg,
                            _SEV_BY_WORD.get(g.get("sev") or "", ""))
    m = _LOOSE_RE.match(line)
    if m:
        pri = m.group("pri")
        return Envelope("loose", _to_int(pri), _canon_ts(m.group("ts")), m.group("host"), "",
                        m.group("body"))
    m = _PRI_ONLY_RE.match(line)
    if m:
        return Envelope("pri", int(m.group("pri")), "", "", "", m.group("body"))
    return Envelope("none", None, "", "", "", line)


class _Skip:
    def __repr__(self) -> str:
        return "SKIP"


SKIP = _Skip()


class ParserPlugin(Protocol):
    name: str
    priority: int  # lower runs first

    def parse(self, line: str, env: Envelope, default_host: str) -> LogEvent | _Skip | None: ...


class ParserRegistry:
    """Ordered set of parser plugins. Thread-safe for reads after setup."""

    def __init__(self) -> None:
        self._plugins: list[ParserPlugin] = []

    def register(self, plugin: ParserPlugin) -> None:
        """Add (or replace by name) a plugin and keep priority order."""
        self._plugins = [p for p in self._plugins if p.name != plugin.name]
        self._plugins.append(plugin)
        self._plugins.sort(key=lambda p: p.priority)

    def unregister(self, name: str) -> bool:
        before = len(self._plugins)
        self._plugins = [p for p in self._plugins if p.name != name]
        return len(self._plugins) != before

    @property
    def names(self) -> list[str]:
        return [p.name for p in self._plugins]

    def parse(self, line: str, default_host: str = "") -> LogEvent | None:
        line = line.lstrip("﻿").strip()
        if not line:
            return None
        # One bad line must never fail a whole batch (triage tick, source fetch, live tail): a
        # plugin that raises is skipped so the next one, ultimately the fallback, still gets it.
        try:
            env = split_envelope(line)
        except Exception:
            log.debug("envelope split failed; parsing the line without one", exc_info=True)
            env = Envelope("none", None, "", "", "", line)
        for plugin in self._plugins:
            try:
                result = plugin.parse(line, env, default_host)
            except Exception:
                log.debug("parser plugin %s failed on a line; trying the next", plugin.name, exc_info=True)
                continue
            if result is SKIP:
                return None
            if result is not None:
                return result  # type: ignore[return-value]
        return None
