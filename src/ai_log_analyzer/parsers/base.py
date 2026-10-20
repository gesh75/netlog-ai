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

import re
from dataclasses import dataclass
from typing import Protocol

from ai_log_analyzer.classifier import LogEvent

# RFC3164: "<PRI>Mmm dd HH:MM:SS host appname[pid]: message"
RFC3164_RE = re.compile(
    r"^(?:<(?P<pri>\d+)>)?"
    r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<app>[\w\-./]+)(?:\[\d+\])?:\s*"
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
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<app>\S+?):\s+"
    r"(?:%-?\w+-\d+-\w+:\s+)?"
    r"(?P<msg>.*)$"
)

# Relay header without an app tag (PAN-OS CSV, FortiOS kv behind rsyslog):
# "<PRI>Mmm dd HH:MM:SS host <body>" or ISO timestamp.
_LOOSE_RE = re.compile(
    r"^(?:<(?P<pri>\d+)>)?"
    r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r"|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>[A-Za-z0-9][\w.\-]*)\s+"
    r"(?P<body>.+)$"
)
_PRI_ONLY_RE = re.compile(r"^<(?P<pri>\d{1,3})>(?P<body>.*)$")

SEV_NAMES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]


def pri_to_severity(pri: int) -> str:
    return SEV_NAMES[pri & 0x07]


@dataclass(frozen=True)
class Envelope:
    fmt: str            # rfc5424 | rfc3164 | junos | loose | pri | none
    pri: int | None
    timestamp: str
    hostname: str
    appname: str
    body: str


def split_envelope(line: str) -> Envelope:
    for fmt, regex in (("rfc5424", RFC5424_RE), ("rfc3164", RFC3164_RE), ("junos", JUNOS_RE)):
        m = regex.match(line)
        if m:
            pri = m.groupdict().get("pri")
            return Envelope(fmt, int(pri) if pri else None, m.group("ts"),
                            m.group("host") or "", m.group("app") or "", m.group("msg"))
    m = _LOOSE_RE.match(line)
    if m:
        pri = m.group("pri")
        return Envelope("loose", int(pri) if pri else None, m.group("ts"), m.group("host"), "", m.group("body"))
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
        env = split_envelope(line)
        for plugin in self._plugins:
            result = plugin.parse(line, env, default_host)
            if result is SKIP:
                return None
            if result is not None:
                return result  # type: ignore[return-value]
        return None
