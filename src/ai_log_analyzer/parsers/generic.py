"""Generic syslog / SecureCRT / fallback plugins.

These reproduce the pre-registry parser's base fields exactly (timestamp,
hostname, appname, severity_raw, message) and add NOS entity enrichment on
top, so every existing caller sees the same five fields as before.
"""
from __future__ import annotations

import re
from collections.abc import Mapping

from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.ingest import clean_timestamp
from ai_log_analyzer.parsers.base import SKIP, Envelope, pri_to_severity
from ai_log_analyzer.parsers.entities import enrich_netos
from ai_log_analyzer.parsers.timeutil import normalize_ts

# SecureCRT terminal session recordings: "HH:MM:SS.ss §<output line>".
SCRT_RE = re.compile(r"^(?P<ts>\d{1,2}:\d{2}:\d{2}\.\d{2})\s*§\s*(?P<msg>.*)$")

_SYSLOG_FORMATS = frozenset({"rfc5424", "rfc3164", "junos", "loose"})


def base_event(env: Envelope, default_host: str) -> LogEvent:
    """Legacy base fields from a matched syslog envelope."""
    return LogEvent(
        timestamp=clean_timestamp(env.timestamp),
        hostname=env.hostname or default_host,
        appname=env.appname or "syslog",
        severity_raw=pri_to_severity(env.pri) if env.pri is not None else (env.severity or "info"),
        message=env.body.strip(),
    )


def with_structure(
    ev: LogEvent,
    fields: Mapping[str, str],
    parser: str,
    attrs: Mapping[str, str] | None = None,
    tz: str | None = None,
) -> LogEvent:
    """Attach structured fields + normalized UTC time; mark the parser used."""
    merged_attrs = {**ev.attrs, **(attrs or {}), "parser": parser}
    norm, assumed = normalize_ts(ev.timestamp, tz)
    if assumed:
        merged_attrs["tz_assumed"] = "utc"
    clean: dict[str, str] = {}
    for k, v in fields.items():
        if not v:
            continue
        if k in _FIELD_NAMES:
            clean[k] = v
        elif k.startswith("attr:"):
            merged_attrs[k[5:]] = v
    # Direct construction — dataclasses.replace() is ~3x slower on this hot path.
    return LogEvent(ev.timestamp, ev.hostname, ev.appname, ev.severity_raw, ev.message,
                    normalized_utc_ts=norm, attrs=merged_attrs, **clean)


_FIELD_NAMES = frozenset({"vendor", "event_type", "interface", "peer_ip", "asn", "vrf",
                          "vni", "tunnel_id", "action", "state"})


class SyslogParser:
    name = "syslog"
    priority = 50

    def parse(self, line: str, env: Envelope, default_host: str) -> LogEvent | None:
        if env.fmt not in _SYSLOG_FORMATS:
            return None
        ev = base_event(env, default_host)
        return with_structure(ev, enrich_netos(ev.appname, ev.message), self.name)


class SecureCrtParser:
    name = "securecrt"
    priority = 60

    def parse(self, line: str, env: Envelope, default_host: str):
        m = SCRT_RE.match(line)
        if not m:
            return None
        msg = (m.group("msg") or "").strip()
        if not msg:
            return SKIP  # empty `§` line — just terminal padding
        ev = LogEvent(timestamp=clean_timestamp(m.group("ts")), hostname=default_host,
                      appname="scrt-session", severity_raw="info", message=msg)
        return with_structure(ev, enrich_netos("", msg), self.name)


class FallbackParser:
    name = "fallback"
    priority = 1000

    def parse(self, line: str, env: Envelope, default_host: str) -> LogEvent:
        ev = LogEvent(timestamp="", hostname=default_host, appname="syslog",
                      severity_raw="info", message=line)
        return with_structure(ev, enrich_netos("", line), self.name)
