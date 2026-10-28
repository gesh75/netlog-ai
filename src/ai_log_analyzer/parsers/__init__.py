"""Parser plugin registry for the canonical event schema.

    from ai_log_analyzer.parsers import registry, parse_line
    ev = parse_line('<189>date=2026-10-20 time=07:01:02 devname="FGT-HQ-01" ...')
    ev.vendor, ev.event_type, ev.tunnel_id, ev.state   # fortinet, ike_phase1, HQ-DC1, down

Built-in plugins, in priority order: FortiOS key=value (10), PAN-OS CSV (20),
Cisco Catalyst SD-WAN (30), JSON lines (40), CEF (41), LEEF (42), generic syslog
RFC 5424/3164/Junos/relay + NOS entity enrichment (50), SecureCRT recordings (60),
fallback (1000). Third-party
plugins register with ``registry.register(MyParser())``.
"""
from __future__ import annotations

import dataclasses

from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.ingest import default_max_line_bytes
from ai_log_analyzer.parsers.base import (
    SKIP,
    Envelope,
    ParserPlugin,
    ParserRegistry,
    split_envelope,
)
from ai_log_analyzer.parsers.entities import enrich_netos
from ai_log_analyzer.parsers.fortinet import FortiOSParser
from ai_log_analyzer.parsers.generic import (
    FallbackParser,
    SecureCrtParser,
    SyslogParser,
    with_structure,
)
from ai_log_analyzer.parsers.panos import PanOSParser
from ai_log_analyzer.parsers.sdwan import CiscoSdwanParser
from ai_log_analyzer.parsers.structured import CefParser, JsonLineParser, LeefParser

registry = ParserRegistry()
for _plugin in (FortiOSParser(), PanOSParser(), CiscoSdwanParser(), JsonLineParser(), CefParser(),
                LeefParser(), SyslogParser(), SecureCrtParser(), FallbackParser()):
    registry.register(_plugin)

_BODY_PLUGINS = (FortiOSParser(), PanOSParser(), CiscoSdwanParser())
_NO_ENV = Envelope("none", None, "", "", "", "")


def parse_line(line: str, default_host: str = "") -> LogEvent | None:
    """Parse one already-sanitized line through the registry."""
    return registry.parse(line, default_host)


def ensure_structured(ev: LogEvent) -> LogEvent:
    """Give an event built outside the registry (API connectors) its structure.

    Events that already went through a parser plugin are returned unchanged.
    Otherwise the vendor body parsers are tried on the message (a Splunk or
    Kibana hit often *is* a raw FortiGate / PAN-OS line); the event keeps its
    own timestamp/hostname unless it had none. Connector text has no ingest
    cap, so the parsers see at most the ingest line limit (AI_LOG_ANALYZER_MAX_LINE_BYTES,
    in characters here) of it; a longer message is flagged ``attrs["parse_truncated"]``.
    """
    if not isinstance(ev, LogEvent) or ev.attrs.get("parser"):
        return ev
    msg = ev.message or ""
    limit = default_max_line_bytes()
    capped = 0 < limit < len(msg)
    note = {"parse_truncated": "1"} if capped else {}
    if capped:
        msg = msg[:limit]
    for plugin in _BODY_PLUGINS:
        try:
            parsed = plugin.parse(msg, dataclasses.replace(_NO_ENV, body=msg), ev.hostname)
        except Exception:   # one bad connector row must not fail the batch it arrived in
            registry.note_error(f"plugin {plugin.name}")
            continue
        if isinstance(parsed, LogEvent):
            return dataclasses.replace(
                parsed,
                timestamp=ev.timestamp or parsed.timestamp,
                hostname=ev.hostname or parsed.hostname,
                appname=parsed.appname if parsed.appname != "syslog" else (ev.appname or "syslog"),
                severity_raw=ev.severity_raw if ev.severity_raw not in ("", "info") else parsed.severity_raw,
                attrs={**parsed.attrs, "parser": f"enrich:{plugin.name}", **note},
            )
    return with_structure(ev, enrich_netos(ev.appname, msg), "enrich", attrs=note)


__all__ = [
    "SKIP", "Envelope", "ParserPlugin", "ParserRegistry", "registry", "parse_line",
    "ensure_structured", "split_envelope",
]
