"""JSON, CEF and LEEF structured-log parsers.

Collectors and SIEM forwarders often ship one JSON object per line, or ArcSight
CEF / QRadar LEEF records (bare or behind a syslog header). Each is reduced to
the canonical fields (timestamp, hostname, app, severity, message) and then run
through the same NOS entity enrichment as free-text syslog. The parsers are
deliberately conservative: a shape they do not recognise (no message-like key,
a truncated header, invalid JSON) returns ``None`` and falls through to the
generic / fallback plugins exactly as before.
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.parsers.base import Envelope, _canon_ts, _to_int, pri_to_severity
from ai_log_analyzer.parsers.entities import enrich_netos
from ai_log_analyzer.parsers.generic import with_structure
from ai_log_analyzer.parsers.timeutil import normalize_ts

_MESSAGE_KEYS = ("message", "msg", "log", "text", "short_message", "description")
_HOST_KEYS = ("hostname", "host", "devname", "device", "device_name", "node", "source_host")
_TS_KEYS = ("@timestamp", "timestamp", "time", "ts", "datetime", "eventtime", "date")
_SEV_KEYS = ("severity", "level", "loglevel", "log_level", "severity_text", "priority")
_APP_KEYS = ("appname", "app", "program", "process", "service", "logger", "tag")
_SEV_WORDS = {
    "emerg": "emerg", "emergency": "emerg", "panic": "emerg", "fatal": "crit",
    "alert": "alert", "crit": "crit", "critical": "crit", "err": "err", "error": "err",
    "warn": "warning", "warning": "warning", "notice": "notice",
    "info": "info", "informational": "info", "information": "info", "debug": "debug", "trace": "debug",
}
_MAX_ATTR = 200


def _scalar(value: Any) -> str:
    """A string for str/int/float values; nested objects reduce to their name."""
    if isinstance(value, bool):
        return ""
    if isinstance(value, (str, int, float)):
        return str(value).strip()
    if isinstance(value, Mapping):   # ECS-style {"host": {"name": "leaf1"}}
        for k in ("name", "hostname", "id"):
            if isinstance(value.get(k), (str, int)):
                return str(value[k]).strip()
    return ""


def _first(obj: Mapping[str, Any], keys: tuple[str, ...]) -> str:
    lowered = {str(k).lower(): v for k, v in obj.items()}
    for key in keys:
        if key in lowered:
            text = _scalar(lowered[key])
            if text:
                return text
    return ""


def _severity(raw: str, default: str = "info") -> str:
    """Syslog severity word from a word ("ERROR") or a 0-7 number."""
    text = raw.strip().lower()
    n = _to_int(text) if text.isdigit() else None
    if n is not None:
        return pri_to_severity(n) if n <= 7 else default
    return _SEV_WORDS.get(text, default)


def _timestamp(raw: str) -> str:
    """Pass ISO-like stamps through; epoch numbers become ISO-8601 UTC; junk becomes ''."""
    text = raw.strip()
    if not text:
        return ""
    if re.fullmatch(r"\d{9,19}(?:\.\d+)?", text):
        return normalize_ts(text.split(".", 1)[0])[0]
    if re.match(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", text):
        return text
    if re.match(r"[A-Z][a-z]{2}\s+\d{1,2}\s+(?:\d{4}\s+)?\d{2}:\d{2}:\d{2}", text):
        return _canon_ts(text)
    return ""


def _build(ts: str, host: str, app: str, sev: str, message: str, default_host: str, parser: str,
           attrs: Mapping[str, str]) -> LogEvent:
    ev = LogEvent(timestamp=ts, hostname=host or default_host, appname=app, severity_raw=sev,
                  message=message)
    return with_structure(ev, enrich_netos(app, message), parser, attrs=attrs)


# ── JSON ────────────────────────────────────────────────────────────────────

def _json_object(text: str) -> dict[str, Any] | None:
    text = text.strip()
    if not (text.startswith("{") and text.endswith("}")):
        return None
    try:
        obj = json.loads(text)
    except (ValueError, RecursionError):
        return None
    return obj if isinstance(obj, dict) else None


class JsonLineParser:
    name = "json"
    priority = 40

    def parse(self, line: str, env: Envelope, default_host: str) -> LogEvent | None:
        obj = _json_object(line) or (_json_object(env.body) if env.fmt != "none" else None)
        if obj is None:
            return None
        message = _first(obj, _MESSAGE_KEYS)
        if not message:
            return None
        app = _first(obj, _APP_KEYS) or "json"
        ts = _timestamp(_first(obj, _TS_KEYS)) or env.timestamp
        host = _first(obj, _HOST_KEYS) or env.hostname
        sev = _severity(_first(obj, _SEV_KEYS), pri_to_severity(env.pri) if env.pri is not None else "info")
        return _build(ts, host, app, sev, message, default_host, self.name, {})


# ── CEF / LEEF ──────────────────────────────────────────────────────────────

_CEF_RE = re.compile(r"CEF:(?P<ver>\d)\|(?P<rest>.*)$", re.DOTALL)
_LEEF_RE = re.compile(r"LEEF:(?P<ver>[12])(?:\.\d)?\|(?P<rest>.*)$", re.DOTALL)
_EXT_RE = re.compile(r"(?<![\w.])(?P<k>[A-Za-z][\w.]*)=(?P<v>.*?)(?=\s+[A-Za-z][\w.]*=|\s*$)", re.DOTALL)
_CEF_SEV = {"low": "info", "medium": "warning", "high": "err", "very-high": "crit", "unknown": "info"}


def _split_header(rest: str, n: int) -> tuple[list[str], str] | None:
    """First ``n`` pipe-delimited header fields (``\\|`` escapes a pipe) and the remainder."""
    fields: list[str] = []
    cur: list[str] = []
    i = 0
    while i < len(rest) and len(fields) < n:
        ch = rest[i]
        if ch == "\\" and i + 1 < len(rest):
            cur.append(rest[i + 1])
            i += 2
            continue
        if ch == "|":
            fields.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    if len(fields) < n:
        return None
    return fields, rest[i:]


def _cef_severity(raw: str) -> str:
    text = raw.strip().lower()
    n = _to_int(text) if text.isdigit() else None
    if n is not None:
        return "info" if n <= 3 else "warning" if n <= 6 else "err" if n <= 8 else "crit"
    return _CEF_SEV.get(text, "info")


def _syslog_context(env: Envelope) -> tuple[str, str, str]:
    sev = pri_to_severity(env.pri) if env.pri is not None else (env.severity or "info")
    return env.timestamp, env.hostname, sev


class CefParser:
    """ArcSight Common Event Format: ``CEF:0|Vendor|Product|Ver|SigID|Name|Sev|k=v ...``."""

    name = "cef"
    priority = 41

    def parse(self, line: str, env: Envelope, default_host: str) -> LogEvent | None:
        if "CEF:" not in line:
            return None
        m = _CEF_RE.search(line)
        header = _split_header(m.group("rest"), 6) if m else None
        if header is None:
            return None
        (vendor, product, _devver, sigid, name, sev), ext_text = header
        ext = {x.group("k"): x.group("v").strip() for x in _EXT_RE.finditer(ext_text)}
        detail = ext.get("msg", "")
        message = f"{name}: {detail}" if detail and name else (detail or name)
        if not message:
            return None
        ts_env, host_env, sev_env = _syslog_context(env)
        ts = _timestamp(ext.get("rt", "")) or ts_env
        host = ext.get("dvchost") or ext.get("dvc") or host_env
        attrs = {"cef_vendor": vendor[:_MAX_ATTR], "cef_product": product[:_MAX_ATTR],
                 "cef_signature": sigid[:_MAX_ATTR]}
        return _build(ts, host, product or "cef", _cef_severity(sev) if sev.strip() else sev_env, message,
                      default_host, self.name, attrs)


class LeefParser:
    """IBM QRadar LEEF: ``LEEF:1.0|Vendor|Product|Ver|EventID|k=v<TAB>k=v`` (2.0 adds a delimiter field)."""

    name = "leef"
    priority = 42

    def parse(self, line: str, env: Envelope, default_host: str) -> LogEvent | None:
        if "LEEF:" not in line:
            return None
        m = _LEEF_RE.search(line)
        if m is None:
            return None
        v2 = m.group("ver") == "2"
        header = _split_header(m.group("rest"), 4 + (1 if v2 else 0))
        if header is None:
            return None
        fields, body = header
        vendor, product, _ver, event_id = fields[:4]
        delim = "\t"
        if v2 and fields[4].strip():   # delimiter: a char, or hex like "x5e"
            raw = fields[4].strip()
            delim = chr(int(raw[1:], 16)) if re.fullmatch(r"x[0-9A-Fa-f]{1,2}", raw) else raw[0]
        parts = body.split(delim)
        if len(parts) == 1 and "=" in body:
            parts = [x.group(0) for x in _EXT_RE.finditer(body)]
        attrs_in: dict[str, str] = {}
        for part in parts:
            key, sep, val = part.partition("=")
            if sep and key.strip():
                attrs_in[key.strip()] = val.strip()
        detail = attrs_in.get("msg", "")
        message = f"{event_id}: {detail}" if detail and event_id else (detail or event_id)
        if not message:
            return None
        ts_env, host_env, sev_env = _syslog_context(env)
        ts = _timestamp(attrs_in.get("devTime", "")) or ts_env
        host = attrs_in.get("devName") or attrs_in.get("identHostName") or attrs_in.get("hostName") or host_env
        sev = _cef_severity(attrs_in["sev"]) if attrs_in.get("sev") else sev_env
        attrs = {"leef_vendor": vendor[:_MAX_ATTR], "leef_product": product[:_MAX_ATTR],
                 "leef_event": event_id[:_MAX_ATTR]}
        return _build(ts, host, product or "leef", sev, message, default_host, self.name, attrs)
