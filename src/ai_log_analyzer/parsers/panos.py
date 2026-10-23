"""Palo Alto Networks PAN-OS syslog (CSV) parser.

Handles the default CSV payload for SYSTEM (routing, vpn, ha, globalprotect,
general …), TRAFFIC, THREAT and GLOBALPROTECT logs, sent bare or behind an
RFC 3164 header. Field positions follow the PAN-OS syslog field reference
(SYSTEM: subtype=4, eventid=8, object=9, severity=13, description=14,
device_name=22; TRAFFIC/THREAT: src=7, dst=8, rule=11, app=14, zones=16/17,
interfaces=18/19, ports=24/25, proto=29, action=30; THREAT name=32,
category=33, severity=34). Users (srcuser/dstuser) are never copied out.
"""
from __future__ import annotations

import csv
import re

from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.parsers.base import Envelope
from ai_log_analyzer.parsers.entities import _IP, bgp_state, enrich_netos, valid_ip
from ai_log_analyzer.parsers.generic import with_structure

_TYPES = frozenset({"SYSTEM", "TRAFFIC", "THREAT", "CONFIG", "GLOBALPROTECT", "HIPMATCH",
                    "USERID", "AUTH", "DECRYPTION", "TUNNEL"})
_TS_RE = re.compile(r"^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}$")
_SEV = {"critical": "crit", "high": "err", "medium": "warning", "low": "notice",
        "informational": "info"}
_FAILED_SA_RE = re.compile(rf"(?:Failed|Established) SA:\s*(?P<a>{_IP})\[\d+\]-(?P<b>{_IP})\[\d+\]")
_ANY_IP_RE = re.compile(rf"(?P<ip>{_IP})")


_TYPE_NEEDLES = tuple(f",{t}," for t in _TYPES)


def parse_csv(text: str) -> list[str] | None:
    if "," not in text or not any(n in text for n in _TYPE_NEEDLES):
        return None
    try:
        fields = next(csv.reader([text]))
    except (csv.Error, StopIteration):
        return None
    if len(fields) < 15 or fields[3] not in _TYPES or not _TS_RE.match(fields[1].strip()):
        return None
    return [f.strip() for f in fields]


def _g(fields: list[str], i: int) -> str:
    return fields[i] if i < len(fields) else ""


_USER_RE = re.compile(r"(?i)\b(user ?name|user|login user)\s*:\s*[^,;]+")


def _system(fields: list[str]) -> tuple[str, str, str, dict[str, str], dict[str, str]]:
    sub, eventid, obj = _g(fields, 4), _g(fields, 8), _g(fields, 9)
    # GlobalProtect / auth descriptions name the user — never keep it.
    sev, desc = _g(fields, 13), _USER_RE.sub(r"\1: <redacted>", _g(fields, 14))
    low = f"{eventid} {desc}".lower()
    out: dict[str, str] = {"vendor": "paloalto"}
    attrs = {"eventid": eventid, "object": obj, "module": _g(fields, 12), "subtype": sub}
    if sub == "routing" or "bgp" in low or "ospf" in low:
        net = enrich_netos("", desc)
        out.update({k: v for k, v in net.items() if k != "vendor"})
        if "bgp" in low:
            out["event_type"] = net.get("event_type") or "bgp_session"
            st = bgp_state(low, desc)
            if st:
                out["state"] = st
    elif sub == "vpn" or "ike" in low or "ipsec" in low:
        if re.search(r"phase-?\s*1|ike-nego-p1", low):
            out["event_type"] = "ike_phase1"
        elif re.search(r"phase-?\s*2|ike-nego-p2|quick mode", low):
            out["event_type"] = "ike_phase2"
        else:
            out["event_type"] = "ipsec_tunnel"
        out["tunnel_id"] = obj
        m = _FAILED_SA_RE.search(desc)
        if m:
            out["peer_ip"] = valid_ip(m.group("b"))
            attrs["local_ip"] = valid_ip(m.group("a"))
        else:
            ips = [valid_ip(x.group("ip")) for x in _ANY_IP_RE.finditer(desc)]
            ips = [ip for ip in ips if ip]
            if ips:
                out["peer_ip"] = ips[-1]
        if re.search(r"fail|down|expired|timeout|delete|error", low):
            out["state"] = "down"
        elif re.search(r"succeeded|success|\bup\b|established", low):
            out["state"] = "up"
    elif sub == "ha":
        out["event_type"] = "ha_state"
    elif sub == "globalprotect" or "globalprotect" in low:
        out["event_type"] = "vpn_auth"
    return f"panos-{sub or 'system'}", _SEV.get(sev.lower(), "info"), f"{eventid}: {desc}".strip(": "), out, attrs


def _traffic(fields: list[str], typ: str) -> tuple[str, str, str, dict[str, str], dict[str, str]]:
    sub, src, dst = _g(fields, 4), _g(fields, 7), _g(fields, 8)
    rule, app, fz, tz = _g(fields, 11), _g(fields, 14), _g(fields, 16), _g(fields, 17)
    inif, sport, dport, proto, action = _g(fields, 18), _g(fields, 24), _g(fields, 25), _g(fields, 29), _g(fields, 30)
    attrs = {"src": src, "dst": dst, "rule": rule, "app": app, "from_zone": fz, "to_zone": tz,
             "outbound_if": _g(fields, 19), "subtype": sub}
    out = {"vendor": "paloalto", "action": action, "interface": inif}
    if typ == "THREAT":
        threat, category, tsev = _g(fields, 32), _g(fields, 33), _g(fields, 34)
        attrs.update({"threat": threat, "category": category, "threat_severity": tsev})
        out["event_type"] = "threat"
        msg = (f"THREAT {sub} severity={tsev} threat={threat} category={category} action={action} "
               f"{src} -> {dst}:{dport} app={app} rule={rule}")
        return "panos-threat", _SEV.get(tsev.lower(), "info"), msg, out, attrs
    out["event_type"] = "traffic"
    msg = (f"TRAFFIC {sub} {action} {src}:{sport} -> {dst}:{dport} proto={proto} app={app} "
           f"rule={rule} from={fz} to={tz}")
    sev = "notice" if re.match(r"deny|drop|reset", action) else "info"
    return "panos-traffic", sev, msg, out, attrs


def _globalprotect(fields: list[str]) -> tuple[str, str, str, dict[str, str], dict[str, str]]:
    # GLOBALPROTECT layout varies by release; keep only the event id and an
    # outcome token — never usernames, machine names or client IPs.
    eventid = _g(fields, 8)
    outcome = next((f for f in fields[9:] if f.lower() in ("success", "failure")), "")
    sev = "warning" if outcome.lower() == "failure" else "info"
    return ("panos-globalprotect", sev, f"globalprotect {eventid} {outcome}".strip(),
            {"vendor": "paloalto", "event_type": "vpn_auth", "action": outcome}, {"eventid": eventid})


class PanOSParser:
    name = "panos"
    priority = 20

    def parse(self, line: str, env: Envelope, default_host: str) -> LogEvent | None:
        body = env.body if env.fmt in ("loose", "pri", "rfc3164", "junos") else line
        fields = parse_csv(body)
        if fields is None and body is not line:
            fields = parse_csv(line)
        if fields is None:
            return None
        typ = fields[3]
        if typ == "SYSTEM":
            app, sev, msg, out, attrs = _system(fields)
            device = _g(fields, 22)
        elif typ in ("TRAFFIC", "THREAT"):
            app, sev, msg, out, attrs = _traffic(fields, typ)
            device = ""
        elif typ == "GLOBALPROTECT":
            app, sev, msg, out, attrs = _globalprotect(fields)
            device = ""
        else:
            app, sev, msg = f"panos-{typ.lower()}", "info", ",".join(fields[4:15])
            out, attrs, device = {"vendor": "paloalto"}, {}, ""
            if typ == "CONFIG":
                out["event_type"] = "config_change"
        attrs.update({"log_type": typ, "serial_present": "1" if _g(fields, 2) else ""})
        attrs = {k: v for k, v in attrs.items() if v}
        gen = _g(fields, 6) or fields[1]
        ev = LogEvent(
            timestamp=gen.replace("/", "-").replace(" ", "T", 1),
            hostname=device or (env.hostname if env.fmt != "none" else "") or default_host,
            appname=app,
            severity_raw=sev,
            message=msg,
        )
        return with_structure(ev, out, self.name, attrs=attrs)
