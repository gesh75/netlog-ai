"""Fortinet FortiOS key=value syslog parser.

FortiOS emits ``date=... time=... devname="FGT" ... type="event"
subtype="vpn" level="error" logdesc="..." msg="..."`` — optionally behind a
PRI or an rsyslog relay header. Event, VPN (IKE/IPsec), SD-WAN health-check /
SLA, router (BGP/OSPF), HA, system (conserve mode, session table) and
traffic/UTM logs are mapped onto the canonical schema.

User identity fields (``user``, ``xauthuser``, ``group``, …) and the device
serial (``devid``) are deliberately never copied into the message.
"""
from __future__ import annotations

import re

from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.parsers.base import Envelope
from ai_log_analyzer.parsers.entities import bgp_state, enrich_netos, valid_ip
from ai_log_analyzer.parsers.generic import with_structure

# The lookbehind and the lazy prefix keep a key attempt to the start of a word run (the first letter or
# underscore in it), so a long run with no "=" costs one linear scan instead of one per character.
_KV_RE = re.compile(r'(?<![\w-])(?:(?![A-Za-z_])[\w-])*(?P<k>[A-Za-z_][\w-]*)=(?P<v>"(?:[^"\\]|\\.)*"|\S*)')
# The SD-WAN state regexes below look at most _GAP characters past "sla" / "back", in at most
# _CLASSIFY_CHARS characters of logdesc + msg; a longer text is flagged (attrs["classify_truncated"]).
_CLASSIFY_CHARS = 4096
_GAP = 300
_START_KEYS = ("date=", "logver=", "devname=", "eventtime=", "itime=")
_LEVELS = {
    "emergency": "emerg", "alert": "alert", "critical": "crit", "error": "err",
    "warning": "warning", "notice": "notice", "information": "info", "debug": "debug",
}
# Fields copied into the human message (in this order). Never identities/serials.
_DETAIL_KEYS = (
    "action", "status", "vpntunnel", "remip", "locip", "tunnelip", "outintf", "reason",
    "error_num", "healthcheck", "interface", "member", "slatargetid", "latency", "jitter",
    "packetloss", "ha_role", "ha_group", "srcip", "dstip", "dstport", "service", "policyid",
    "attack", "severity", "crlevel",
)
_ATTR_KEYS = ("logid", "type", "subtype", "vd", "remip", "locip", "tunnelip", "remport",
              "locport", "healthcheck", "member", "slatargetid", "status", "reason", "logdesc",
              "outintf", "srcip", "dstip", "policyid", "ha_role", "attack", "severity")


def _kv_start(text: str) -> int:
    idx = [text.find(k) for k in _START_KEYS]
    idx = [i for i in idx if i >= 0 and (i == 0 or text[i - 1] in " >")]
    return min(idx) if idx else -1


def parse_kv(text: str) -> dict[str, str] | None:
    """FortiOS kv dict, or None when ``text`` is not a FortiOS log."""
    if "devname=" not in text or not ("logid=" in text or "type=" in text):
        return None
    start = _kv_start(text)
    if start < 0:
        return None
    kv: dict[str, str] = {}
    for m in _KV_RE.finditer(text[start:]):
        v = m.group("v")
        if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
            v = v[1:-1].replace('\\"', '"')
        kv[m.group("k").lower()] = v
    return kv if "devname" in kv else None


def _tz(text: str) -> str | None:
    m = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", (text or "").strip())
    return f"{m.group(1)}{m.group(2)}:{m.group(3)}" if m else None


def _classify(kv: dict[str, str]) -> dict[str, str]:
    typ = kv.get("type", "").lower()
    sub = kv.get("subtype", "").lower()
    desc = f"{kv.get('logdesc', '')} {kv.get('msg', '')}"
    low = desc.lower()
    action = kv.get("action", "").lower()
    status = kv.get("status", "").lower()
    out: dict[str, str] = {"vendor": "fortinet", "action": kv.get("action", "")}

    if sub == "vpn" or "ipsec" in low or "ike" in low:
        if re.search(r"phase\s*(?:-\s*)?2|phase2|quick mode", low) or action.startswith("phase2"):
            out["event_type"] = "ike_phase2"
        elif re.search(r"phase\s*(?:-\s*)?1|phase1", low) or action == "negotiate":
            out["event_type"] = "ike_phase1"
        else:
            out["event_type"] = "ipsec_tunnel"
        out["tunnel_id"] = kv.get("vpntunnel", "")
        out["peer_ip"] = valid_ip(kv.get("remip"))
        out["interface"] = kv.get("outintf", "")
        if action in ("tunnel-down", "phase2-down", "delete_ipsec_sa", "delete_phase1_sa") \
                or re.search(r"error|fail|timeout|dpd", f"{status} {low}"):
            out["state"] = "down"
        elif action in ("tunnel-up", "phase2-up", "install_sa") or "success" in status:
            out["state"] = "up"
    elif sub == "sdwan" or re.search(r"sd-?wan|virtual wan link|health[- ]?check|\bsla\b", low):
        out["event_type"] = "sdwan_sla"
        out["interface"] = kv.get("interface", "")
        rx = low[:_CLASSIFY_CHARS]
        if len(low) > _CLASSIFY_CHARS:
            out["attr:classify_truncated"] = "1"
        if status in ("down", "dead") or re.search(
                rf"out[- ]of[- ]sla|stop forwarding|unreachable|miss(?:ed)? threshold"
                rf"|sla.{{0,{_GAP}}}(?:fail|violat)|\bdead\b", rx):
            out["state"] = "down"
        elif status in ("up", "alive") or re.search(
                rf"in[- ]sla|back.{{0,{_GAP}}}sla|start forwarding|is available|\balive\b", rx):
            out["state"] = "up"
    elif sub == "router" or "bgp" in low or "ospf" in low:
        net = enrich_netos("", kv.get("msg", "") or desc)
        out.update({k: v for k, v in net.items() if k != "vendor"})
        if "bgp" in low and not out.get("state"):
            out["state"] = bgp_state(low, desc)
    elif sub == "ha":
        out["event_type"] = "ha_state"
    elif "conserve mode" in low or "low memory" in low:
        out["event_type"] = "conserve_mode"
        out["state"] = "up" if re.search(r"\b(?:leave|leaves|left|exit\w*)\b", low) else "down"
    elif "session" in low and re.search(r"table|limit|full|exhaust", low):
        out["event_type"] = "session_table"
    elif typ == "traffic":
        out["event_type"] = "traffic"
        out["interface"] = kv.get("srcintf", "")
    elif typ in ("utm", "attack", "anomaly") or sub in ("ips", "virus", "anomaly", "webfilter"):
        out["event_type"] = "threat"
    return out


class FortiOSParser:
    name = "fortios"
    priority = 10

    def parse(self, line: str, env: Envelope, default_host: str) -> LogEvent | None:
        kv = parse_kv(line)
        if kv is None:
            return None
        date, time_ = kv.get("date", ""), kv.get("time", "")
        tz = _tz(kv.get("tz", ""))
        ts = f"{date}T{time_}{tz or ''}" if date and time_ else (env.timestamp or "")
        sub = kv.get("subtype") or kv.get("type") or "event"
        head = [kv.get("logdesc", ""), kv.get("msg", "")]
        text = " | ".join(dict.fromkeys(h for h in head if h))
        details = " ".join(f"{k}={kv[k]}" for k in _DETAIL_KEYS if kv.get(k) and kv[k] != "N/A")
        ev = LogEvent(
            timestamp=ts,
            hostname=kv.get("devname") or env.hostname or default_host,
            appname=f"fortios-{sub.lower()}",
            severity_raw=_LEVELS.get(kv.get("level", "").lower(), "info"),
            message=f"{text} {details}".strip() or line,
        )
        attrs = {k: kv[k] for k in _ATTR_KEYS if kv.get(k)}
        if "vd" in attrs:
            attrs["vdom"] = attrs.pop("vd")
        return with_structure(ev, _classify(kv), self.name, attrs=attrs, tz=tz)
