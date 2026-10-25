"""Cisco Catalyst SD-WAN (Viptela) syslog parser.

Recognizes vEdge/cEdge daemon messages (``%Viptela-…`` / ``%Cisco-SDWAN-…``)
and the notification form (``bfd-state-change``, ``omp-peer-state-change``,
``control-connection-state-change`` with ``key:value`` pairs). The syslog
envelope's base fields are kept exactly as the generic parser would set them;
this plugin only adds the structured BFD / OMP / control-connection fields.
"""
from __future__ import annotations

import re

from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.parsers.base import Envelope
from ai_log_analyzer.parsers.entities import _IP, final_state_word, valid_ip
from ai_log_analyzer.parsers.generic import base_event, with_structure

# Case-sensitive substring gate — vendors emit these tokens verbatim.
_GATE_TOKENS = ("%Viptela-", "%Cisco-SDWAN-", "bfd-state-change", "omp-peer-state-change",
                "control-connection-state-change", "BFD-session")
_KV_RE = re.compile(r'(?P<k>[a-z][\w-]*):(?P<v>"[^"]*"|[^\s,]+)')
_PAIR_RE = re.compile(r"\b(?P<k>local-tloc-ip|remote-tloc-ip|local-color|remote-color|state|"
                      r"local-system-ip|remote-system-ip|flap-reason)\s+(?P<v>[^\s,]+)", re.IGNORECASE)
_PEER_RES = (
    re.compile(rf"\b(?:vsmart|vbond|vmanage|peer|at)\s+(?P<ip>{_IP})", re.IGNORECASE),
    re.compile(rf"->\s*(?P<ip>{_IP})"),
)
_OMP_RE = re.compile(r"(?<![a-z])omp(?![a-z])")  # not the "omp" inside "completed" / "computing"
_STATE_WORD_RE = re.compile(r"\b(?:is|state)\s+(?P<s>up|down|init|handshake)\b", re.IGNORECASE)
_DOWN_WORDS = frozenset({"down", "init", "handshake", "connect", "tear_down", "challenge", "disconnected"})


def _state(word: str) -> str:
    w = word.lower().strip('"')
    if w == "up":
        return "up"
    if w in _DOWN_WORDS:
        return "down"
    return ""


class CiscoSdwanParser:
    name = "cisco_sdwan"
    priority = 30

    def parse(self, line: str, env: Envelope, default_host: str) -> LogEvent | None:
        if not any(t in line for t in _GATE_TOKENS):
            return None
        if env.fmt in ("rfc5424", "rfc3164", "junos"):
            ev = base_event(env, default_host)
        else:
            ev = LogEvent(timestamp="", hostname=default_host, appname="syslog",
                          severity_raw="info", message=line)
        text = ev.message
        low = f"{ev.appname} {text}".lower()
        kv = {m.group("k").lower(): m.group("v").strip('"') for m in _KV_RE.finditer(text)}
        kv.update({m.group("k").lower(): m.group("v") for m in _PAIR_RE.finditer(text)})

        out: dict[str, str] = {"vendor": "cisco_sdwan"}
        if "bfd" in low:
            out["event_type"] = "bfd_session"
        elif _OMP_RE.search(low):
            out["event_type"] = "omp_peer"
        elif "system-config-commit" in low:
            out["event_type"] = "config_change"
        elif "control-connection" in low or "vdaemon" in low or re.search(r"\b(?:vsmart|vbond|vmanage)\b", low):
            out["event_type"] = "control_connection"

        state = _state(kv.get("new-state", "") or kv.get("state", ""))
        if not state:
            m = _STATE_WORD_RE.search(text)
            state = _state(m.group("s")) if m else _state(final_state_word(text))
        if state:
            out["state"] = state

        peer = ""
        for key in ("remote-system-ip", "peer-system-ip", "peer", "dst-ip", "remote-tloc-ip"):
            peer = valid_ip(kv.get(key))
            if peer:
                break
        if not peer:
            for pattern in _PEER_RES:
                m = pattern.search(text)
                if m and valid_ip(m.group("ip")):
                    peer = valid_ip(m.group("ip"))
                    break
        out["peer_ip"] = peer

        lc, rc = kv.get("local-color", ""), kv.get("remote-color", "")
        if out.get("event_type") == "bfd_session" and (lc or rc):
            remote = kv.get("remote-tloc-ip") or kv.get("remote-system-ip") or kv.get("dst-ip") or peer
            out["tunnel_id"] = f"{lc or '?'}->{rc or '?'}@{remote}"
        elif out.get("event_type") == "control_connection":
            ptype = kv.get("peer-type", "")
            if ptype or peer:
                out["tunnel_id"] = f"{ptype or 'controller'}@{peer}"

        attrs = {
            "system_ip": valid_ip(kv.get("local-system-ip") or kv.get("system-ip")),
            "local_color": lc, "remote_color": rc,
            "local_tloc_ip": valid_ip(kv.get("local-tloc-ip")),
            "remote_tloc_ip": valid_ip(kv.get("remote-tloc-ip")),
            "src_ip": valid_ip(kv.get("src-ip")), "dst_ip": valid_ip(kv.get("dst-ip")),
            "flap_reason": kv.get("flap-reason", ""), "peer_type": kv.get("peer-type", ""),
            "site_id": kv.get("site-id", ""),
        }
        if not ev.hostname and kv.get("host-name"):
            import dataclasses
            ev = dataclasses.replace(ev, hostname=kv["host-name"])
        return with_structure(ev, out, self.name, attrs={k: v for k, v in attrs.items() if v})
