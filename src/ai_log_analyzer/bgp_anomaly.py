"""BGP anomaly detection over classified, structured events.

Turns individual BGP log lines into operator-grade findings:

* **NOTIFICATION decoding** — RFC 4271 error codes and RFC 4486 Cease
  subcodes (e.g. ``6/2`` Administrative Shutdown vs ``4/0`` Hold Timer
  Expired), so a planned shutdown is not triaged like a transport failure.
* **RFC 8203 / RFC 9003 shutdown communication** — the free-text reason an
  operator attached to an administrative shutdown (change ticket, RMA …).
* **Max-prefix** threshold warnings vs. limit exceeded, with received/limit
  counts when the vendor logs them.
* **Origin / AS-path changes** (route monitor or vendor logs) with prefix and
  old → new origin, flagged as possible hijack / leak.
* **Route-flap storms** — a peer with ``>= flap_threshold`` down transitions
  in the flap window, and a fabric-wide storm when several peers flap at once.

Pure functions; bounded memory (at most ``max_findings`` findings kept).
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from ai_log_analyzer.entity_state import EntityState
from ai_log_analyzer.parsers.entities import valid_ip

# RFC 4271 §4.5 error codes.
NOTIFICATION_CODES: dict[int, str] = {
    1: "Message Header Error",
    2: "OPEN Message Error",
    3: "UPDATE Message Error",
    4: "Hold Timer Expired",
    5: "Finite State Machine Error",
    6: "Cease",
    7: "ROUTE-REFRESH Message Error",
}
# RFC 4486 Cease subcodes (+ RFC 9384 9/10).
CEASE_SUBCODES: dict[int, str] = {
    1: "Maximum Number of Prefixes Reached",
    2: "Administrative Shutdown",
    3: "Peer De-configured",
    4: "Administrative Reset",
    5: "Connection Rejected",
    6: "Other Configuration Change",
    7: "Connection Collision Resolution",
    8: "Out of Resources",
    9: "Hard Reset",
    10: "BFD Down",
}
_PLANNED_CEASE = frozenset({2, 3, 4, 6})

_CODE_SLASH_RE = re.compile(r"(?:notification|cease)[^\n]*?\b(?P<c>[1-7])/(?P<s>\d{1,2})\b", re.IGNORECASE)
_CODE_WORDS_RE = re.compile(r"\bcode\s+(?P<c>[1-7])\b(?:[^\n]*?\bsubcode\s+(?P<s>\d{1,2})\b)?", re.IGNORECASE)
_SHUTDOWN_COMM_RE = re.compile(
    r"shutdown communication\s*[:=]?\s*(?:\"(?P<q>[^\"]{1,255})\"|'(?P<q2>[^']{1,255})'|(?P<raw>[^,;\n]{1,255}))",
    re.IGNORECASE,
)
_MAXPFX_COUNTS_RES = (
    re.compile(r"reaches\s+(?P<recv>\d+),\s*max\s+(?P<lim>\d+)", re.IGNORECASE),
    re.compile(r"(?:prefix\s+)?(?P<recv>\d+)\s+exceed(?:s|ed)?\s+(?:the\s+)?limit\s+(?P<lim>\d+)", re.IGNORECASE),
    re.compile(r"limit\s+(?P<lim>\d+)[^\n]*?received\s+(?P<recv>\d+)", re.IGNORECASE),
)
_PREFIX_RE = re.compile(r"\b(?P<p>(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}|[0-9A-Fa-f:]+::?[0-9A-Fa-f:]*/\d{1,3})\b")
_ORIGIN_RE = re.compile(r"\bAS\s?(?P<old>\d{1,10})\s*(?:->|to)\s*AS\s?(?P<new>\d{1,10})\b", re.IGNORECASE)
_PATH_RE = re.compile(r":\s*(?P<old>\d+(?:\s+\d+)*)\s*->\s*(?P<new>\d+(?:\s+\d+)*)")

_DESC_TYPES: dict[str, str] = {
    "BGP max-prefix limit exceeded": "max_prefix_exceeded",
    "BGP max-prefix threshold warning": "max_prefix_warning",
    "BGP hold timer expired": "hold_timer_expired",
    "BGP administrative shutdown / reset (Cease)": "admin_cease",
    "BGP NOTIFICATION — protocol / OPEN / UPDATE error": "notification_error",
    "BGP origin / AS-path change (possible hijack or leak)": "path_change",
}

_INTERPRETATION: dict[str, str] = {
    "hold_timer_expired": ("Keepalives were lost for the full hold time — suspect the transport "
                           "(underlay, IPsec/SD-WAN path, MTU) or control-plane congestion, not a "
                           "deliberate reset."),
    "admin_shutdown": ("The peer was shut down on purpose (RFC 4486 Cease/2). Treat as planned "
                       "work if a change record exists; otherwise ask who shut it."),
    "admin_reset": "The session was reset by an operator or a configuration change (Cease/3, /4 or /6).",
    "max_prefix_exceeded": ("The peer sent more prefixes than the configured limit and the session was "
                            "torn down — likely a route leak or a full-table mis-advertisement."),
    "max_prefix_warning": "Prefix count crossed the warning threshold; the session is still up.",
    "notification_error": ("A protocol error tore the session down (OPEN/UPDATE/FSM) — usually a "
                           "configuration mismatch (AS, capabilities, auth) or a malformed update."),
    "path_change": ("Origin AS or AS-path changed for a monitored prefix — validate against "
                    "IRR/RPKI before trusting it; possible hijack or leak."),
    "peer_flapping": "The session flapped repeatedly — dampen and look for a lossy transport.",
    "route_flap_storm": "Several BGP sessions flapped together — look for a shared upstream cause.",
}


def decode_notification(message: str) -> tuple[int | None, int | None]:
    """(code, subcode) from vendor NOTIFICATION text, or (None, None)."""
    m = _CODE_SLASH_RE.search(message) or _CODE_WORDS_RE.search(message)
    if not m:
        return None, None
    code = int(m.group("c"))
    sub = m.group("s")
    return code, int(sub) if sub is not None else None


def shutdown_communication(message: str) -> str:
    m = _SHUTDOWN_COMM_RE.search(message)
    if not m:
        return ""
    return (m.group("q") or m.group("q2") or m.group("raw") or "").strip()


def _finding(ev: Any, ftype: str, **extra: Any) -> dict[str, Any]:
    out = {
        "type": ftype,
        "hostname": ev.hostname,
        "peer_ip": ev.peer_ip,
        "asn": ev.asn,
        "vrf": ev.vrf,
        "vendor": ev.vendor,
        "timestamp": ev.timestamp,
        "severity": ev.severity,
        "message": ev.message[:300],
        "interpretation": _INTERPRETATION.get(ftype, ""),
    }
    out.update({k: v for k, v in extra.items() if v not in (None, "")})
    return out


class BgpAnomalyCollector:
    """Streaming collector of per-event BGP anomalies."""

    def __init__(self, max_findings: int = 500) -> None:
        self.max_findings = max_findings
        self.findings: list[dict[str, Any]] = []
        self.dropped = 0

    def add(self, ev: Any) -> None:
        ftype = _DESC_TYPES.get(getattr(ev, "description", ""))
        if not ftype:
            return
        extra: dict[str, Any] = {}
        code, sub = decode_notification(ev.message)
        if code is not None:
            extra["code"] = code
            extra["code_name"] = NOTIFICATION_CODES.get(code, "")
            if sub is not None:
                extra["subcode"] = sub
                if code == 6:
                    extra["subcode_name"] = CEASE_SUBCODES.get(sub, "")
        if ftype == "admin_cease":
            comm = shutdown_communication(ev.message)
            planned_shutdown = sub == 2 or comm or re.search(r"admin\w*\s+shut", ev.message, re.IGNORECASE)
            ftype = "admin_shutdown" if planned_shutdown else "admin_reset"
            extra["shutdown_communication"] = comm
            extra["planned"] = sub in _PLANNED_CEASE if sub is not None else True
        elif ftype in ("max_prefix_exceeded", "max_prefix_warning"):
            for pattern in _MAXPFX_COUNTS_RES:
                m = pattern.search(ev.message)
                if m:
                    extra["received"] = int(m.group("recv"))
                    extra["limit"] = int(m.group("lim"))
                    break
            extra["planned"] = False
        elif ftype == "path_change":
            p = _PREFIX_RE.search(ev.message)
            if p:
                extra["prefix"] = p.group("p")
            o = _ORIGIN_RE.search(ev.message)
            if o:
                extra["old_origin"], extra["new_origin"] = o.group("old"), o.group("new")
            else:
                path = _PATH_RE.search(ev.message)
                if path:
                    old, new = path.group("old").split(), path.group("new").split()
                    extra["old_path"], extra["new_path"] = " ".join(old), " ".join(new)
                    if old[-1] != new[-1]:
                        extra["old_origin"], extra["new_origin"] = old[-1], new[-1]
            extra["planned"] = False
        else:
            extra["planned"] = False
        if len(self.findings) >= self.max_findings:
            self.dropped += 1
            return
        self.findings.append(_finding(ev, ftype, **extra))

    def report(self, entity_states: Iterable[EntityState] = (), storm_peers: int = 3) -> dict[str, Any]:
        findings = list(self.findings)
        flapping = [s for s in entity_states if s.kind == "bgp" and s.status == "flapping"]
        for s in flapping:
            vrf, _, peer = s.entity.partition("|")
            findings.append({
                "type": "peer_flapping", "hostname": s.hostname, "peer_ip": valid_ip(peer) or peer,
                "vrf": vrf, "vendor": s.vendor, "timestamp": s.first_down, "severity": "high",
                "downs": s.downs, "current_state": s.current_state, "planned": False,
                "interpretation": _INTERPRETATION["peer_flapping"],
            })
        if len(flapping) >= storm_peers:
            findings.append({
                "type": "route_flap_storm", "severity": "critical", "planned": False,
                "peers": sorted({f"{s.hostname}:{s.entity.partition('|')[2]}" for s in flapping}),
                "hosts": sorted({s.hostname for s in flapping}),
                "timestamp": min((s.first_down for s in flapping if s.first_down), default=""),
                "interpretation": _INTERPRETATION["route_flap_storm"],
            })
        counts: dict[str, int] = {}
        for f in findings:
            counts[f["type"]] = counts.get(f["type"], 0) + 1
        planned = sum(1 for f in findings if f.get("planned"))
        return {
            "findings": findings,
            "counts": counts,
            "planned": planned,
            "unplanned": len(findings) - planned,
            "dropped": self.dropped,
        }
