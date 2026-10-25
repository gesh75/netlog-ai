"""Tiny ClassifiedEvent builder shared by the W8 correlation / suppression tests."""
from __future__ import annotations

from datetime import datetime, timedelta

from ai_log_analyzer.classifier import ClassifiedEvent

T0 = datetime(2026, 10, 1, 10, 0, 0)


def ev(host: str, offset_s: float | None, et: str = "bgp_session", *, asn: str = "", peer: str = "",
       iface: str = "", state: str = "down", sev: str = "high", vendor: str = "juniper", vrf: str = "",
       tun: str = "", desc: str = "", attrs: dict | None = None) -> ClassifiedEvent:
    """A classified failure event ``offset_s`` seconds after T0 (None = untimed)."""
    stamp = "" if offset_s is None else (T0 + timedelta(seconds=offset_s)).isoformat()
    return ClassifiedEvent(
        timestamp=stamp, hostname=host, appname="x", severity=sev, severity_raw="", category="routing",
        description=desc or f"{et} {state}", action="", message="", vendor=vendor, event_type=et, asn=asn,
        peer_ip=peer, interface=iface, state=state, vrf=vrf, tunnel_id=tun, attrs=attrs or {})
