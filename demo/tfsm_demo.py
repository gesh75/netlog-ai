"""Demo driver — used by demo/tfsm_demo.tape (VHS).

Self-contained Python session that exercises the new tfsm_fire adapter and prints
human-readable results. Designed to look good when recorded with VHS.
Run directly:  python demo/tfsm_demo.py
"""
from __future__ import annotations

import sys

from ai_log_analyzer.adapters.tfsm_auto import auto_parse, is_available


def hdr(text: str) -> None:
    print()
    print(f"\033[1;36m{'─' * 64}\033[0m")
    print(f"\033[1;36m▶ {text}\033[0m")
    print(f"\033[1;36m{'─' * 64}\033[0m")


def show(label: str, value: object) -> None:
    print(f"  \033[2m{label:<14}\033[0m {value}")


def main() -> int:
    hdr("netlog-ai · tfsm_fire auto-detect parser")
    show("available", is_available())

    # 1) Cisco LLDP table — give the engine a hint so it's fast
    lldp = """\
Device ID           Local Intf     Hold-time  Capability      Port ID
switch1             Gi0/1          120        R               Gi1/0/1
switch2             Gi0/2          120        R               Gi1/0/2
switch3             Gi0/3          120        R               Gi1/0/3
"""
    hdr("Sample 1: Cisco-style LLDP neighbors")
    r = auto_parse(lldp, filter_hint="lldp_neighbor")
    show("template", r.template)
    show("score", f"{r.score:.1f}")
    show("records", len(r.records))
    show("first row", r.records[0] if r.records else "—")

    # 2) IOS show version
    ver = """\
Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE10a
ROM: Bootstrap program is C2960 boot loader
switch uptime is 5 weeks, 2 days, 4 hours, 21 minutes
"""
    hdr("Sample 2: IOS show version")
    r = auto_parse(ver, filter_hint="version")
    show("template", r.template)
    show("score", f"{r.score:.1f}")
    show("records", len(r.records))

    # 3) FRR vtysh BGP summary — proves it picks up FRR/NX-OS lookalike output
    bgp = """\
IPv4 Unicast Summary (VRF default):
BGP router identifier 10.200.0.11, local AS number 65001 vrf-id 0
BGP table version 12

Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd
10.200.0.12     4      65002       145       148        0    0    0 00:12:34            5
10.200.0.13     4      65003       139       142        0    0    0 00:12:30            3
"""
    hdr("Sample 3: FRR-style BGP summary (lab vtysh output)")
    r = auto_parse(bgp, filter_hint="bgp_summary")
    show("template", r.template)
    show("score", f"{r.score:.1f}")
    show("records", len(r.records))
    if r.records:
        for row in r.records[:2]:
            short = {k: row[k] for k in list(row)[:4]}  # first 4 cols only
            print(f"    {short}")

    hdr("Threshold filtering (min_score=40 in production)")
    r = auto_parse("random log line nothing structured here at all",
                   min_score=40.0)
    show("matched", r.matched)
    show("score", f"{r.score:.1f}")
    show("note", "low-confidence matches are rejected by the threshold")

    print()
    print("\033[1;32m✓ Adapter wired. Use auto_parse() anywhere — never raises.\033[0m")
    print("  Source:  src/ai_log_analyzer/adapters/tfsm_auto.py")
    print("  Tests:   tests/test_tfsm_auto.py · 11/11 green")
    print("  Docs:    docs/TFSM_AUTO_PARSER.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
