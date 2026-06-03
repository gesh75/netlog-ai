"""Rule-based phased deep-analysis KB — fallback when LLM is unavailable.

Each entry follows the 5-phase incident workflow:
    1. DIAGNOSE   — verify what is happening (read-only commands, expected results)
    2. MITIGATE   — immediate workaround to restore service
    3. REMEDIATE  — root-cause fix
    4. VERIFY     — confirm green
    5. OPTIMIZE   — preventive measures, config-as-code patches, monitoring

Every action carries platform-specific CLI variants (FRR/Junos/EOS) so the UI
can render the right command for the device being inspected and execute it
against the DCN_Network_Tool's SSH proxy.
"""
from __future__ import annotations

import re
from typing import Any

# ── Type shorthand ───────────────────────────────────────────────────────────
# Action: {cli: {platform: command}, expected: str, note: str}
# Phase:  {name: str, goal: str, actions: list[Action]}
# Pattern: {match: regex, root_cause: str, risk: str, phases: list[Phase],
#           preventive_config: list[str], monitoring: list[str], timeline: str}

# ─────────────────────────────────────────────────────────────────────────────
# BGP — peer down / connect failure
# ─────────────────────────────────────────────────────────────────────────────
_BGP_DOWN = {
    "match": r"bgp.*(?:down|connect|idle|notification|hold|cease)",
    "root_cause": (
        "BGP session failure. Common causes: (1) Physical link down between peers, "
        "(2) Underlay routing failure (no route to peer loopback), (3) TCP port 179 "
        "blocked by firewall/ACL, (4) Peer device down or misconfigured, "
        "(5) Hold timer expiry due to CPU overload."
    ),
    "risk": "Routes via this peer withdrawn → traffic blackhole or re-route through suboptimal path.",
    "timeline": "P1 — investigate within 15 min; service-impacting if uplink peer.",
    "rca": {
        "root_cause": (
            "BGP session failure. Common causes: (1) Physical link down between peers, "
            "(2) Underlay routing failure (no route to peer loopback), (3) TCP port 179 "
            "blocked by firewall/ACL, (4) Peer device down or misconfigured, "
            "(5) Hold timer expiry due to CPU overload."
        ),
        "risk": "Routes learned via failed peer are lost → traffic blackholing. If multiple peers fail, site may become isolated from IBGP mesh.",
        "resolution_steps": [
            "Check if BGP peer device is reachable (ping loopback)",
            "Verify physical link status between devices",
            "Check route table for path to peer address",
            "Verify no firewall/ACL blocking TCP 179",
            "Review BGP neighbor configuration on both sides",
            "Check CPU/memory on both devices (hold timer expiry = CPU issue)",
            "If IBGP: verify IGP (OSPF/ISIS) is healthy",
        ],
        "cli_junos": [
            "show bgp summary",
            "show bgp neighbor <peer-ip>",
            "show route <peer-ip>",
            "ping <peer-ip> source <local-loopback> rapid count 5",
            "show ospf neighbor",
            "show isis adjacency",
            "show firewall filter __default_bpdu_filter__",
            "show system processes extensive | match rpd",
        ],
        "cli_eos": [
            "show bgp summary",
            "show bgp neighbor <peer-ip>",
            "show ip route <peer-ip>",
            "ping <peer-ip> source <loopback>",
            "show ip ospf neighbor",
        ],
        "timeline": "P1 — Verify reachability NOW. Fix routing/link within hours.",
    },
    "phases": [
        {
            "name": "Diagnose",
            "goal": "Determine peer state and whether L3 reachability is intact.",
            "actions": [
                {"cli": {"frr": "vtysh -c 'show ip bgp summary'",
                         "junos": "show bgp summary",
                         "eos": "show ip bgp summary"},
                 "expected": "Peer state: Idle / Active / Connect → session is broken; Established → already recovered",
                 "note": "Look at the State/PfxRcd column"},
                {"cli": {"frr": "vtysh -c 'show ip bgp neighbor <peer-ip>'",
                         "junos": "show bgp neighbor <peer-ip>",
                         "eos": "show ip bgp neighbors <peer-ip>"},
                 "expected": "Last error / Last reset reason explains why the session dropped",
                 "note": "Replace <peer-ip> with the actual peer address from the event"},
                {"cli": {"frr": "ping -c 5 <peer-ip>",
                         "junos": "ping <peer-ip> rapid count 5",
                         "eos": "ping <peer-ip>"},
                 "expected": "0% loss — L3 path is up",
                 "note": "If 100% loss, this is a physical/IGP problem first"},
                {"cli": {"frr": "ss -tn state established '( dport = :179 or sport = :179 )'",
                         "junos": "show system connections | match :179",
                         "eos": "show tcp connections | grep 179"},
                 "expected": "Established TCP/179 socket exists toward the peer",
                 "note": "If no socket: ACL/firewall blocking TCP 179"},
            ],
        },
        {
            "name": "Mitigate",
            "goal": "Restore traffic flow without yet fixing the root cause.",
            "actions": [
                {"cli": {"frr": "vtysh -c 'clear ip bgp <peer-ip> soft'",
                         "junos": "clear bgp neighbor <peer-ip> soft",
                         "eos": "clear ip bgp <peer-ip> soft"},
                 "expected": "Session refreshes prefixes without full reset",
                 "note": "Soft-clear is non-disruptive"},
                {"cli": {"frr": "vtysh -c 'clear ip bgp <peer-ip>'",
                         "junos": "clear bgp neighbor <peer-ip>",
                         "eos": "clear ip bgp <peer-ip>"},
                 "expected": "Full session reset — re-establishes from scratch",
                 "note": "Use only if soft-clear didn't recover"},
            ],
        },
        {
            "name": "Remediate",
            "goal": "Fix the underlying cause.",
            "actions": [
                {"cli": {"frr": "vtysh -c 'show running-config bgp'",
                         "junos": "show configuration protocols bgp",
                         "eos": "show running-config | section bgp"},
                 "expected": "Validate AS numbers, neighbor IPs, MD5 password, route-maps",
                 "note": "Compare with peer-side config — mismatch is the most common cause"},
                {"cli": {"frr": "tail -100 /var/log/frr/bgpd.log",
                         "junos": "show log messages | match BGP | last 100",
                         "eos": "show logging | grep -i bgp"},
                 "expected": "Local log explains the reset reason",
                 "note": "Coordinate with peer admin to compare reset reasons"},
            ],
        },
        {
            "name": "Verify",
            "goal": "Confirm session is Established and prefixes are flowing.",
            "actions": [
                {"cli": {"frr": "vtysh -c 'show ip bgp summary'",
                         "junos": "show bgp summary",
                         "eos": "show ip bgp summary"},
                 "expected": "Peer State = Established, PfxRcd > 0",
                 "note": ""},
                {"cli": {"frr": "vtysh -c 'show ip route bgp | head -20'",
                         "junos": "show route protocol bgp | match active",
                         "eos": "show ip route bgp | head"},
                 "expected": "BGP routes installed in RIB",
                 "note": ""},
            ],
        },
        {
            "name": "Optimize",
            "goal": "Prevent recurrence and shorten future detection time.",
            "actions": [
                {"cli": {"frr": "vtysh -c 'configure' -c 'router bgp <ASN>' -c 'neighbor <peer-ip> bfd'"},
                 "expected": "Enables BFD on the peer — sub-second failure detection",
                 "note": "Reduces blackhole time from 90s+ (hold timer) to <1s"},
                {"cli": {"frr": "vtysh -c 'configure' -c 'router bgp <ASN>' -c 'bgp graceful-restart'"},
                 "expected": "Routes preserved across control-plane restarts",
                 "note": "Critical for planned maintenance"},
                {"cli": {"frr": "vtysh -c 'configure' -c 'router bgp <ASN>' -c 'neighbor <peer-ip> timers 3 9'"},
                 "expected": "Tighter timers — keepalive 3s, hold 9s",
                 "note": "Pair with BFD; only on links with stable jitter"},
            ],
        },
    ],
    "preventive_config": [
        "# FRR config snippet — drop into the peer block:",
        "  neighbor <peer-ip> bfd",
        "  neighbor <peer-ip> timers 3 9",
        "  bgp graceful-restart",
        "  neighbor <peer-ip> prefix-list FROM-PEER-IN in",
        "  neighbor <peer-ip> maximum-prefix 500000 90",
    ],
    "monitoring": [
        "Alert on BGP state != Established for > 60s",
        "Alert if PfxRcd drops by > 20% in 5 min",
        "Track BGP flaps/hour per peer — alert when > 2",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# OSPF adjacency change
# ─────────────────────────────────────────────────────────────────────────────
_OSPF_ADJ = {
    "match": r"ospf|adj.*change|adj.*full|dead.*timer",
    "root_cause": (
        "OSPF adjacency state change — hello/dead-timer mismatch, MTU mismatch, "
        "subnet mismatch on the same link, or interface flap can break the adjacency."
    ),
    "risk": "Intra-area routing recomputation; transient blackholes during SPF run.",
    "timeline": "P2 — investigate within 1h.",
    "rca": {
        "root_cause": "OSPF adjacency change. Neighbors going down indicates link failure, MTU mismatch, area misconfiguration, or dead timer expiry.",
        "risk": "SPF recalculation, route convergence delay, potential traffic rerouting through suboptimal paths.",
        "resolution_steps": [
            "Check OSPF neighbor state and identify which neighbor changed",
            "Verify physical link to the neighbor",
            "Check MTU matches on both sides of the link",
            "Verify OSPF area, hello/dead timers match",
            "Review interface error counters for drops/CRC errors",
        ],
        "cli_junos": [
            "show ospf neighbor",
            "show ospf neighbor detail",
            "show ospf interface",
            "show interfaces <intf> extensive | match \"error|drop|MTU\"",
        ],
        "cli_eos": [
            "show ip ospf neighbor",
            "show ip ospf interface",
            "show interfaces <intf> counters errors",
        ],
        "timeline": "P1 — Investigate immediately.",
    },
    "phases": [
        {
            "name": "Diagnose",
            "goal": "Check adjacency state and identify the broken link.",
            "actions": [
                {"cli": {"frr": "vtysh -c 'show ip ospf neighbor'",
                         "junos": "show ospf neighbor",
                         "eos": "show ip ospf neighbor"},
                 "expected": "Neighbor in Full state, not Init / 2-Way / ExStart",
                 "note": "Stuck in ExStart = MTU mismatch; stuck in 2-Way = priority issue"},
                {"cli": {"frr": "vtysh -c 'show ip ospf interface'",
                         "junos": "show ospf interface detail",
                         "eos": "show ip ospf interface"},
                 "expected": "Hello / dead intervals match peer; MTU correct",
                 "note": ""},
            ],
        },
        {
            "name": "Mitigate",
            "goal": "Restore adjacency.",
            "actions": [
                {"cli": {"frr": "vtysh -c 'clear ip ospf process'",
                         "junos": "restart routing-process",
                         "eos": "clear ip ospf neighbor *"},
                 "expected": "Force OSPF to renegotiate",
                 "note": "Disruptive — only if neighbor is hard-stuck"},
            ],
        },
        {
            "name": "Remediate",
            "goal": "Fix timer / MTU / subnet mismatch.",
            "actions": [
                {"cli": {"frr": "ip link show <int> | grep -i mtu",
                         "junos": "show interfaces <int> | match MTU",
                         "eos": "show interfaces <int> | grep -i mtu"},
                 "expected": "Local MTU == peer MTU",
                 "note": "Set both to 9000 for jumbo, 1500 for default"},
            ],
        },
        {
            "name": "Verify",
            "goal": "Confirm adjacency is Full and DB is synchronized.",
            "actions": [
                {"cli": {"frr": "vtysh -c 'show ip ospf neighbor'",
                         "junos": "show ospf neighbor",
                         "eos": "show ip ospf neighbor"},
                 "expected": "Neighbor state = Full",
                 "note": ""},
                {"cli": {"frr": "vtysh -c 'show ip ospf database summary'",
                         "junos": "show ospf database summary",
                         "eos": "show ip ospf database summary"},
                 "expected": "LSDB matches peer count",
                 "note": ""},
            ],
        },
        {
            "name": "Optimize",
            "goal": "Reduce convergence time + prevent flap impact.",
            "actions": [
                {"cli": {"frr": "vtysh -c 'configure' -c 'interface <int>' -c 'ip ospf bfd'"},
                 "expected": "BFD-tracked OSPF — sub-second failure detection",
                 "note": ""},
                {"cli": {"frr": "vtysh -c 'configure' -c 'router ospf' -c 'timers throttle spf 50 200 5000'"},
                 "expected": "Faster initial SPF, exponential back-off",
                 "note": "Tune carefully — too fast burns CPU during flap storms"},
            ],
        },
    ],
    "preventive_config": [
        "  interface <int>",
        "    ip ospf bfd",
        "    ip ospf hello-interval 1",
        "    ip ospf dead-interval 4",
        "  router ospf",
        "    timers throttle spf 50 200 5000",
        "    timers throttle lsa 50 200 5000",
    ],
    "monitoring": [
        "Alert when OSPF neighbor count != expected",
        "Track SPF runs/min — alert if > 10",
        "Alert on LSA-throttle activation",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# Interface link down / flap / err-disable
# ─────────────────────────────────────────────────────────────────────────────
_INT_DOWN = {
    "match": r"link.*down|carrier.*down|if_down|err.?disabl|errdisable",
    "root_cause": (
        "Interface lost link — SFP/transceiver failure, fiber damage, patch panel issue, "
        "peer-side shutdown, or err-disable trigger (BPDU guard, port-security, etc.)."
    ),
    "risk": "Traffic loss on this link; degraded LAG throughput if member; full outage if uplink.",
    "timeline": "P1 — immediate if uplink/transit.",
    "rca": {
        "root_cause": "Interface state change (link down/up or flapping). Common causes: (1) SFP/transceiver failure, (2) Fiber cut or bend, (3) Patch panel issue, (4) Auto-negotiation failure, (5) Remote device reboot, (6) Error-disable due to excessive errors.",
        "risk": "Traffic disruption on affected interface, potential impact on LAG if member link, customer-facing outage if last-resort path.",
        "resolution_steps": [
            "Check interface status and error counters",
            "Verify SFP Rx/Tx optical power (low Rx = fiber issue, low Tx = SFP issue)",
            "Check for CRC, input, or output errors (indicates physical layer problem)",
            "Verify auto-negotiation or speed/duplex settings",
            "Check remote device interface status",
            "If flapping: look for pattern (regular = auto-neg, random = fiber)",
            "If error-disabled: identify trigger, fix root cause, re-enable",
        ],
        "cli_junos": [
            "show interfaces <intf> extensive",
            "show interfaces <intf> | match \"Physical|Status|Speed|Duplex\"",
            "show interfaces diagnostics optics <intf>",
            "show log messages | match <intf> | last 20",
            "set interfaces <intf> disable",
            "delete interfaces <intf> disable",
            "commit",
        ],
        "cli_eos": [
            "show interfaces <intf>",
            "show interfaces <intf> counters errors",
            "show interfaces <intf> transceiver detail",
            "interface <intf>",
            "  shutdown / no shutdown",
        ],
        "timeline": "P1 — Check SFP and cabling today.",
    },
    "phases": [
        {
            "name": "Diagnose",
            "goal": "Identify physical vs administrative cause.",
            "actions": [
                {"cli": {"frr": "ip link show <int>",
                         "junos": "show interfaces <int> extensive",
                         "eos": "show interfaces <int> status"},
                 "expected": "State / admin status; flap counters",
                 "note": "DOWN/DOWN = both sides; UP/DOWN = peer-side issue"},
                {"cli": {"frr": "ethtool <int>",
                         "junos": "show interfaces diagnostics optics <int>",
                         "eos": "show interfaces <int> transceiver detail"},
                 "expected": "Link detected: yes; Speed/Duplex correct; SFP power within range",
                 "note": "Rx -30dBm or worse = bad fiber/connector"},
                {"cli": {"frr": "ethtool -S <int> | grep -iE 'error|drop|crc'",
                         "junos": "show interfaces <int> extensive | match error",
                         "eos": "show interfaces <int> counters errors"},
                 "expected": "Zero CRC / input errors",
                 "note": "Rising CRC count = bad fiber/SFP"},
            ],
        },
        {
            "name": "Mitigate",
            "goal": "Restore the link if administratively bouncable.",
            "actions": [
                {"cli": {"frr": "ip link set <int> down && sleep 2 && ip link set <int> up",
                         "junos": "deactivate interfaces <int> disable",
                         "eos": "interface <int> shutdown / no shutdown"},
                 "expected": "Link returns to UP",
                 "note": "Last-resort — physical issue won't recover from bounce"},
            ],
        },
        {
            "name": "Remediate",
            "goal": "Replace bad hardware or clear err-disable cause.",
            "actions": [
                {"cli": {"junos": "show log messages | match errdisable | last 50",
                         "eos": "show errdisable recovery"},
                 "expected": "Trigger cause: BPDU-guard, link-flap, port-security",
                 "note": "Fix the root cause before clearing err-disable"},
            ],
        },
        {
            "name": "Verify",
            "goal": "Link up, no rising counters.",
            "actions": [
                {"cli": {"frr": "ip -br link show <int>",
                         "junos": "show interfaces <int> terse",
                         "eos": "show interfaces <int> status"},
                 "expected": "UP/UP, traffic flowing",
                 "note": ""},
            ],
        },
        {
            "name": "Optimize",
            "goal": "Detect future flaps faster, protect against bad SFPs.",
            "actions": [
                {"cli": {"junos": "set interfaces <int> hold-time up 5000 down 0",
                         "eos": "interface <int> ; dampening"},
                 "expected": "Dampens flapping interface — prevents protocol churn",
                 "note": "Hold-time 5000ms suppresses sub-5s flaps from triggering protocol convergence"},
            ],
        },
    ],
    "preventive_config": [
        "# Dampening (Junos)",
        "  set interfaces <int> hold-time up 5000 down 0",
        "# Interface monitoring",
        "  set chassis fpc <n> pic <m> port-mode 100g",
    ],
    "monitoring": [
        "Alert if interface flap count > 3/hour",
        "Track SFP Rx power — alert if < -20dBm",
        "Track CRC errors — alert on any increment",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# LACP / LAG member issues
# ─────────────────────────────────────────────────────────────────────────────
_LAG_DOWN = {
    "match": r"lacp.*(?:timeout|expired|down)|lag_bundle.*(?:down|leaving|member)|ae\d+.*down",
    "root_cause": (
        "LAG member left the bundle — LACP PDU loss, mismatched LACP mode, "
        "speed/duplex mismatch, or peer-side configuration change."
    ),
    "risk": "Reduced bundle throughput; full LAG-down if last member.",
    "timeline": "P1 if LAG-down; P2 if member-only.",
    "rca": {
        "root_cause": "LAG/LACP member link event. Possible causes: (1) Physical link failure (SFP, fiber, patch panel), (2) LACP mode mismatch (active vs passive), (3) LACP timeout mismatch, (4) Speed/duplex mismatch, (5) Remote side interface down.",
        "risk": "Reduced aggregate bandwidth, potential traffic loss if minimum-links threshold is breached, hash redistribution causing microloops.",
        "resolution_steps": [
            "Identify which LAG member(s) are affected",
            "Check physical layer — SFP Rx/Tx power, fiber integrity",
            "Verify LACP mode matches on both ends (active/active or active/passive)",
            "Check LACP timeout settings (fast vs slow)",
            "Verify interface speed matches on both sides",
            "Check for CRC errors or input/output errors on member interfaces",
            "Test with alternative SFP/fiber if available",
        ],
        "cli_junos": [
            "show lacp interfaces",
            "show lacp statistics interfaces ae<N>",
            "show interfaces ae<N> detail",
            "show interfaces ae<N> | match \"Physical|Status|Speed\"",
            "show interfaces diagnostics optics <member-intf>",
        ],
        "cli_eos": [
            "show lacp neighbor",
            "show lacp counters",
            "show port-channel <N> detailed",
            "show interfaces <member> transceiver detail",
        ],
        "timeline": "P1 — Check physical cabling NOW. Replace SFP if needed.",
    },
    "phases": [
        {
            "name": "Diagnose",
            "goal": "Identify which members are down and why.",
            "actions": [
                {"cli": {"frr": "cat /proc/net/bonding/bond0",
                         "junos": "show lacp interfaces",
                         "eos": "show port-channel detail all"},
                 "expected": "All expected members in Distributing state",
                 "note": "Look for Defaulted, Expired, or Selected-but-not-distributing"},
                {"cli": {"junos": "show lacp statistics interfaces",
                         "eos": "show lacp neighbor"},
                 "expected": "LACP PDU counters increment on both sides",
                 "note": "Static counters = LACP PDUs not arriving"},
                {"cli": {"junos": "show interfaces <member> extensive | match Lacp",
                         "eos": "show interfaces <member> | grep -i lacp"},
                 "expected": "Member-side LACP error counters",
                 "note": ""},
            ],
        },
        {
            "name": "Mitigate",
            "goal": "Get the bundle back to full bandwidth.",
            "actions": [
                {"cli": {"junos": "deactivate interfaces <member> gigether-options 802.3ad",
                         "eos": "interface <member> ; channel-group <id> mode active"},
                 "expected": "Member re-added to bundle",
                 "note": "Re-toggle membership if stuck"},
            ],
        },
        {
            "name": "Remediate",
            "goal": "Address root cause (cable, SFP, config).",
            "actions": [
                {"cli": {"junos": "show interfaces diagnostics optics <member>",
                         "eos": "show interfaces <member> transceiver detail"},
                 "expected": "Same checks as single interface — bad SFP, bad fiber",
                 "note": ""},
            ],
        },
        {
            "name": "Verify",
            "goal": "All members distributing, throughput correct.",
            "actions": [
                {"cli": {"junos": "show interfaces ae<n> extensive | match Active",
                         "eos": "show port-channel <id> detail"},
                 "expected": "All members active and distributing",
                 "note": ""},
            ],
        },
        {
            "name": "Optimize",
            "goal": "Faster failure detection in the bundle.",
            "actions": [
                {"cli": {"junos": "set interfaces ae<n> aggregated-ether-options lacp periodic fast",
                         "eos": "interface port-channel <id> ; lacp rate fast"},
                 "expected": "LACP PDUs every 1s instead of 30s",
                 "note": "Detects member failure in 3s instead of 90s"},
            ],
        },
    ],
    "preventive_config": [
        "  interfaces ae<n>",
        "    aggregated-ether-options",
        "      lacp periodic fast",
        "      lacp system-priority 100",
        "      minimum-links 1",
    ],
    "monitoring": [
        "Alert if LAG member count < expected",
        "Alert if LAG bandwidth < 50% of nominal",
        "Track LACP-expired events per LAG",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# ASIC / hardware parity error
# ─────────────────────────────────────────────────────────────────────────────
_ASIC_PARITY = {
    "match": r"parity|ser_overlay|sbus|memory.*block",
    "root_cause": (
        "Hard parity error in switching ASIC SRAM — SER (Soft Error Recovery) repeatedly "
        "fails at a fixed memory address, indicating physical silicon damage."
    ),
    "risk": "Forwarding-table corruption — packet drops or unicast blackholing through the affected hash bucket.",
    "timeline": "P1 — schedule FPC restart in maintenance window; RMA if recurring.",
    "rca": {
        "root_cause": "Permanent (hard) parity error in switching ASIC SRAM. The SER (Soft Error Recovery) mechanism repeatedly fails to correct the error at a fixed memory address, indicating physical silicon damage — not a transient cosmic ray bit flip.",
        "risk": "IPv4/IPv6 traffic blackholing through affected hash bucket, incorrect forwarding decisions, sustained CPU overhead from error logging, syslog flooding consuming disk/bandwidth.",
        "resolution_steps": [
            "Verify error is at fixed address (same address every time = hard error)",
            "Check current memory status and identify affected forwarding table",
            "Attempt FPC restart in maintenance window to clear SRAM",
            "If error persists after restart → hardware RMA required",
            "Check if other devices of same model/site show similar errors (systemic issue)",
        ],
        "cli_junos": [
            "show chassis hardware | match FPC",
            "show chassis alarms",
            "show system memory",
            "show pfe statistics traffic",
            "request pfe execute target fpc0 command \"show memory\"",
            "show system core-dumps",
            "request chassis fpc slot 0 restart",
            "request support information | save /var/tmp/techsupport.txt",
        ],
        "cli_eos": [
            "show platform sand memory-usage",
            "show hardware tcam profile | no-more",
            "show logging last 100 | grep -i parity",
        ],
        "timeline": "P1 — Reboot FPC this week. If persists, RMA ASAP.",
    },
    "phases": [
        {
            "name": "Diagnose",
            "goal": "Confirm hard (recurring at same address) vs soft (one-time) error.",
            "actions": [
                {"cli": {"junos": "show chassis alarms",
                         "eos": "show hardware platform"},
                 "expected": "Critical alarm for affected FPC",
                 "note": ""},
                {"cli": {"junos": "show log messages | match parity | last 20",
                         "eos": "show logging | grep -i parity"},
                 "expected": "Same memory address recurring = hard error",
                 "note": "If different addresses each time = soft error, may self-correct"},
                {"cli": {"junos": "show pfe statistics traffic",
                         "eos": "show platform fap counters"},
                 "expected": "Elevated discard / drop counters",
                 "note": ""},
            ],
        },
        {
            "name": "Mitigate",
            "goal": "Move traffic off the affected FPC if possible.",
            "actions": [
                {"cli": {"junos": "show chassis fpc",
                         "eos": "show module"},
                 "expected": "Identify affected FPC and connected ports",
                 "note": "Coordinate with peer to drain ports before restart"},
            ],
        },
        {
            "name": "Remediate",
            "goal": "Restart the FPC or RMA the line card.",
            "actions": [
                {"cli": {"junos": "request chassis fpc slot <n> restart",
                         "eos": "reload module <n>"},
                 "expected": "FPC reboots and comes back online",
                 "note": "DISRUPTIVE — affects all ports on this FPC"},
                {"cli": {"junos": "request support information | save /var/tmp/sysreport.txt",
                         "eos": "show tech-support | save flash:tech.log"},
                 "expected": "Collect evidence for vendor RMA",
                 "note": ""},
            ],
        },
        {
            "name": "Verify",
            "goal": "Post-restart: error gone, traffic resumed.",
            "actions": [
                {"cli": {"junos": "show chassis alarms",
                         "eos": "show hardware platform"},
                 "expected": "No active alarms on this FPC",
                 "note": ""},
                {"cli": {"junos": "show log messages | match parity | last 5",
                         "eos": "show logging | grep -i parity | tail"},
                 "expected": "No new parity errors in last 1h",
                 "note": ""},
            ],
        },
        {
            "name": "Optimize",
            "goal": "Track recurrence rate, automate FPC restart on hard errors.",
            "actions": [
                {"cli": {"junos": "set system syslog file parity-errors any any match parity"},
                 "expected": "Dedicated parity log file for easier tracking",
                 "note": ""},
            ],
        },
    ],
    "preventive_config": [
        "# Dedicated parity-error log",
        "  set system syslog file parity-errors any any",
        "  set system syslog file parity-errors match parity",
        "# Automated FPC restart event policy (Junos)",
        "  set event-options policy auto-fpc-restart events PARITY_ERROR",
        "  set event-options policy auto-fpc-restart then execute-commands ...",
    ],
    "monitoring": [
        "Alert on any parity event (zero tolerance)",
        "Track parity events per FPC — RMA threshold = 3 events in 30 days",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# License expiration
# ─────────────────────────────────────────────────────────────────────────────
_LICENSE = {
    "match": r"license",
    "root_cause": "Feature license expiration / invalid — affects BGP, EVPN, VXLAN, VC, etc.",
    "risk": "Feature degradation — sessions may drop, fabric disruption, compliance audit finding.",
    "timeline": "P1 if expired today; P2 if expiring within 30 days.",
    "rca": {
        "root_cause": "Juniper feature license expiration. When licenses expire, features like BGP, EVPN, VXLAN, Virtual Chassis, and advanced routing may stop working or operate in degraded mode.",
        "risk": "Feature degradation or complete loss. BGP license expiry → sessions may drop. VXLAN license expiry → EVPN fabric disruption. VC license → virtual chassis split.",
        "resolution_steps": [
            "Identify which licenses have expired and which features are affected",
            "Check if expired licenses are actively used by running features",
            "Contact Juniper licensing team for renewal",
            "Apply new license keys via CLI",
            "Verify features are operational after license renewal",
            "Audit all devices for upcoming license expirations",
        ],
        "cli_junos": [
            "show system license",
            "show system license usage",
            "show system license keys",
            "request system license add <license-key>",
            "show bgp summary",
            "show evpn database | count",
            "show virtual-chassis status",
        ],
        "cli_eos": [
            "show license",
            "show license status",
        ],
        "timeline": "P1 — Renew licenses TODAY before feature degradation.",
    },
    "phases": [
        {
            "name": "Diagnose",
            "goal": "Inventory licenses and expiration dates.",
            "actions": [
                {"cli": {"junos": "show system license",
                         "eos": "show license"},
                 "expected": "List of features and expiry dates",
                 "note": ""},
                {"cli": {"junos": "show system license usage",
                         "eos": "show license info"},
                 "expected": "Which features are actively in use",
                 "note": "Only worry about features actually used"},
            ],
        },
        {"name": "Mitigate", "goal": "No mitigation — feature loss is hard.",
         "actions": [{"cli": {}, "expected": "Engage vendor for emergency license",
                      "note": "If session-affecting, request grace license"}]},
        {
            "name": "Remediate",
            "goal": "Install renewed license.",
            "actions": [
                {"cli": {"junos": "request system license add <key-file>",
                         "eos": "license add <key>"},
                 "expected": "License installed, expiry refreshed",
                 "note": ""},
            ],
        },
        {
            "name": "Verify",
            "goal": "Confirm new license active.",
            "actions": [
                {"cli": {"junos": "show system license",
                         "eos": "show license"},
                 "expected": "New expiry date present",
                 "note": ""},
            ],
        },
        {
            "name": "Optimize",
            "goal": "Auto-track expirations.",
            "actions": [
                {"cli": {"junos": "set system syslog file license-events match LICENSE"},
                 "expected": "License events captured in dedicated log",
                 "note": ""},
            ],
        },
    ],
    "preventive_config": [
        "# Track license expirations centrally — script that runs weekly:",
        "#   show system license | grep 'days from now' → alert if < 30",
    ],
    "monitoring": [
        "Daily check: licenses expiring within 30 days",
        "Critical alert: licenses expiring within 7 days",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# SSH authentication failure
# ─────────────────────────────────────────────────────────────────────────────
_AUTH_FAIL = {
    "match": r"auth.*fail|login.*fail|auth.*invalid|pam_unix.*fail",
    "root_cause": "Management auth failure — brute force, misconfigured client, or credential rotation.",
    "risk": "Unauthorized access attempt or service disruption from automated tools.",
    "timeline": "P1 if many failures from one IP; P3 for isolated events.",
    "rca": {
        "root_cause": "Security event — authentication failure, ACL deny, or IDS alert. Could indicate: (1) Brute force SSH attempt, (2) Misconfigured credentials, (3) Unauthorized access attempt, (4) ACL blocking legitimate traffic.",
        "risk": "If brute force: potential unauthorized access. If ACL deny: legitimate traffic may be blocked. If IDS: possible intrusion attempt.",
        "resolution_steps": [
            "Review failed login source IPs — are they known/authorized?",
            "Check if failures are from automation (scripts with old credentials)",
            "Verify SSH access-list configuration",
            "Check for patterns (same source = brute force, random = scan)",
            "Tighten firewall filters if unauthorized sources detected",
            "Enable rate-limiting on SSH if not already configured",
        ],
        "cli_junos": [
            "show log messages | match \"sshd|login|auth\" | last 50",
            "show system login",
            "show firewall filter <ssh-filter> detail",
            "show system connections | match :22",
        ],
        "cli_eos": [
            "show logging last 50 | grep -i auth",
            "show users",
            "show ip access-lists",
        ],
        "timeline": "P2 — Review auth logs today, tighten access if needed.",
    },
    "phases": [
        {
            "name": "Diagnose",
            "goal": "Identify source IP, count, and pattern.",
            "actions": [
                {"cli": {"frr": "journalctl -u sshd --since '1 hour ago' | grep -i fail",
                         "junos": "show log messages | match 'authentication failed' | last 50",
                         "eos": "show logging | grep -i 'authentication failure'"},
                 "expected": "Source IPs, usernames, count per source",
                 "note": ""},
                {"cli": {"frr": "ss -tn '( sport = :22 )' | head",
                         "junos": "show system connections | match :22",
                         "eos": "show users"},
                 "expected": "Current SSH sessions",
                 "note": ""},
            ],
        },
        {
            "name": "Mitigate",
            "goal": "Block attacking sources.",
            "actions": [
                {"cli": {"frr": "iptables -I INPUT -s <attacker-ip> -p tcp --dport 22 -j DROP",
                         "junos": "set firewall family inet filter MGMT-IN term BLOCK-<n> from source-address <attacker-ip>/32 then discard"},
                 "expected": "Subsequent attempts dropped",
                 "note": ""},
            ],
        },
        {
            "name": "Remediate",
            "goal": "Tighten management ACL permanently.",
            "actions": [
                {"cli": {"junos": "show configuration firewall family inet filter MGMT-IN"},
                 "expected": "Validate that mgmt ACL is restrictive",
                 "note": "Best practice: allow only management subnet to TCP/22"},
            ],
        },
        {
            "name": "Verify",
            "goal": "Confirm attack is blocked, real users still have access.",
            "actions": [
                {"cli": {"junos": "show log messages | match 'authentication failed' | last 10"},
                 "expected": "No new failures from blocked source",
                 "note": ""},
            ],
        },
        {
            "name": "Optimize",
            "goal": "Rate-limit and alert on auth-fail bursts.",
            "actions": [
                {"cli": {"junos": "set system services ssh rate-limit 4",
                         "eos": "management ssh ; rate-limit 4"},
                 "expected": "Max 4 connections/minute from any one source",
                 "note": ""},
            ],
        },
    ],
    "preventive_config": [
        "  set system services ssh rate-limit 4",
        "  set system services ssh root-login deny",
        "  set system services ssh max-sessions-per-connection 1",
        "  set system services ssh protocol-version v2",
    ],
    "monitoring": [
        "Alert on > 10 auth failures from single IP in 5 min",
        "Alert on auth failure from any non-management subnet IP",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# Kernel panic / OOM
# ─────────────────────────────────────────────────────────────────────────────
_KERNEL_PANIC = {
    "match": r"kernel.*panic|core.*dump|oom|out\s+of\s+memory",
    "root_cause": "OS-level failure — kernel panic, OOM kill, or core dump. Possible memory leak, hardware fault, or corrupted firmware.",
    "risk": "Device reboot, control-plane outage, possible data-plane impact during recovery.",
    "timeline": "P1 — collect evidence immediately, before next reboot loses it.",
    "rca": {
        "root_cause": "System-level error — kernel panic, memory exhaustion, or process crash. Often caused by software bug, memory leak, or resource exhaustion under load.",
        "risk": "Device instability, potential routing engine failover, process restart, or complete device crash.",
        "resolution_steps": [
            "Check system memory and process status",
            "Look for core dumps that indicate crashed processes",
            "Check system uptime (very long uptime + memory issue = likely leak)",
            "Schedule maintenance reboot if memory is critically low",
            "Check for known Junos/EOS bugs matching the error pattern",
            "Upgrade to latest maintenance release if bug is identified",
        ],
        "cli_junos": [
            "show system memory",
            "show system processes extensive | match \"PID|mem|rpd|fpc\"",
            "show system core-dumps",
            "show system uptime",
            "show version",
            "request system core-dumps delete",
            "request system reboot at <time> message \"Memory maintenance\"",
        ],
        "cli_eos": [
            "show processes top once",
            "show version | grep memory",
            "show uptime",
        ],
        "timeline": "P1 — Check memory NOW. Schedule reboot if critical.",
    },
    "phases": [
        {
            "name": "Diagnose",
            "goal": "Collect crash evidence before it's overwritten.",
            "actions": [
                {"cli": {"frr": "dmesg | grep -iE 'panic|oom' | tail -50",
                         "junos": "show system core-dumps",
                         "eos": "show reload cause"},
                 "expected": "Core dump file path and reboot reason",
                 "note": ""},
                {"cli": {"frr": "free -h",
                         "junos": "show system processes extensive | match Mem",
                         "eos": "show processes top"},
                 "expected": "Current memory pressure",
                 "note": ""},
            ],
        },
        {
            "name": "Mitigate",
            "goal": "Stabilize and prevent immediate re-crash.",
            "actions": [
                {"cli": {"junos": "request system reboot",
                         "eos": "reload"},
                 "expected": "Controlled reboot to clean state",
                 "note": "Only if instability persists"},
            ],
        },
        {
            "name": "Remediate",
            "goal": "RMA / firmware upgrade / config fix.",
            "actions": [
                {"cli": {"junos": "request support information | save /var/tmp/sysreport-{date}.txt",
                         "eos": "show tech-support | save flash:tech-{date}.log"},
                 "expected": "Full diagnostic snapshot for vendor",
                 "note": ""},
            ],
        },
        {
            "name": "Verify",
            "goal": "Post-recovery stability check.",
            "actions": [
                {"cli": {"junos": "show system uptime",
                         "eos": "show version | grep uptime"},
                 "expected": "Stable for > 1 hour",
                 "note": ""},
            ],
        },
        {
            "name": "Optimize",
            "goal": "Auto-collect crash artifacts to off-box storage.",
            "actions": [
                {"cli": {"junos": "set system archival configuration transfer-on-commit",
                         "junos2": "set system archival configuration archive-sites scp://backup-server/"},
                 "expected": "Config auto-saved to remote backup on commit",
                 "note": "Critical for post-crash forensics"},
            ],
        },
    ],
    "preventive_config": [
        "# Auto-collect cores to remote SCP",
        "  set system core-dumps directory /var/crash",
        "  set system archival configuration transfer-on-commit",
        "# Aggressive process restart",
        "  set system processes routing failover other-routing-engine",
    ],
    "monitoring": [
        "Alert on any kernel-panic / OOM event",
        "Track memory utilization — alert if > 85% sustained 5 min",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# VPN / IPsec tunnel failure  (DCN _AI_KB "vpn" category port)
# ─────────────────────────────────────────────────────────────────────────────
_VPN_DOWN = {
    "match": r"ike|ipsec|vpn|tunnel",
    "root_cause": (
        "VPN/IPsec tunnel failure. Possible causes: (1) IKE Phase 1 mismatch (pre-shared key, "
        "encryption algorithm, lifetime), (2) IKE Phase 2 mismatch (transform set, PFS group), "
        "(3) NAT interference, (4) Firewall blocking UDP 500/4500, (5) Certificate expiry, "
        "(6) Peer device down."
    ),
    "risk": "Site-to-site connectivity loss. Remote site may be completely isolated if VPN is the only path.",
    "timeline": "P1 — Verify VPN peer reachability and IKE config NOW.",
    "rca": {
        "root_cause": "VPN/IPsec tunnel failure. Possible causes: (1) IKE Phase 1 mismatch (pre-shared key, encryption algorithm, lifetime), (2) IKE Phase 2 mismatch (transform set, PFS group), (3) NAT interference, (4) Firewall blocking UDP 500/4500, (5) Certificate expiry, (6) Peer device down.",
        "risk": "Site-to-site connectivity loss. Remote site may be completely isolated if VPN is the only path.",
        "resolution_steps": [
            "Check IKE SA (Phase 1) status — is it established?",
            "Check IPsec SA (Phase 2) status — are there active SAs?",
            "Verify pre-shared key matches on both sides",
            "Check IKE proposals match (encryption, hash, DH group, lifetime)",
            "Verify no NAT between peers (or NAT-T is enabled)",
            "Check firewall rules allow UDP 500, 4500, and ESP (protocol 50)",
            "If certificate-based: check certificate expiry dates",
        ],
        "cli_junos": [
            "show security ike security-associations",
            "show security ipsec security-associations",
            "show security ike security-associations detail",
            "show security ipsec statistics",
            "show log kmd | last 20",
        ],
        "cli_eos": [
            "show ip security connection",
            "show ip security policy",
        ],
        "timeline": "P1 — Verify VPN peer reachability and IKE config NOW.",
    },
    "phases": [
        {
            "name": "Diagnose",
            "goal": "Check IKE/IPsec SA status and identify the phase that failed.",
            "actions": [
                {"cli": {"junos": "show security ike security-associations",
                         "eos": "show ip security connection"},
                 "expected": "IKE Phase 1 SA established; State = UP",
                 "note": "Missing IKE SA = Phase 1 failure (pre-shared key, proposal mismatch)"},
                {"cli": {"junos": "show security ipsec security-associations",
                         "eos": "show ip security policy"},
                 "expected": "IPsec Phase 2 SAs active, bytes-in/out incrementing",
                 "note": "IKE up but no IPsec SA = Phase 2 failure (transform set, PFS mismatch)"},
                {"cli": {"junos": "show security ike security-associations detail",
                         "eos": "show ip security connection detail"},
                 "expected": "Detailed peer info including proposals and lifetime",
                 "note": "Compare both sides — mismatch is the most common cause"},
                {"cli": {"junos": "ping <peer-gateway-ip> rapid count 5",
                         "eos": "ping <peer-gateway-ip>"},
                 "expected": "0% loss — L3 path to peer is reachable",
                 "note": "If 100% loss, routing/physical problem must be resolved first"},
            ],
        },
        {
            "name": "Mitigate",
            "goal": "Bounce the tunnel to force re-negotiation.",
            "actions": [
                {"cli": {"junos": "clear security ike security-associations",
                         "eos": "clear ip security association"},
                 "expected": "IKE SAs cleared — device will re-initiate",
                 "note": "Clears all SAs; use specific peer if in a hub config"},
                {"cli": {"junos": "clear security ipsec security-associations"},
                 "expected": "IPsec SAs cleared",
                 "note": "Forces Phase 2 renegotiation"},
            ],
        },
        {
            "name": "Remediate",
            "goal": "Fix proposal mismatch, expired certificates, or firewall blocks.",
            "actions": [
                {"cli": {"junos": "show configuration security ike",
                         "eos": "show running-config | section crypto"},
                 "expected": "Proposals, pre-shared key, gateway config",
                 "note": "Must match peer-side exactly — encryption, hash, DH group, lifetime"},
                {"cli": {"junos": "show log kmd | last 50"},
                 "expected": "KMD log shows specific mismatch reason",
                 "note": "Key messages: 'No proposal chosen', 'Invalid cookie'"},
            ],
        },
        {
            "name": "Verify",
            "goal": "Tunnel up, traffic flowing.",
            "actions": [
                {"cli": {"junos": "show security ipsec security-associations",
                         "eos": "show ip security connection"},
                 "expected": "Active SAs with incrementing bytes-in/out",
                 "note": ""},
                {"cli": {"junos": "ping <remote-site-host> routing-instance <vpn-ri>",
                         "eos": "ping <remote-site-host> source <local-int>"},
                 "expected": "Traffic passes through the tunnel",
                 "note": ""},
            ],
        },
        {
            "name": "Optimize",
            "goal": "Reduce re-key downtime and improve resilience.",
            "actions": [
                {"cli": {"junos": "set security ike policy <policy> proposal-set standard"},
                 "expected": "Standardized proposal set — fewer mismatch scenarios",
                 "note": "Agree on a single proposal set across all peers"},
                {"cli": {"junos": "set security ipsec vpn <vpn> establish-tunnels immediately"},
                 "expected": "Tunnel pre-established rather than on-demand",
                 "note": "Eliminates first-packet delay for new flows"},
            ],
        },
    ],
    "preventive_config": [
        "# Junos — pre-established tunnel with standard proposals",
        "  set security ipsec vpn <vpn> establish-tunnels immediately",
        "  set security ike policy <p> proposal-set standard",
        "  set security ike policy <p> pre-shared-key ascii-text <key>",
    ],
    "monitoring": [
        "Alert if IPsec SA byte-counters don't increment for > 5 min on active tunnel",
        "Alert on IKE negotiation failures",
        "Track certificate expiry for cert-based peers — alert 30 days before",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# Gateway redundancy — VRRP/HSRP failover  (DCN _AI_KB "redundancy" port)
# ─────────────────────────────────────────────────────────────────────────────
_REDUNDANCY = {
    "match": r"vrrp|hsrp|failover|master.*change",
    "root_cause": (
        "Gateway redundancy failover event (VRRP/HSRP). The master/primary gateway changed, "
        "causing a brief traffic disruption. Common triggers: interface failure, device reboot, "
        "priority change, or preemption."
    ),
    "risk": "Brief traffic disruption during failover (1–3 seconds typically). If failover is flapping, sustained disruption possible.",
    "timeline": "P2 — Verify failover reason. Ensure original master recovers.",
    "rca": {
        "root_cause": "Gateway redundancy failover event (VRRP/HSRP). The master/primary gateway changed, causing a brief traffic disruption. Common triggers: interface failure, device reboot, priority change, or preemption.",
        "risk": "Brief traffic disruption during failover (1-3 seconds typically). If failover is flapping, sustained disruption possible.",
        "resolution_steps": [
            "Identify which VRRP/HSRP group changed and which device is now master",
            "Check if the original master is still alive",
            "Verify VRRP priority and preemption settings",
            "Check tracked interfaces/objects that may have triggered failover",
            "Verify both devices agree on virtual IP and group configuration",
        ],
        "cli_junos": [
            "show vrrp summary",
            "show vrrp detail",
            "show vrrp track-summary",
        ],
        "cli_eos": [
            "show vrrp",
            "show vrrp detail",
        ],
        "timeline": "P2 — Verify failover reason. Ensure original master recovers.",
    },
    "phases": [
        {
            "name": "Diagnose",
            "goal": "Determine which VRRP/HSRP group failed over and why.",
            "actions": [
                {"cli": {"junos": "show vrrp summary",
                         "eos": "show vrrp"},
                 "expected": "Current master for each group; priority values",
                 "note": "Check if failover matches expected priority ordering"},
                {"cli": {"junos": "show vrrp detail",
                         "eos": "show vrrp detail"},
                 "expected": "Tracked object status, preemption settings, advertisement interval",
                 "note": "Tracked interface down = expected failover; unexpected = config issue"},
                {"cli": {"junos": "show vrrp track-summary"},
                 "expected": "All tracked objects UP",
                 "note": "Tracked object DOWN lowers priority below backup → triggers failover"},
                {"cli": {"junos": "show log messages | match vrrp | last 20",
                         "eos": "show logging | grep -i vrrp"},
                 "expected": "State change log with timestamp and old/new master",
                 "note": ""},
            ],
        },
        {
            "name": "Mitigate",
            "goal": "Ensure one active master is forwarding traffic.",
            "actions": [
                {"cli": {"junos": "show vrrp summary",
                         "eos": "show vrrp"},
                 "expected": "Exactly one master per group",
                 "note": "Two masters = split-brain; investigate immediately"},
            ],
        },
        {
            "name": "Remediate",
            "goal": "Restore original master if desired, fix tracked object issue.",
            "actions": [
                {"cli": {"junos": "show configuration interfaces <int> family inet address vrrp-group",
                         "eos": "show running-config | section vrrp"},
                 "expected": "Priority and preemption settings correct on both devices",
                 "note": "Priority should be higher on preferred master"},
                {"cli": {"junos": "show interfaces <tracked-int> terse",
                         "eos": "show interfaces <tracked-int> status"},
                 "expected": "Tracked interface UP",
                 "note": "If tracked interface is down, fix it to restore original master (if preemption is on)"},
            ],
        },
        {
            "name": "Verify",
            "goal": "Correct master active, no split-brain, traffic flowing.",
            "actions": [
                {"cli": {"junos": "show vrrp summary",
                         "eos": "show vrrp"},
                 "expected": "Master is the intended device, all groups healthy",
                 "note": ""},
                {"cli": {"junos": "ping <virtual-ip> rapid count 5",
                         "eos": "ping <virtual-ip>"},
                 "expected": "Virtual IP responds",
                 "note": ""},
            ],
        },
        {
            "name": "Optimize",
            "goal": "Minimize failover time and prevent spurious failovers.",
            "actions": [
                {"cli": {"junos": "set interfaces <int> family inet address <vip>/24 vrrp-group <n> fast-interval 200"},
                 "expected": "200ms advertisement interval instead of 1s",
                 "note": "Reduces failover detection from 3s to <1s"},
                {"cli": {"junos": "set interfaces <int> family inet address <vip>/24 vrrp-group <n> track interface <uplink> priority-cost 50"},
                 "expected": "Priority drops by 50 when uplink goes down → automatic failover",
                 "note": ""},
            ],
        },
    ],
    "preventive_config": [
        "# Junos VRRP with fast timers + uplink tracking",
        "  set interfaces <int> family inet address <vip>/24 vrrp-group <n> priority 110",
        "  set interfaces <int> family inet address <vip>/24 vrrp-group <n> fast-interval 200",
        "  set interfaces <int> family inet address <vip>/24 vrrp-group <n> preempt hold-time 5",
        "  set interfaces <int> family inet address <vip>/24 vrrp-group <n> track interface <uplink> priority-cost 50",
    ],
    "monitoring": [
        "Alert on any VRRP state change",
        "Alert if VRRP group has no master for > 5s",
        "Track VRRP failover frequency — alert if > 2/hour",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# FPC / line card error  (DCN _AI_KB "hardware.fpc" sub-entry port)
# ─────────────────────────────────────────────────────────────────────────────
_FPC_ERR = {
    "match": r"fpc.*(?:offline|crash|error|halt|restart)|line.?card",
    "root_cause": (
        "FPC (Flexible PIC Concentrator) or line card experiencing errors. This could be caused by "
        "hardware failure, memory exhaustion, software bug, or environmental factors (temperature, power)."
    ),
    "risk": "Forwarding plane disruption — traffic through affected FPC will be dropped. If device has redundant FPCs, traffic may reroute; if single FPC, full outage.",
    "timeline": "P1 — Investigate immediately. RMA if hardware failure confirmed.",
    "rca": {
        "root_cause": "FPC (Flexible PIC Concentrator) or line card experiencing errors. This could be caused by hardware failure, memory exhaustion, software bug, or environmental factors (temperature, power).",
        "risk": "Forwarding plane disruption — traffic through affected FPC will be dropped. If device has redundant FPCs, traffic may reroute; if single FPC, full outage.",
        "resolution_steps": [
            "Check FPC status and identify which FPC is affected",
            "Review chassis alarms and environmental sensors",
            "Check if FPC errors correlate with specific traffic patterns",
            "Attempt FPC restart in maintenance window",
            "Collect tech-support for vendor (JTAC) analysis",
            "If hardware failure confirmed → initiate RMA",
        ],
        "cli_junos": [
            "show chassis fpc",
            "show chassis fpc detail",
            "show chassis alarms",
            "show chassis environment",
            "show system alarms",
            "show log messages | match fpc | last 50",
            "request chassis fpc slot <N> restart",
            "request support information | save /var/tmp/techsupport.txt",
        ],
        "cli_eos": [
            "show module",
            "show environment all",
            "show logging last 100 | grep -i fpc",
        ],
        "timeline": "P1 — Investigate immediately. RMA if hardware failure confirmed.",
    },
    "phases": [
        {
            "name": "Diagnose",
            "goal": "Identify which FPC/line-card is affected and the error type.",
            "actions": [
                {"cli": {"junos": "show chassis fpc",
                         "eos": "show module"},
                 "expected": "FPC state: Online / Offline / Error; memory usage",
                 "note": "Offline or Error state = forwarding plane disrupted on this FPC"},
                {"cli": {"junos": "show chassis fpc detail",
                         "eos": "show environment all"},
                 "expected": "Detailed status including temperature, CPU, memory per FPC",
                 "note": "High CPU or memory = possible software bug or traffic storm"},
                {"cli": {"junos": "show chassis alarms",
                         "eos": "show module detail"},
                 "expected": "Critical alarms for the affected FPC",
                 "note": ""},
                {"cli": {"junos": "show log messages | match fpc | last 50",
                         "eos": "show logging last 100 | grep -i fpc"},
                 "expected": "FPC error messages with timestamps",
                 "note": "Repeated offline/online cycles = hardware instability"},
            ],
        },
        {
            "name": "Mitigate",
            "goal": "Move traffic off the affected FPC to restore service.",
            "actions": [
                {"cli": {"junos": "show chassis fpc pic-status"},
                 "expected": "Identify all PICs on the affected FPC and connected ports",
                 "note": "Coordinate with peer to drain ports before restart"},
                {"cli": {"junos": "request chassis fpc slot <N> offline",
                         "eos": "shutdown module <N>"},
                 "expected": "FPC gracefully offlined — traffic migrates via redundant paths",
                 "note": "Only if redundant FPCs or ECMP paths exist"},
            ],
        },
        {
            "name": "Remediate",
            "goal": "Restart FPC or initiate RMA.",
            "actions": [
                {"cli": {"junos": "request chassis fpc slot <N> restart",
                         "eos": "reload module <N>"},
                 "expected": "FPC reboots and comes back online",
                 "note": "DISRUPTIVE — affects all ports on this FPC"},
                {"cli": {"junos": "request support information | save /var/tmp/techsupport.txt",
                         "eos": "show tech-support | save flash:tech.log"},
                 "expected": "Evidence bundle for vendor RMA / JTAC case",
                 "note": "Collect before restart if possible"},
            ],
        },
        {
            "name": "Verify",
            "goal": "FPC back online, traffic forwarding correctly.",
            "actions": [
                {"cli": {"junos": "show chassis fpc",
                         "eos": "show module"},
                 "expected": "FPC state = Online, memory usage normal",
                 "note": ""},
                {"cli": {"junos": "show chassis alarms",
                         "eos": "show environment all"},
                 "expected": "No active alarms on this FPC",
                 "note": ""},
            ],
        },
        {
            "name": "Optimize",
            "goal": "Auto-restart on FPC failure, monitoring.",
            "actions": [
                {"cli": {"junos": "set chassis fpc <N> lite-mode"},
                 "expected": "Reduced feature set on FPC — lower memory pressure",
                 "note": "Only if FPC exhausting memory under normal load"},
                {"cli": {"junos": "set system syslog file fpc-errors any any match fpc"},
                 "expected": "Dedicated FPC error log for easier tracking",
                 "note": ""},
            ],
        },
    ],
    "preventive_config": [
        "# Dedicated FPC error log (Junos)",
        "  set system syslog file fpc-errors any any",
        "  set system syslog file fpc-errors match fpc",
        "# Event policy — auto-collect tech-support on FPC offline",
        "  set event-options policy fpc-offline-collect events CHASSISD_FPC_OFFLINE",
        "  set event-options policy fpc-offline-collect then execute-commands ...",
    ],
    "monitoring": [
        "Alert on any FPC offline/error event",
        "Track FPC restarts per week — RMA threshold if > 2",
        "Alert on FPC memory usage > 80%",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# Chassis environmental alarm  (DCN _AI_KB "hardware.chassis" sub-entry port)
# ─────────────────────────────────────────────────────────────────────────────
_CHASSIS_ENV = {
    "match": r"chassis.*alarm|power.*fail|fan.*fail|psu|temperature",
    "root_cause": (
        "Chassis environmental alarm — power supply failure, fan failure, or temperature threshold exceeded. "
        "These are hardware-level alerts that require physical intervention."
    ),
    "risk": "Reduced redundancy (single PSU/fan), potential thermal shutdown if temperature critical, device instability under load.",
    "timeline": "P1 — Check within hours. Replace failed component ASAP.",
    "rca": {
        "root_cause": "Chassis environmental alarm — power supply failure, fan failure, or temperature threshold exceeded. These are hardware-level alerts that require physical intervention.",
        "risk": "Reduced redundancy (single PSU/fan), potential thermal shutdown if temperature critical, device instability under load.",
        "resolution_steps": [
            "Identify which component triggered the alarm (PSU, fan, temp sensor)",
            "Check environmental status for current readings",
            "If PSU: verify power feed, check for loose connections",
            "If Fan: check for obstruction, verify airflow path",
            "If Temperature: check ambient temp, verify cooling, reduce load",
            "Replace failed component — engage DC hands for physical access",
        ],
        "cli_junos": [
            "show chassis alarms",
            "show chassis environment",
            "show chassis power",
            "show chassis fan",
            "show chassis temperature-thresholds",
        ],
        "cli_eos": [
            "show environment all",
            "show environment power",
            "show environment cooling",
            "show environment temperature",
        ],
        "timeline": "P1 — Check within hours. Replace failed component ASAP.",
    },
    "phases": [
        {
            "name": "Diagnose",
            "goal": "Identify the failing component (PSU, fan, or thermal sensor).",
            "actions": [
                {"cli": {"junos": "show chassis alarms",
                         "eos": "show environment all"},
                 "expected": "Active alarms with component name (PEM 0, Fan 1, etc.)",
                 "note": ""},
                {"cli": {"junos": "show chassis environment",
                         "eos": "show environment power"},
                 "expected": "Temperature readings, PSU status (OK/Absent/Failed), fan speeds",
                 "note": "Temperature > threshold = cooling failure; check ambient DC temp"},
                {"cli": {"junos": "show chassis power",
                         "eos": "show environment cooling"},
                 "expected": "PSU input/output voltage, capacity",
                 "note": "Both PSUs should be present and drawing power"},
                {"cli": {"junos": "show chassis fan",
                         "eos": "show environment temperature"},
                 "expected": "All fans Running at normal RPM",
                 "note": "Fan speed > 80% = thermal pressure; check airflow obstructions"},
            ],
        },
        {
            "name": "Mitigate",
            "goal": "Reduce thermal load and prevent shutdown.",
            "actions": [
                {"cli": {"junos": "show chassis temperature-thresholds"},
                 "expected": "Current temp vs thresholds — how close to shutdown?",
                 "note": "If approaching threshold: reduce traffic load, improve airflow"},
                {"cli": {"junos": "request chassis fpc slot <N> offline"},
                 "expected": "Reduces power draw on affected FPC — lowers thermal load",
                 "note": "Last resort — only if thermal shutdown is imminent"},
            ],
        },
        {
            "name": "Remediate",
            "goal": "Replace failed hardware component (hands-on required).",
            "actions": [
                {"cli": {"junos": "show chassis hardware detail | match PEM",
                         "eos": "show environment power detail"},
                 "expected": "Part number and serial for replacement order",
                 "note": "PSU hot-swappable on most platforms; fan tray usually too"},
                {"cli": {"junos": "request support information | save /var/tmp/chassis-env.txt"},
                 "expected": "Environmental snapshot for JTAC if under support contract",
                 "note": ""},
            ],
        },
        {
            "name": "Verify",
            "goal": "All alarms cleared, temperatures normal.",
            "actions": [
                {"cli": {"junos": "show chassis alarms",
                         "eos": "show environment all"},
                 "expected": "No active environmental alarms",
                 "note": ""},
                {"cli": {"junos": "show chassis environment",
                         "eos": "show environment temperature"},
                 "expected": "All temperatures below OK threshold",
                 "note": ""},
            ],
        },
        {
            "name": "Optimize",
            "goal": "Proactive thermal and power monitoring.",
            "actions": [
                {"cli": {"junos": "set chassis temperature-thresholds yellow-alarm <temp>"},
                 "expected": "Early warning before red (shutdown) alarm",
                 "note": "Set yellow ~10°C below red threshold"},
                {"cli": {"junos": "set system syslog file chassis-env any any match chassis"},
                 "expected": "Dedicated chassis event log",
                 "note": ""},
            ],
        },
    ],
    "preventive_config": [
        "# Yellow thermal alarm (early warning)",
        "  set chassis temperature-thresholds yellow-alarm 55",
        "# Chassis event log",
        "  set system syslog file chassis-env any any",
        "  set system syslog file chassis-env match chassis",
    ],
    "monitoring": [
        "Alert on any PSU failure or absence (zero tolerance)",
        "Alert when temperature > yellow threshold",
        "Track fan RPM — alert if any fan stops",
        "Alert if fewer PSUs present than expected",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# NTP sync lost
# ─────────────────────────────────────────────────────────────────────────────
_NTP_LOST = {
    "match": r"ntp.*(?:unreachable|stratum|sync\s+lost|no.*server)",
    "root_cause": "NTP peer unreachable or unsynchronized — UDP/123 blocked, server down, or stratum-16 (no sync).",
    "risk": "Inaccurate logs, certificate validation failures, RADIUS/TACACS failures, false log correlation.",
    "timeline": "P3 — investigate this week.",
    "phases": [
        {
            "name": "Diagnose",
            "goal": "Check sync state and reachability.",
            "actions": [
                {"cli": {"frr": "chronyc sources",
                         "junos": "show ntp associations",
                         "eos": "show ntp associations"},
                 "expected": "At least one source with stratum < 16, reach != 0",
                 "note": ""},
                {"cli": {"frr": "chronyc tracking",
                         "junos": "show ntp status",
                         "eos": "show ntp status"},
                 "expected": "Reference ID set, offset < 100ms",
                 "note": ""},
            ],
        },
        {"name": "Mitigate", "goal": "Use a known-good public NTP as fallback.",
         "actions": [{"cli": {"frr": "chronyc add server pool.ntp.org",
                              "junos": "set system ntp server pool.ntp.org",
                              "eos": "ntp server pool.ntp.org"},
                      "expected": "Public NTP reachable", "note": "Internal NTP preferred if available"}]},
        {"name": "Remediate", "goal": "Restore internal NTP path / firewall.",
         "actions": [{"cli": {"frr": "nc -uvz <ntp-server> 123",
                              "junos": "ping <ntp-server>",
                              "eos": "ping <ntp-server>"},
                      "expected": "UDP/123 reachable", "note": ""}]},
        {"name": "Verify", "goal": "Sync restored, stratum < 16.",
         "actions": [{"cli": {"frr": "chronyc tracking",
                              "junos": "show ntp status",
                              "eos": "show ntp status"},
                      "expected": "Stratum < 16, low offset", "note": ""}]},
        {"name": "Optimize", "goal": "Multiple NTP sources for redundancy.",
         "actions": [{"cli": {"junos": "set system ntp server <primary>",
                              "junos2": "set system ntp server <secondary>",
                              "junos3": "set system ntp server <tertiary>"},
                      "expected": "Three sources configured", "note": ""}]},
    ],
    "preventive_config": [
        "  set system ntp server <primary-ntp> prefer",
        "  set system ntp server <secondary-ntp>",
        "  set system ntp server <tertiary-ntp>",
        "  set system ntp authentication-key 1 type sha256 value ...",
    ],
    "monitoring": [
        "Alert if NTP stratum == 16 for > 10 min",
        "Alert if NTP offset > 100ms",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# Final registry
# ─────────────────────────────────────────────────────────────────────────────
KB: dict[str, dict[str, dict[str, Any]]] = {
    "routing": {
        "bgp_down": _BGP_DOWN,
        "ospf":     _OSPF_ADJ,
        "_default": _BGP_DOWN,
    },
    "interface":  {"link_down":   _INT_DOWN,    "_default": _INT_DOWN},
    "lag":        {"_default":    _LAG_DOWN},
    "hardware": {
        "parity":  _ASIC_PARITY,
        "fpc":     _FPC_ERR,
        "chassis": _CHASSIS_ENV,
        "_default": _ASIC_PARITY,
    },
    "compliance": {"license":     _LICENSE,     "_default": _LICENSE},
    "security":   {"auth_fail":   _AUTH_FAIL,   "_default": _AUTH_FAIL},
    "system":     {"_default":    _KERNEL_PANIC},
    "ntp":        {"_default":    _NTP_LOST},
    "vpn":        {"tunnel_down": _VPN_DOWN,    "_default": _VPN_DOWN},
    "redundancy": {"failover":    _REDUNDANCY,  "_default": _REDUNDANCY},
}


def lookup(category: str, description: str) -> dict[str, Any]:
    """Best-match KB entry for (category, description)."""
    cat_kb = KB.get(category, {})
    desc_lower = description.lower()

    for sub_key, sub_kb in cat_kb.items():
        if sub_key == "_default":
            continue
        match = sub_kb.get("match", "")
        if match and re.search(match, desc_lower):
            return sub_kb

    if "_default" in cat_kb:
        return cat_kb["_default"]

    return {
        "root_cause": f"Event detected: {description}",
        "risk": "Unknown — manual review needed.",
        "timeline": "P3 — investigate this week.",
        "phases": [
            {"name": "Diagnose", "goal": "Triage", "actions": [
                {"cli": {"junos": "show log messages | last 50",
                         "eos": "show logging last 50",
                         "frr": "journalctl --since '1 hour ago' | tail -50"},
                 "expected": "Recent log context", "note": ""},
            ]},
            {"name": "Mitigate", "goal": "Escalate if recurring", "actions": []},
            {"name": "Remediate", "goal": "Investigate per device state", "actions": []},
            {"name": "Verify", "goal": "Confirm no new occurrences", "actions": []},
            {"name": "Optimize", "goal": "Add specific monitoring once cause is known", "actions": []},
        ],
        "preventive_config": [],
        "monitoring": [],
    }


def phase_cli_for(phase: dict[str, Any], platform: str) -> list[str]:
    """Extract platform-specific CLI commands from a phase definition."""
    out: list[str] = []
    for action in phase.get("actions", []):
        cli = action.get("cli", {})
        if isinstance(cli, str):
            out.append(cli)
            continue
        if not isinstance(cli, dict):
            continue
        # Match exact platform, then fallbacks
        for key in (platform, "any", "junos", "frr", "eos"):
            if key in cli and isinstance(cli[key], str):
                out.append(cli[key])
                break
    return out
