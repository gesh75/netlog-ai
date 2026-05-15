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
        "BGP session torn down — most commonly TCP/179 unreachability, "
        "hold-timer expiration, peer reset, MD5 mismatch, or route-policy change."
    ),
    "risk": "Routes via this peer withdrawn → traffic blackhole or re-route through suboptimal path.",
    "timeline": "P1 — investigate within 15 min; service-impacting if uplink peer.",
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
    "hardware":   {"asic_parity": _ASIC_PARITY, "_default": _ASIC_PARITY},
    "compliance": {"license":     _LICENSE,     "_default": _LICENSE},
    "security":   {"auth_fail":   _AUTH_FAIL,   "_default": _AUTH_FAIL},
    "system":     {"_default":    _KERNEL_PANIC},
    "ntp":        {"_default":    _NTP_LOST},
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
