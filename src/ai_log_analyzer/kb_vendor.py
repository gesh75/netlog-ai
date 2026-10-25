"""Rule-based playbooks for security / SD-WAN vendors, BGP anomalies, and the
categories the classifier emits that had no playbook (IS-IS/LDP/BFD/EIGRP, STP, DHCP,
wireless, AAA, resource pressure, crashes, IPS/ACL/DDoS, MAC moves).

Merged into ``kb.KB`` at import time. Entries in ``PREPEND`` are matched
*before* the existing generic entries of the same category (``kb.lookup``
walks sub-entries in insertion order), so "BGP hold timer expired" gets the
hold-timer playbook instead of the generic BGP-down one. ``CATEGORIES`` adds
whole new categories (``sdwan``, ``firewall``).

CLI keys: ``fortios`` (FortiGate), ``panos`` (PAN-OS), ``sdwan`` (Cisco
Catalyst SD-WAN cEdge / IOS-XE; vEdge drops the ``sdwan`` keyword), plus
``junos`` / ``eos`` / ``frr`` where the DC side matters. Commands are
read-only unless the phase is Mitigate/Remediate/Optimize; verify syntax on
your release before use (FortiOS 7.x, PAN-OS 10.x/11.x, IOS-XE SD-WAN 17.x).
"""
from __future__ import annotations

from typing import Any


def _act(cli: dict[str, str], expected: str, note: str = "") -> dict[str, Any]:
    return {"cli": cli, "expected": expected, "note": note}


def _phases(diagnose: list, mitigate: list, remediate: list, verify: list, optimize: list,
            goals: tuple[str, str, str, str, str]) -> list[dict[str, Any]]:
    names = ("Diagnose", "Mitigate", "Remediate", "Verify", "Optimize")
    return [{"name": n, "goal": g, "actions": a}
            for n, g, a in zip(names, goals, (diagnose, mitigate, remediate, verify, optimize))]


def _entry(match: str, root_cause: str, risk: str, timeline: str, steps: list[str],
           cli_junos: list[str], cli_eos: list[str], phases: list[dict[str, Any]],
           preventive: list[str], monitoring: list[str]) -> dict[str, Any]:
    return {
        "match": match,
        "root_cause": root_cause,
        "risk": risk,
        "timeline": timeline,
        "rca": {"root_cause": root_cause, "risk": risk, "resolution_steps": steps,
                "cli_junos": cli_junos, "cli_eos": cli_eos, "timeline": timeline},
        "phases": phases,
        "preventive_config": preventive,
        "monitoring": monitoring,
    }


# ─────────────────────────────────────────────────────────────────────────────
# VPN — IKE Phase 1 / Phase 2 / DPD
# ─────────────────────────────────────────────────────────────────────────────
_IKE_P1 = _entry(
    r"phase 1",
    "IKE Phase 1 (IKE SA) could not be negotiated. Typical causes: (1) proposal mismatch "
    "(encryption/integrity/DH group/lifetime), (2) pre-shared key or certificate/ID mismatch, "
    "(3) UDP 500/4500 blocked or NAT-T not negotiated, (4) peer gateway unreachable over the "
    "underlay (ISP or SD-WAN member out of SLA), (5) IKE version mismatch (v1 vs v2).",
    "No IKE SA → no IPsec SA → tunnel down; routing over the tunnel (BGP/OSPF) times out and "
    "the remote site is isolated if this is its only path.",
    "P1 — confirm underlay reachability and compare both peers' Phase 1 proposals now.",
    [
        "Confirm the peer's public IP answers on UDP 500/4500 from this gateway",
        "Compare Phase 1 proposals, DH groups, lifetimes and IKE version on both peers",
        "Check PSK / certificate validity and local/remote IDs",
        "Check whether the egress interface (SD-WAN member / ISP) is out of SLA",
        "Read the IKE debug for the exact failure reason (no proposal chosen, auth failed, timeout)",
    ],
    ["show security ike security-associations", "show security ike security-associations detail",
     "show log kmd | last 50"],
    ["show ip security connection", "show ip security connection detail"],
    _phases(
        [_act({"fortios": "diagnose vpn ike gateway list name <tunnel>",
               "panos": "show vpn ike-sa gateway <ike-gateway>",
               "junos": "show security ike security-associations detail"},
              "IKE SA present for the peer", "No SA listed = Phase 1 never completed"),
         _act({"fortios": "diagnose vpn ike log-filter dst-addr4 <peer-ip>",
               "panos": "less mp-log ikemgr.log",
               "junos": "show log kmd | match <peer-ip>"},
              "Exact negotiation failure reason",
              "FortiOS: follow with 'diagnose debug application ike -1' and 'diagnose debug enable'; "
              "7.4+ uses 'diagnose vpn ike log filter rem-addr4'. Disable debug afterwards.")],
        [_act({"fortios": "execute ping <peer-ip>", "panos": "ping source <local-ip> host <peer-ip>",
               "junos": "ping <peer-ip> source <local-ip> count 5"},
              "Peer reachable over the underlay", "If unreachable, fix the transport (ISP/SD-WAN) first")],
        [_act({"fortios": "config vpn ipsec phase1-interface\n edit <tunnel>\n show",
               "panos": "show network ike gateway <ike-gateway>",
               "junos": "show configuration security ike"},
              "Proposals/IDs identical on both peers", "Align proposals on both sides in a change window")],
        [_act({"fortios": "get vpn ipsec tunnel summary", "panos": "show vpn flow",
               "junos": "show security ipsec security-associations"},
              "Tunnel up, SA counters incrementing")],
        [_act({"fortios": "config vpn ipsec phase1-interface\n edit <tunnel>\n set dpd on-idle\n"
                          " set dpd-retryinterval 10\n next\nend",
               "panos": "set network ike gateway <ike-gateway> protocol ikev2 dpd enable yes",
               "junos": "set security ike gateway <gw> dead-peer-detection probe-idle-tunnel"},
              "DPD detects a dead peer within seconds, not minutes")],
        ("Find which side rejects Phase 1 and why.", "Prove the underlay path is healthy.",
         "Align Phase 1 parameters on both peers.", "Tunnel and SAs established.",
         "Fast dead-peer detection and proposal hygiene."),
    ),
    ["# Keep one modern proposal set on both peers (e.g. AES-256-GCM / SHA-256 / DH group 20-21)",
     "# Enable DPD on both peers so a dead path is detected in seconds"],
    ["Alert: IKE Phase 1 failure for the same peer > 3 times in 5 min",
     "Track: tunnel state per peer; page when down > 60 s on a single-path site"],
)

_IKE_P2 = _entry(
    r"phase 2",
    "IKE Phase 1 is up but the IPsec (Phase 2 / CHILD SA) negotiation fails. Typical causes: "
    "(1) traffic-selector / proxy-ID mismatch, (2) transform set or PFS group mismatch, "
    "(3) lifetime mismatch, (4) peer rekey collision.",
    "Tunnel shows up at IKE level but carries no traffic for the mismatched selectors; routing "
    "protocols over the tunnel drop.",
    "P1 — compare Phase 2 selectors and PFS on both peers.",
    ["Compare local/remote traffic selectors (proxy-IDs) on both peers",
     "Compare Phase 2 proposals and PFS group",
     "Check rekey timers and lifetimes"],
    ["show security ipsec security-associations detail", "show log kmd | last 50"],
    ["show ip security policy"],
    _phases(
        [_act({"fortios": "diagnose vpn tunnel list name <tunnel>",
               "panos": "show vpn ipsec-sa tunnel <tunnel>",
               "junos": "show security ipsec security-associations detail"},
              "Phase 2 SA for each selector pair", "Missing SA for one selector = proxy-ID mismatch")],
        [_act({"fortios": "execute vpn ipsec tunnel up <phase2-name>",
               "panos": "test vpn ipsec-sa tunnel <tunnel>",
               "junos": "clear security ipsec security-associations index <index>"},
              "Fresh Phase 2 negotiation", "Clears only the affected SA — confirm the index first")],
        [_act({"fortios": "config vpn ipsec phase2-interface\n edit <phase2-name>\n show",
               "panos": "show network tunnel ipsec <tunnel>",
               "junos": "show configuration security ipsec"},
              "Selectors, transforms and PFS identical on both peers")],
        [_act({"fortios": "get vpn ipsec tunnel summary", "panos": "show vpn ipsec-sa tunnel <tunnel>",
               "junos": "show security ipsec statistics"},
              "Encrypt/decrypt counters increasing")],
        [_act({"fortios": "# use 0.0.0.0/0 selectors with route-based VPN where policy allows",
               "panos": "# prefer route-based tunnels with a single 0.0.0.0/0 proxy-ID pair",
               "junos": "# prefer route-based st0 tunnels over policy-based selectors"},
              "Fewer selector pairs to drift out of sync")],
        ("Identify the mismatched selector or transform.", "Renegotiate only the affected SA.",
         "Align Phase 2 parameters.", "Traffic flowing through the SA.", "Reduce selector sprawl."),
    ),
    ["# Route-based VPN with a single any/any selector pair avoids proxy-ID drift"],
    ["Alert: Phase 2 failure with Phase 1 up for > 2 min"],
)

_DPD = _entry(
    r"dpd|dead peer",
    "Dead Peer Detection declared the IPsec peer dead: DPD probes went unanswered. The peer is "
    "down, its public path is broken, or the probes are being dropped (NAT/ISP).",
    "Tunnel torn down; anything routed over it fails over or blackholes.",
    "P1 — check the underlay and the peer device.",
    ["Check reachability of the peer public IP", "Check the egress member's SLA",
     "Check the peer device health"],
    ["show security ike security-associations", "show log kmd | last 50"],
    ["show ip security connection"],
    _phases(
        [_act({"fortios": "diagnose vpn ike gateway list name <tunnel>",
               "panos": "show vpn ike-sa gateway <ike-gateway>",
               "junos": "show security ike security-associations"}, "DPD counters / SA state")],
        [_act({"fortios": "diagnose sys sdwan health-check", "panos": "show routing route",
               "junos": "show route <peer-ip>"}, "A healthy alternate path exists")],
        [_act({"fortios": "execute ping <peer-ip>", "panos": "ping host <peer-ip>",
               "junos": "ping <peer-ip> count 5"}, "Peer reachable once the underlay recovers")],
        [_act({"fortios": "get vpn ipsec tunnel summary", "panos": "show vpn flow",
               "junos": "show security ipsec security-associations"}, "Tunnel re-established")],
        [_act({"fortios": "# pair DPD with SD-WAN health-checks so traffic moves before the tunnel dies",
               "panos": "# enable tunnel monitoring with a monitor profile (fail-over action)",
               "junos": "set security ipsec vpn <vpn> vpn-monitor"}, "Faster, controlled failover")],
        ("Confirm the peer is really unreachable.", "Move traffic to a healthy path.",
         "Restore the underlay / peer.", "Tunnel back up.", "Monitor the tunnel actively."),
    ),
    [], ["Alert: DPD failure on a single-path site"],
)

# ─────────────────────────────────────────────────────────────────────────────
# SD-WAN — SLA / BFD / OMP / control connections
# ─────────────────────────────────────────────────────────────────────────────
_SDWAN_SLA = _entry(
    r"sla",
    "An SD-WAN member (transport) missed its health-check SLA: latency, jitter or packet loss "
    "crossed the target, or the probe server became unreachable. Usually ISP degradation, "
    "last-mile congestion, or the probe target itself failing.",
    "Traffic steered off the member; if every member fails SLA, applications degrade or IPsec "
    "overlays on that member drop (BGP over the tunnel follows).",
    "P2 — P1 if all members of a site are out of SLA.",
    ["Identify which member and which metric (latency/jitter/loss) failed",
     "Check whether the probe target is reachable from other sites (probe vs path problem)",
     "Check ISP status and interface errors on the member",
     "Confirm steering moved traffic to a healthy member"],
    ["show interfaces <wan-interface> extensive"], ["show interfaces <wan-interface> counters errors"],
    _phases(
        [_act({"fortios": "diagnose sys sdwan health-check",
               "sdwan": "show sdwan app-route stats"},
              "Per-member latency/jitter/loss vs SLA target",
              "FortiOS 6.4 and older: 'diagnose sys virtual-wan-link health-check'"),
         _act({"fortios": "diagnose sys sdwan member", "sdwan": "show sdwan bfd sessions"},
              "Member state and which members are alive")],
        [_act({"fortios": "diagnose sys sdwan service", "sdwan": "show sdwan policy app-route-policy-filter"},
              "Rules now prefer the healthy member")],
        [_act({"fortios": "execute ping-options source <member-ip>\nexecute ping <probe-server>",
               "sdwan": "ping <probe-server> source <wan-interface>"},
              "Loss/latency confirmed on the member path", "Open an ISP ticket with these results")],
        [_act({"fortios": "diagnose sys sdwan health-check", "sdwan": "show sdwan app-route stats"},
              "Member back inside SLA for several intervals")],
        [_act({"fortios": "config system sdwan\n config health-check\n  edit <health-check>\n"
                          "   set failtime 3\n   set recoverytime 5\n  next\n end\nend",
               "sdwan": "# vManage: tune the SLA class and app-route multiplier per transport"},
              "Steering reacts quickly but does not flap on a single lost probe")],
        ("Pinpoint the failing member and metric.", "Keep traffic on healthy transports.",
         "Fix or escalate the degraded transport.", "SLA restored and stable.",
         "Tune detection vs recovery timers."),
    ),
    ["# FortiOS: health-check failtime/recoverytime sized to avoid flapping",
     "# Use at least two independent probe servers per health-check"],
    ["Alert: member out of SLA > 2 min", "Alert: all members of a site out of SLA (P1)"],
)

_SDWAN_BFD = _entry(
    r"bfd",
    "An SD-WAN BFD session between two TLOCs (overlay tunnel) went down. Causes: transport "
    "loss/blackout on one color, NAT/firewall dropping IPsec (UDP 12346+), TLOC or color "
    "mismatch after a change, or the remote edge going down.",
    "Data-plane tunnel on that color pair lost; app-route steering shifts traffic; repeated "
    "flaps cause brownouts.",
    "P2 — P1 if the site has no remaining BFD sessions.",
    ["Check which local/remote color pairs are down", "Check transport reachability between TLOC IPs",
     "Look at flap-reason (timeout vs admin)", "Check NAT type and firewall pinholes for the overlay"],
    [], [],
    _phases(
        [_act({"sdwan": "show sdwan bfd sessions"}, "Sessions per color; DOWN pairs identified",
              "vEdge: 'show bfd sessions'"),
         _act({"sdwan": "show sdwan bfd history"}, "Flap timing and reasons")],
        [_act({"sdwan": "show sdwan app-route stats"}, "Traffic steered to surviving colors")],
        [_act({"sdwan": "show sdwan control local-properties"},
              "TLOC public/private IPs and NAT type as expected")],
        [_act({"sdwan": "show sdwan bfd sessions"}, "All expected sessions UP and stable")],
        [_act({"sdwan": "# vManage feature template: BFD hello-interval/multiplier per color"},
              "Detection tuned per transport (tighter on MPLS, looser on LTE)")],
        ("Find the failing color pairs.", "Confirm steering protects traffic.",
         "Fix transport/NAT/TLOC issue.", "Sessions stable.", "Tune BFD per transport."),
    ),
    ["# vEdge example: bfd color biz-internet hello-interval 1000 multiplier 7"],
    ["Alert: BFD session flaps > 3 in 10 min per TLOC pair"],
)

_SDWAN_OMP = _entry(
    r"omp",
    "The OMP peering to the vSmart controller left the up state. The edge stops learning/"
    "advertising overlay routes and TLOCs; existing data-plane sessions keep forwarding until "
    "the OMP graceful-restart timer expires.",
    "Route/TLOC changes stop propagating; after graceful restart expires, the site loses "
    "overlay routes.",
    "P1 — restore the control plane before the OMP graceful-restart timer expires.",
    ["Check control connections to vSmart (OMP rides on them)", "Check certificates / org name",
     "Check reachability to controllers on every transport"],
    [], [],
    _phases(
        [_act({"sdwan": "show sdwan omp peers"}, "vSmart peers and state"),
         _act({"sdwan": "show sdwan control connections"}, "DTLS/TLS control connections to vSmart up")],
        [_act({"sdwan": "show sdwan omp routes"}, "Routes retained under graceful restart")],
        [_act({"sdwan": "show sdwan control connections-history"}, "Reason the connection dropped")],
        [_act({"sdwan": "show sdwan omp peers"}, "Peer state up")],
        [_act({"sdwan": "# vManage: keep OMP graceful-restart enabled and controllers reachable on 2+ colors"},
              "Control-plane loss tolerated during transport events")],
        ("Find why OMP dropped.", "Confirm graceful restart is protecting forwarding.",
         "Restore the control connection.", "OMP up.", "Harden controller reachability."),
    ),
    [], ["Alert: OMP peer down to all vSmarts > 60 s"],
)

_SDWAN_CONTROL = _entry(
    r"control connection",
    "A DTLS/TLS control connection from the edge to a controller (vSmart/vBond/vManage) went "
    "down. Causes: transport loss on the color, certificate/serial whitelist issue, clock skew, "
    "NAT or firewall blocking control ports.",
    "Without control connections the edge cannot receive policy, keys or routes; OMP follows.",
    "P1 when no control connections remain.",
    ["Check control connection state and history", "Check certificates and clock (NTP)",
     "Check controller reachability per color"],
    [], [],
    _phases(
        [_act({"sdwan": "show sdwan control connections"}, "Connections per controller and color")],
        [_act({"sdwan": "show sdwan control connections-history"}, "Last error (e.g. DCONFAIL, CRTREJSER)")],
        [_act({"sdwan": "show clock"}, "Clock in sync (certificate validation needs it)")],
        [_act({"sdwan": "show sdwan control connections"}, "All expected controllers up")],
        [_act({"sdwan": "# allow control connections on every transport color and monitor cert expiry"},
              "No single color is a control-plane SPOF")],
        ("Find which controller/color dropped.", "Read the failure code.",
         "Fix cert/clock/reachability.", "Connections up.", "Remove control-plane SPOFs."),
    ),
    [], ["Alert: control connections to vSmart = 0 for > 60 s"],
)

# ─────────────────────────────────────────────────────────────────────────────
# Firewall platform — HA split-brain / failover, conserve mode, session table
# ─────────────────────────────────────────────────────────────────────────────
_HA_SPLIT = _entry(
    r"split-brain|heartbeat",
    "The firewall HA pair lost its heartbeat/HA1 control link and both members may consider "
    "themselves active (split-brain). Causes: heartbeat cabling/switch failure, HA interface "
    "down, or a member hung.",
    "Two active firewalls → duplicate IP/MAC on data interfaces, asymmetric sessions, ARP "
    "flapping and outages until one member is forced passive.",
    "P1 — isolate immediately.",
    ["Confirm both members' HA state", "Restore heartbeat / HA1 links (use two, on separate paths)",
     "Force the wrong member to passive/standby"],
    [], [],
    _phases(
        [_act({"fortios": "get system ha status", "panos": "show high-availability state"},
              "Exactly one primary/active member"),
         _act({"fortios": "diagnose sys ha status", "panos": "show high-availability all"},
              "Heartbeat / HA1 link state and last failure reason")],
        [_act({"fortios": "# from the member that must stand down: execute ha manage <index> <admin> then shut its data ports",
               "panos": "request high-availability state suspend"},
              "Only one member forwarding", "Run on the member that should NOT own traffic")],
        [_act({"fortios": "diagnose sys ha checksum cluster", "panos": "show high-availability path-monitoring"},
              "Configs in sync; heartbeat path fixed")],
        [_act({"fortios": "get system ha status", "panos": "show high-availability state"},
              "One active, one passive, heartbeat up")],
        [_act({"fortios": "config system ha\n set hbdev \"<port-a>\" 50 \"<port-b>\" 50\nend",
               "panos": "# configure HA1 backup link and heartbeat backup over management"},
              "Redundant heartbeat paths")],
        ("Confirm the dual-active state.", "Force one member out of service.",
         "Fix heartbeat and re-sync.", "Normal active/passive state.", "Redundant heartbeat links."),
    ),
    [], ["Alert: HA heartbeat lost on any link", "Alert: both members report active"],
)

_FW_FAILOVER = _entry(
    r"ha failover|state change",
    "The firewall HA pair failed over (member state changed). Triggers: monitored interface/"
    "path failure, device fault, manual failover or preemption.",
    "Brief disruption; sessions survive only if session sync is enabled and healthy.",
    "P2 — confirm the trigger and that the new primary is healthy.",
    ["Identify the failover trigger (link/path monitor, device, manual)",
     "Confirm session sync status", "Decide whether to fail back"],
    [], [],
    _phases(
        [_act({"fortios": "diagnose sys ha history read", "panos": "show high-availability state-synchronization"},
              "Failover reason and session sync state")],
        [_act({"fortios": "get system ha status", "panos": "show high-availability state"},
              "New primary is forwarding normally")],
        [_act({"fortios": "diagnose sys ha checksum cluster", "panos": "show high-availability link-monitoring"},
              "Trigger (link/path) cleared")],
        [_act({"fortios": "get system ha status", "panos": "show high-availability all"}, "Pair healthy")],
        [_act({"fortios": "# review HA override/preempt settings to avoid unplanned failback",
               "panos": "# review preemption hold time and link/path monitoring groups"},
              "Predictable failover/failback")],
        ("Find the trigger.", "Confirm the new primary.", "Clear the trigger.", "Pair healthy.",
         "Tune failover policy."),
    ),
    [], ["Alert: any HA state change"],
)

_CONSERVE = _entry(
    r"conserve",
    "FortiOS entered memory conserve mode: memory use crossed the red threshold, so the unit "
    "stops accepting new sessions that need proxy/UTM inspection (fail-open or fail-closed per "
    "config). Causes: session/UTM load, memory leak in a daemon, very large tables.",
    "New sessions may be dropped or bypass inspection; routing daemons can be starved.",
    "P1 — reduce load and find the consumer.",
    ["Check which processes and features consume memory", "Check session count and UTM load",
     "Plan a controlled restart of the leaking daemon or reboot in a window"],
    [], [],
    _phases(
        [_act({"fortios": "diagnose hardware sysinfo conserve"}, "Current state and thresholds"),
         _act({"fortios": "diagnose sys top 2 20"}, "Top memory consumers")],
        [_act({"fortios": "get system performance status"}, "Memory dropping below the green threshold")],
        [_act({"fortios": "diagnose sys session stat"}, "Session load understood")],
        [_act({"fortios": "diagnose hardware sysinfo conserve"}, "Conserve mode exited")],
        [_act({"fortios": "config system global\n set memory-use-threshold-red 88\n"
                          " set memory-use-threshold-extreme 95\nend"},
              "Thresholds set deliberately; size the platform for the load")],
        ("Find the memory consumer.", "Shed load.", "Fix the cause.", "Conserve mode cleared.",
         "Right-size thresholds/platform."),
    ),
    [], ["Alert: memory > 80 % for 10 min", "Alert: conserve mode entered"],
)

_SESSION_TABLE = _entry(
    r"session table",
    "The firewall session table is full or at its limit. Causes: traffic surge or DDoS, very "
    "long session timeouts, or a platform sized below the session count.",
    "New connections are dropped; existing sessions continue.",
    "P1 — identify the top talkers.",
    ["Check session counts and the setup rate", "Find top sources/destinations",
     "Shorten idle timeouts for chatty protocols"],
    [], [],
    _phases(
        [_act({"fortios": "diagnose sys session full-stat", "panos": "show session info"},
              "Session count vs limit, setup rate")],
        [_act({"fortios": "diagnose sys session filter src <top-talker>",
               "panos": "show counter global filter delta yes severity drop"},
              "Source of the surge identified")],
        [_act({"fortios": "# apply DoS policy / shorten session-ttl for the offending service",
               "panos": "# apply a zone protection / DoS protection profile"},
              "Session growth contained")],
        [_act({"fortios": "diagnose sys session full-stat", "panos": "show session info"},
              "Session count back under limit")],
        [_act({"fortios": "# alert on session count at 80 % of platform limit",
               "panos": "# alert on session table utilization at 80 %"},
              "Early warning before drops")],
        ("Measure session pressure.", "Find the source.", "Contain it.", "Back under limit.",
         "Early warning."),
    ),
    [], ["Alert: session table > 80 % of limit"],
)

# ─────────────────────────────────────────────────────────────────────────────
# BGP anomalies
# ─────────────────────────────────────────────────────────────────────────────
_BGP_MAXPFX = _entry(
    r"max-prefix",
    "A BGP peer advertised more prefixes than the configured maximum-prefix limit (or crossed "
    "its warning threshold). Typical causes: a route leak (peer re-advertising a full table), "
    "de-aggregation upstream, or a limit sized for yesterday's table.",
    "Exceeded → the session is torn down and all routes via the peer are withdrawn; repeated "
    "restarts flap the table. Warning → no impact yet.",
    "P1 if exceeded on a transit/core peer; P3 for a warning.",
    ["Compare received prefix count with the limit and the normal baseline",
     "Look at what the peer is sending (new origins/prefixes)",
     "Coordinate with the peer before raising the limit — never raise it blindly"],
    ["show bgp neighbor <peer-ip> | match \"prefix|Last error\"",
     "show route receive-protocol bgp <peer-ip> | count"],
    ["show ip bgp neighbors <peer-ip>", "show ip bgp summary"],
    _phases(
        [_act({"junos": "show bgp neighbor <peer-ip> | match \"prefix|Last error\"",
               "eos": "show ip bgp neighbors <peer-ip>",
               "frr": "vtysh -c 'show bgp neighbors <peer-ip>'",
               "fortios": "get router info bgp neighbors <peer-ip>"},
              "Received vs maximum prefixes; last error = Cease/1")],
        [_act({"junos": "show route receive-protocol bgp <peer-ip> | count",
               "eos": "show ip bgp neighbors <peer-ip> received-routes",
               "frr": "vtysh -c 'show bgp neighbors <peer-ip> received-routes'"},
              "Which prefixes caused the jump", "Needs soft-reconfiguration inbound or Adj-RIB-In")],
        [_act({"junos": "set protocols bgp group <group> neighbor <peer-ip> family inet unicast "
                        "prefix-limit maximum <n> teardown 80 idle-timeout 30",
               "eos": "neighbor <peer-ip> maximum-routes <n> warning-limit 80 percent",
               "frr": "neighbor <peer-ip> maximum-prefix <n> 80 restart 30",
               "fortios": "config router bgp\n config neighbor\n  edit <peer-ip>\n"
                          "   set maximum-prefix <n>\n   set maximum-prefix-threshold 80\n  next\n end\nend"},
              "Limit agreed with the peer; auto-restart after idle timeout")],
        [_act({"junos": "show bgp summary", "eos": "show ip bgp summary",
               "frr": "vtysh -c 'show bgp summary'", "fortios": "get router info bgp summary"},
              "Session Established; prefix count at baseline")],
        [_act({"junos": "# pair prefix-limit with IRR/RPKI-based import filters",
               "eos": "# pair maximum-routes with prefix-lists generated from IRR",
               "frr": "# pair maximum-prefix with prefix-lists generated from IRR"},
              "Leaks are filtered before they hit the limit")],
        ("Confirm what the peer sent.", "Identify the leaked/extra prefixes.",
         "Fix filters/limit with the peer.", "Session stable at baseline.", "Filter leaks at import."),
    ),
    ["# Junos: prefix-limit maximum <n> teardown 80 idle-timeout 30",
     "# EOS: neighbor <peer> maximum-routes <n> warning-limit 80 percent",
     "# FRR: neighbor <peer> maximum-prefix <n> 80 restart 30"],
    ["Alert: received prefixes > 80 % of limit", "Alert: Cease/1 (max-prefix) on any peer"],
)

_BGP_HOLD = _entry(
    r"hold timer",
    "The BGP hold timer expired: no KEEPALIVE/UPDATE arrived for the full hold time. This is a "
    "transport or control-plane symptom, not a deliberate reset — lossy underlay, IPsec/SD-WAN "
    "path failure, MTU black-hole after the session was up, or CPU/CoPP starvation.",
    "Session down and routes withdrawn until TCP and BGP re-establish; recurring expiry flaps "
    "the table.",
    "P1 — investigate the transport under the session now.",
    ["Check the path to the peer (loss, MTU with DF set)",
     "Check if an IPsec / SD-WAN overlay under the session failed first",
     "Check control-plane load / CoPP drops on both ends",
     "Consider BFD for faster, cleaner failure detection"],
    ["show bgp neighbor <peer-ip> | match \"Last State|Last Error|Holdtime\"", "show bfd session"],
    ["show ip bgp neighbors <peer-ip>", "show bfd peers"],
    _phases(
        [_act({"junos": "show bgp neighbor <peer-ip> | match \"Last State|Last Error|Holdtime\"",
               "eos": "show ip bgp neighbors <peer-ip>",
               "frr": "vtysh -c 'show bgp neighbors <peer-ip>'",
               "fortios": "get router info bgp neighbors <peer-ip>",
               "panos": "show routing protocol bgp peer peer-name <peer>"},
              "Last error = Hold Timer Expired; note flap count",
              "PAN-OS advanced routing engine: 'show advanced-routing bgp peer status'")],
        [_act({"junos": "ping <peer-ip> size 1472 do-not-fragment count 20",
               "eos": "ping <peer-ip> size 1472 df-bit repeat 20",
               "fortios": "execute ping-options df-bit yes\nexecute ping-options data-size 1472\nexecute ping <peer-ip>"},
              "No loss at full MTU", "Loss only at large sizes = MTU black-hole on the path")],
        [_act({"junos": "show security ipsec security-associations",
               "fortios": "get vpn ipsec tunnel summary",
               "panos": "show vpn flow",
               "sdwan": "show sdwan bfd sessions"},
              "Underlying tunnel/overlay healthy", "Fix the overlay first — BGP follows it")],
        [_act({"junos": "show bgp summary", "eos": "show ip bgp summary", "frr": "vtysh -c 'show bgp summary'",
               "fortios": "get router info bgp summary"}, "Established and stable")],
        [_act({"junos": "set protocols bgp group <group> bfd-liveness-detection minimum-interval 300",
               "eos": "neighbor <peer-ip> bfd", "frr": "neighbor <peer-ip> bfd",
               "fortios": "config router bgp\n config neighbor\n  edit <peer-ip>\n   set bfd enable\n  next\n end\nend"},
              "Sub-second, deterministic failure detection")],
        ("Confirm hold-timer expiry and its frequency.", "Test the path (loss/MTU).",
         "Fix the transport under the session.", "Session stable.", "Add BFD."),
    ),
    ["# Junos: bfd-liveness-detection minimum-interval 300 multiplier 3",
     "# EOS/FRR: neighbor <peer> bfd"],
    ["Alert: hold-timer expiry on the same peer > 2 in 30 min"],
)

_BGP_ADMIN = _entry(
    r"administrative shutdown",
    "The session was closed with a Cease NOTIFICATION for an administrative reason (RFC 4486: "
    "/2 Administrative Shutdown, /3 Peer De-configured, /4 Administrative Reset, /6 Other "
    "Configuration Change). RFC 8203/9003 lets the operator attach a shutdown communication "
    "(e.g. a change ticket).",
    "Planned impact if a change exists; if not, someone shut a production peer by mistake.",
    "P3 when it matches an approved change; P1 when no change record exists.",
    ["Read the shutdown communication / change reference in the NOTIFICATION",
     "Match it to an approved change (ServiceNow change window)",
     "If no change exists, find who shut the peer (commit history) and restore it"],
    ["show bgp neighbor <peer-ip> | match \"Last Error|State\"", "show system commit"],
    ["show ip bgp neighbors <peer-ip>", "show logging | include BGP"],
    _phases(
        [_act({"junos": "show bgp neighbor <peer-ip> | match \"Last Error|State\"",
               "eos": "show ip bgp neighbors <peer-ip>",
               "frr": "vtysh -c 'show bgp neighbors <peer-ip>'"},
              "Last error Cease/2-6 and the shutdown communication text")],
        [_act({"junos": "show system commit", "eos": "show logging | include CONFIG",
               "frr": "journalctl -u frr --since '1 hour ago'"},
              "Who changed what, and when")],
        [_act({"junos": "# re-activate the neighbor only if no change covers the shutdown",
               "eos": "# 'no neighbor <peer-ip> shutdown' only if no change covers it",
               "frr": "# 'no neighbor <peer-ip> shutdown' only if no change covers it"},
              "Unplanned shutdown reversed")],
        [_act({"junos": "show bgp summary", "eos": "show ip bgp summary", "frr": "vtysh -c 'show bgp summary'"},
              "Session state matches the change plan")],
        [_act({"frr": "neighbor <peer-ip> shutdown message \"<change-id> <reason>\"",
               "junos": "# use graceful-shutdown (RFC 8326) to drain before shutting a peer"},
              "Every planned shutdown carries its change ID (RFC 8203)")],
        ("Read the reason.", "Match it to a change.", "Reverse it if unplanned.",
         "State matches plan.", "Always send a shutdown communication."),
    ),
    ["# FRR: neighbor <peer> shutdown message \"CHG0012345 maintenance\" (RFC 8203)"],
    ["Alert: Cease/2 outside an approved change window"],
)

_BGP_NOTIF_ERR = _entry(
    r"protocol / open / update",
    "A BGP NOTIFICATION reported a protocol error (RFC 4271 code 1 header, 2 OPEN — e.g. Bad "
    "Peer AS, unsupported capability, auth — 3 UPDATE — malformed attribute — or 5 FSM). This "
    "is a configuration mismatch or a malformed update, not a transport problem.",
    "Session cannot establish (OPEN errors) or resets on every bad UPDATE.",
    "P1 for production peers.",
    ["Decode code/subcode", "OPEN errors: compare peer-as, local-as, router-id, capabilities, auth",
     "UPDATE errors: capture the offending update; consider RFC 7606 treat-as-withdraw"],
    ["show bgp neighbor <peer-ip> | match \"Peer AS|Local AS|Error\""],
    ["show ip bgp neighbors <peer-ip>"],
    _phases(
        [_act({"junos": "show bgp neighbor <peer-ip> | match \"Peer AS|Local AS|Error\"",
               "eos": "show ip bgp neighbors <peer-ip>", "frr": "vtysh -c 'show bgp neighbors <peer-ip>'"},
              "Error code/subcode and the configured AS numbers")],
        [_act({"junos": "show configuration protocols bgp group <group>",
               "eos": "show running-config section router bgp",
               "frr": "vtysh -c 'show running-config'"}, "Local config for the neighbor")],
        [_act({"junos": "# fix peer-as / authentication-key / family to match the peer",
               "eos": "# fix remote-as / password / address-family to match the peer",
               "frr": "# fix remote-as / password / capabilities to match the peer"},
              "Both sides agree on AS, auth and capabilities")],
        [_act({"junos": "show bgp summary", "eos": "show ip bgp summary", "frr": "vtysh -c 'show bgp summary'"},
              "Established")],
        [_act({"junos": "# enable RFC 7606 revised error handling where supported",
               "frr": "# FRR applies RFC 7606 treat-as-withdraw by default"},
              "A malformed attribute withdraws a route instead of resetting the session")],
        ("Decode the error.", "Read the local config.", "Align config with the peer.", "Established.",
         "Use revised error handling."),
    ),
    [], ["Alert: NOTIFICATION code 2/3 on any peer"],
)

_BGP_PATH = _entry(
    r"origin / as-path",
    "The origin AS or AS-path for a monitored prefix changed. Legitimate causes exist (new "
    "transit, traffic engineering), but an unexpected origin is the signature of a prefix hijack "
    "and a new transit in the middle of the path the signature of a route leak.",
    "Traffic for the prefix may be diverted, black-holed or intercepted.",
    "P1 for your own prefixes until validated.",
    ["Compare old vs new origin and path", "Validate the new origin against RPKI ROAs and IRR",
     "If invalid: contact upstreams, announce more-specifics only per policy, file with the upstream NOC"],
    ["show route <prefix> detail | match \"AS path|Source|Validation\"", "show validation database"],
    ["show ip bgp <prefix> detail"],
    _phases(
        [_act({"junos": "show route <prefix> detail | match \"AS path|Source|Validation\"",
               "eos": "show ip bgp <prefix> detail", "frr": "vtysh -c 'show bgp ipv4 unicast <prefix>'"},
              "Current paths, origin and RPKI validation state")],
        [_act({"junos": "show validation database", "frr": "vtysh -c 'show rpki prefix-table'"},
              "ROA for the prefix and expected origin")],
        [_act({"junos": "set policy-options policy-statement RPKI-IMPORT term invalid from validation-database invalid\n"
                        "set policy-options policy-statement RPKI-IMPORT term invalid then reject",
               "frr": "route-map RPKI-IN deny 10\n match rpki invalid"},
              "RPKI-invalid routes rejected at import")],
        [_act({"junos": "show route <prefix> detail", "eos": "show ip bgp <prefix> detail",
               "frr": "vtysh -c 'show bgp ipv4 unicast <prefix>'"}, "Expected origin restored")],
        [_act({"junos": "# deploy ROV (RPKI) + IRR-generated prefix-lists on every external peer",
               "eos": "# deploy RPKI origin validation and IRR prefix-lists on external peers",
               "frr": "# deploy RPKI origin validation and IRR prefix-lists on external peers"},
              "Hijacks/leaks filtered automatically")],
        ("Characterize the change.", "Validate against RPKI/IRR.", "Reject invalid routes.",
         "Expected origin back.", "Origin validation everywhere."),
    ),
    ["# Junos: RPKI validation-database invalid → reject on external imports"],
    ["Alert: origin AS change for any owned prefix", "Alert: RPKI-invalid route accepted"],
)

# ─────────────────────────────────────────────────────────────────────────────
# Categories the classifier emits that had no playbook of their own (they fell
# through to "Event detected: ..." or to an unrelated entry). Deliberately
# compact: root cause, read-only diagnosis, and the standard first mitigation.
# ─────────────────────────────────────────────────────────────────────────────
_IPS_THREAT = _entry(
    r"\bips\b|threat|signature",
    "The firewall's IPS / threat engine matched a signature at high or critical severity. It can be a real "
    "exploit attempt, a scanner, or a false positive from a legitimate application that trips the signature.",
    "A genuine hit on an exposed or unpatched host can mean compromise; a noisy false positive hides real ones.",
    "P2 — P1 if the destination host is in the signature's target class and the action was 'allow'.",
    ["Identify the signature, source, destination and the action taken (blocked vs allowed)",
     "Check whether the destination is vulnerable to what the signature describes",
     "Block or rate-limit a malicious source; tune the signature only after confirming a false positive"],
    [], [],
    _phases(
        [_act({"panos": "show log threat", "fortios": "diagnose sys session filter src <src-ip>\ndiagnose sys session list",
               "junos": "show security flow session source-prefix <src-ip>"},
              "Signature, source/destination and whether traffic was blocked or allowed")],
        [_act({"any": "# block or rate-limit the source at the perimeter if the hit is malicious"},
              "Malicious source can no longer reach the target", "Confirm it is not a business partner or monitor first")],
        [_act({"any": "# patch or isolate the targeted host; tune the signature only after confirming a false positive"},
              "Target no longer exposed to the exploit")],
        [_act({"panos": "show log threat", "fortios": "diagnose sys session list"},
              "No further hits from the source; sessions blocked")],
        [_act({"any": "# keep IPS signatures current and run in block mode on internet-facing zones"},
              "Fewer allowed hits and fewer false positives")],
        ("Characterize the hit.", "Contain the source.", "Fix or isolate the target.", "No repeat hits.",
         "Keep signatures current."),
    ),
    ["# Apply IPS/threat profiles to every internet-facing policy; set critical/high severity actions to block"],
    ["Alert: > 10 critical IPS hits from one source in 5 min", "Alert: IPS hit with action 'allow' on a server zone"],
)

_ACL_DENY = _entry(
    r"acl|deny",
    "Traffic was denied by an ACL or firewall policy. Normal for internet noise; a concern when it is internal "
    "traffic that used to pass (a policy or route change) or a sudden spike from one source (scan or misconfigured host).",
    "Legitimate flows silently dropped; or a scan/attack probing the network.",
    "P3 — P2 if a business flow is affected or the volume is a sharp rise.",
    ["Find the top denied source/destination/port pairs", "Compare against the last policy or routing change",
     "Add a permit if the flow is legitimate; block the source if it is a scan"],
    ["show firewall log"], ["show ip access-lists"],
    _phases(
        [_act({"junos": "show firewall log", "eos": "show ip access-lists", "frr": "nft list ruleset",
               "ios": "show access-lists"},
              "Hit counters / log entries for the denying term")],
        [_act({"any": "# rate-limit or block the noisy source; do not open a policy for unverified traffic"},
              "Noise reduced without opening access", "Verify the flow is wanted before adding a permit")],
        [_act({"any": "# add the missing permit (least privilege) or fix the route/NAT that moved the flow"},
              "Legitimate flow passes; denied counters stop climbing for it")],
        [_act({"junos": "show firewall log", "eos": "show ip access-lists", "ios": "show access-lists"},
              "No new denies for the intended flow")],
        [_act({"any": "# log only meaningful denies; summarize internet noise with a rate limit"},
              "Deny logs stay readable")],
        ("Find top denied flows.", "Contain noise.", "Fix wanted flows.", "No new denies.", "Reduce log noise."),
    ),
    ["# Log denies on a counter with a rate limit instead of per-packet logging"],
    ["Alert: denies per source > 1000 in 5 min", "Alert: deny count on an internal-to-internal rule > 0"],
)

_DDOS_STORM = _entry(
    r"ddos|storm|flood",
    "A DDoS or broadcast/multicast storm protection threshold fired. Causes: a volumetric/protocol attack, a layer-2 "
    "loop or a misbehaving host flooding broadcast or unknown-unicast traffic.",
    "Control-plane and links saturate; a layer-2 loop takes the whole broadcast domain down.",
    "P1 if a loop is suspected or the control plane is affected; otherwise P2.",
    ["Find the port or protocol that crossed the threshold", "Check for a layer-2 loop (STP events, MAC flaps)",
     "Rate-limit or block the offending source; keep storm control enabled"],
    ["show ddos-protection protocols violations"], ["show storm-control"],
    _phases(
        [_act({"junos": "show ddos-protection protocols violations", "eos": "show storm-control",
               "ios": "show storm-control", "frr": "ip -s link show"},
              "Which protocol or port crossed the limit and when"),
         _act({"junos": "show interfaces <intf> extensive", "eos": "show interfaces counters rates"},
              "Which interface carries the flood")],
        [_act({"any": "# rate-limit or shut the offending access port; keep storm control active"},
              "Flood contained to one port", "Identify the host/loop first so a legitimate port is not cut")],
        [_act({"any": "# remove the loop or fix the host NIC/application generating the flood"},
              "Counters return to baseline")],
        [_act({"junos": "show ddos-protection protocols violations", "eos": "show storm-control"},
              "No active violations")],
        [_act({"any": "# set per-port storm-control and edge BPDU guard on all access ports"},
              "A single bad host cannot flood the domain")],
        ("Find the source of the flood.", "Contain the port.", "Fix the cause.", "No violations.",
         "Add edge protections."),
    ),
    ["# Storm control on every access port; BPDU guard on edge ports"],
    ["Alert: storm-control or DDoS violation on any port", "Alert: broadcast rate > 5% of link capacity for 1 min"],
)

_AAA_DOWN = _entry(
    r"aaa|tacacs|radius",
    "A TACACS+ or RADIUS server stopped answering (marked dead). Causes: server or network path down, firewall "
    "change, shared-secret mismatch, or a server overload.",
    "Operators may be locked out of devices that have no local fallback; accounting and 802.1X/VPN logins fail.",
    "P2 — P1 if no local fallback account works on critical devices.",
    ["Check reachability and the UDP/TCP port of the AAA server", "Confirm a local fallback account works",
     "Check the shared secret and the server's own health"],
    ["show configuration system tacplus-server"], ["show tacacs"],
    _phases(
        [_act({"ios": "show aaa servers", "eos": "show tacacs", "junos": "show configuration system tacplus-server",
               "frr": "nc -vz <aaa-server> 49"},
              "Server state (dead/alive) and counters"),
         _act({"junos": "ping <aaa-server>", "eos": "ping <aaa-server>", "ios": "ping <aaa-server>"},
              "Server reachable from the management VRF")],
        [_act({"any": "# make sure the local fallback (aaa authentication ... local) works before closing sessions"},
              "Operators can still log in", "Test from a second session before logging out")],
        [_act({"any": "# restore the AAA server or path; verify the shared secret matches on both ends"},
              "Server answers authentication requests")],
        [_act({"ios": "show aaa servers", "eos": "show tacacs"}, "Servers alive; no new dead events")],
        [_act({"any": "# configure at least two AAA servers per device plus a local fallback"},
              "One AAA outage no longer locks operators out")],
        ("Check server state.", "Keep a way in.", "Restore the server.", "Servers alive.", "Add redundancy."),
    ),
    ["# Two AAA servers + local fallback account on every device"],
    ["Alert: AAA server marked dead on any device", "Alert: > 5 failed AAA requests in 1 min"],
)

_DHCP_EXHAUST = _entry(
    r"dhcp",
    "A DHCP pool or scope has no free addresses. Causes: lease time too long for the client churn, rogue or stale "
    "leases, a scope that is too small, or an attacker consuming leases.",
    "New clients cannot get an address and fall back to link-local; existing clients are unaffected until renewal.",
    "P2 — new users are affected now.",
    ["Check pool utilisation and the oldest leases", "Shorten lease time or enlarge the scope",
     "Look for a single MAC consuming many leases"],
    ["show dhcp server binding"], ["show dhcp server"],
    _phases(
        [_act({"ios": "show ip dhcp pool\nshow ip dhcp binding", "junos": "show dhcp server binding",
               "eos": "show dhcp server"},
              "Pool utilisation and the leases in use"),
         _act({"ios": "show ip dhcp conflict"}, "Address conflicts removing addresses from the pool")],
        [_act({"any": "# free stale bindings for the affected scope or add a temporary range"},
              "New clients receive addresses", "Only clear bindings for the exhausted scope")],
        [_act({"any": "# size the scope for peak clients and shorten the lease time on guest/wireless scopes"},
              "Utilisation below 80% at peak")],
        [_act({"ios": "show ip dhcp pool", "junos": "show dhcp server binding"}, "Free addresses available")],
        [_act({"any": "# enable DHCP snooping rate limits to stop a single host exhausting the pool"},
              "A rogue client cannot drain the scope")],
        ("Measure utilisation.", "Free addresses.", "Resize the scope.", "Addresses free.", "Limit abuse."),
    ),
    ["# Lease time of 1-8 hours on guest/wireless scopes; DHCP snooping on access ports"],
    ["Alert: DHCP pool utilisation > 85%", "Alert: pool utilisation at 100%"],
)

_AP_DOWN = _entry(
    r"access point|\bap\b",
    "A wireless access point went offline. Causes: switch port or PoE failure, uplink/VLAN change, controller or "
    "cloud-management reachability, or the AP itself failing.",
    "Wireless coverage for that area is lost and clients roam to weaker neighbours.",
    "P2 — P1 if several APs on one switch dropped together (upstream fault).",
    ["Check whether several APs on the same switch dropped together", "Check the switch port, PoE draw and VLAN",
     "Confirm the AP can reach its controller or cloud management"],
    ["show poe interface <intf>"], ["show interfaces <intf> status"],
    _phases(
        [_act({"junos": "show poe interface <intf>", "eos": "show interfaces <intf> status",
               "ios": "show power inline <intf>\nshow ap summary"},
              "Port up, PoE delivered, AP present in the controller list"),
         _act({"junos": "ping <ap-ip>", "eos": "ping <ap-ip>", "ios": "ping <ap-ip>"},
              "AP answers from the management network")],
        [_act({"any": "# move clients to neighbouring APs by raising their power if coverage allows"},
              "Coverage restored for the area", "Revert the power change after repair")],
        [_act({"any": "# fix the port/PoE/VLAN fault or replace the AP"}, "AP rejoins the controller")],
        [_act({"ios": "show ap summary", "junos": "show poe interface <intf>"}, "AP online and serving clients")],
        [_act({"any": "# monitor PoE budget per switch and alert on AP disconnects in groups"},
              "Upstream faults are seen as one event")],
        ("Find the scope.", "Restore coverage.", "Fix the AP or port.", "AP online.", "Alert on groups."),
    ),
    ["# PoE budget headroom of at least 20% per access switch"],
    ["Alert: AP offline > 5 min", "Alert: 3 or more APs offline on one switch"],
)

_STP_EVENTS = _entry(
    r"stp|spanning",
    "A spanning-tree protection or topology event: root guard, loop guard or BPDU guard blocked a port, or the "
    "topology changed (TCN / root change). Causes: a switch or host sending BPDUs on an edge port, a bridge with a "
    "better priority appearing, a unidirectional link, or a layer-2 loop.",
    "Blocked ports cut the devices behind them; repeated topology changes flush MAC tables and cause flooding.",
    "P2 — P1 if the root moved or traffic is looping.",
    ["Identify the blocked port and the VLAN", "Find the device that sent the BPDU / claims root",
     "Fix the neighbour or edge-port configuration, then clear the guard state"],
    ["show spanning-tree bridge", "show spanning-tree interface"],
    ["show spanning-tree root", "show spanning-tree blockedports"],
    _phases(
        [_act({"junos": "show spanning-tree bridge\nshow spanning-tree interface",
               "eos": "show spanning-tree root\nshow spanning-tree blockedports",
               "ios": "show spanning-tree inconsistentports\nshow spanning-tree summary",
               "frr": "bridge -d link show"},
              "Root bridge, blocked/inconsistent ports and the VLANs affected"),
         _act({"ios": "show spanning-tree detail | include ieee|occurr|from|is exec"},
              "Which port the last topology change came from")],
        [_act({"any": "# keep the guard in place; isolate the offending device or port rather than disabling the guard"},
              "Protected topology stays stable", "Disabling root/BPDU guard hands the root to the offender")],
        [_act({"any": "# remove the rogue switch or correct its priority; fix the unidirectional link"},
              "Expected root bridge and port roles restored")],
        [_act({"junos": "show spanning-tree bridge", "eos": "show spanning-tree root",
               "ios": "show spanning-tree summary"}, "Root as designed; no inconsistent ports")],
        [_act({"any": "# set root primary/secondary explicitly; BPDU guard on edge ports; UDLD/loop guard on uplinks"},
              "Predictable root and fast containment")],
        ("Find the blocked port and root.", "Contain the offender.", "Fix topology.", "Root and ports as designed.",
         "Harden edges and uplinks."),
    ),
    ["# Explicit root and secondary-root priorities; BPDU guard on edge ports; loop guard / UDLD on uplinks"],
    ["Alert: root guard or BPDU guard block on any port", "Alert: > 5 topology changes in 10 min on one VLAN"],
)

_MAC_FLAP = _entry(
    r"mac",
    "MAC addresses are being learned on changing ports (move/flap). Causes: a layer-2 loop, a mis-wired or "
    "bonded host without LAG, a VM migration, or a duplicate MAC.",
    "Frames follow the wrong port; flooding and intermittent loss; a loop can saturate the domain.",
    "P2 — P1 if the move rate is high or spans many MACs (loop).",
    ["Find the MAC and the ports it moves between", "Check for a layer-2 loop or a host with two uplinks not in a LAG",
     "Fix the topology or the host teaming"],
    ["show ethernet-switching table"], ["show mac address-table"],
    _phases(
        [_act({"junos": "show ethernet-switching table\nshow ethernet-switching mac-learning-log",
               "eos": "show mac address-table address <mac>", "ios": "show mac address-table address <mac>",
               "frr": "bridge fdb show"},
              "Ports the MAC is learned on and how often it moves")],
        [_act({"any": "# shut or rate-limit the port that should not carry the MAC if a loop is confirmed"},
              "Move rate drops", "Only after confirming it is not a planned VM migration")],
        [_act({"any": "# fix the loop, team the host NICs in a LAG, or correct the duplicate MAC"},
              "MAC stable on one port")],
        [_act({"junos": "show ethernet-switching table", "eos": "show mac address-table address <mac>"},
              "MAC learned on a single port")],
        [_act({"any": "# enable MAC-move limits / loop protection on access ports"}, "Loops contained at the edge")],
        ("Find the moving MAC.", "Contain the loop.", "Fix the cause.", "MAC stable.", "Add move limits."),
    ),
    ["# MAC-move limit or loop protection on access ports"],
    ["Alert: same MAC moves > 5 times in 60 s", "Alert: MAC move events > 100 per minute on one VLAN"],
)

_BFD_DOWN = _entry(
    r"bfd session down|ptmd",
    "A BFD session to a neighbor went down, so the protocol that registered with it (BGP, OSPF, IS-IS, static) "
    "was told to tear its adjacency. Causes: link or path loss, CPU/control-plane congestion delaying hellos, "
    "interval/multiplier too aggressive, or the neighbor restarting.",
    "Fast failover fires; if it flaps, the routing protocol reconverges repeatedly.",
    "P2 — P1 if it is the only path to the neighbor.",
    ["Find which neighbor/interface the session is on and the diagnostic code", "Check the underlying link and path loss",
     "Check control-plane drops and the BFD interval/multiplier"],
    ["show bfd session extensive"], ["show bfd peers detail"],
    _phases(
        [_act({"junos": "show bfd session extensive", "eos": "show bfd peers detail",
               "frr": "vtysh -c 'show bfd peers'", "ios": "show bfd neighbors detail"},
              "Session state, diagnostic (timeout/neighbor signalled down) and last change")],
        [_act({"any": "# if the link is flapping, leave BFD to protect traffic; do not widen timers during an outage"},
              "Traffic stays on the surviving path", "Widen timers only after the cause is understood")],
        [_act({"any": "# fix the link/path loss or the control-plane congestion causing missed hellos"},
              "No missed BFD packets")],
        [_act({"junos": "show bfd session extensive", "eos": "show bfd peers detail", "frr": "vtysh -c 'show bfd peers'"},
              "Session up and stable")],
        [_act({"any": "# size interval x multiplier for the path (e.g. 300 ms x 3 on a stable link, looser on a WAN)"},
              "Detection tuned to the transport")],
        ("Find the session.", "Protect traffic.", "Fix the cause.", "Session stable.", "Tune timers."),
    ),
    ["# BFD interval/multiplier sized per link type; CoPP allowance for BFD"],
    ["Alert: BFD flaps > 3 in 10 min per neighbor", "Alert: BFD session down > 60 s"],
)

_EIGRP_DOWN = _entry(
    r"eigrp",
    "An EIGRP neighbor was lost. Causes: hold timer expiry (link loss, congestion), interface or subnet mismatch, "
    "authentication or K-value mismatch after a change, or the neighbor restarting.",
    "Routes learned from the neighbor are withdrawn and EIGRP reconverges; stuck-in-active can spread the impact.",
    "P2 — P1 if it is the only path.",
    ["Read the neighbor-down reason (holding time expired, interface down, peer restarted)",
     "Check the link and the interface timers on both ends", "Check the AS, K-values and authentication"],
    [], [],
    _phases(
        [_act({"ios": "show ip eigrp neighbors\nshow ip eigrp interfaces", "frr": "vtysh -c 'show ip eigrp neighbor'"},
              "Neighbor list, hold times and queue counts")],
        [_act({"ios": "show ip eigrp topology", "frr": "vtysh -c 'show ip eigrp topology'"},
              "Alternate paths exist for the lost routes")],
        [_act({"any": "# fix the link or the AS/K-value/authentication mismatch on one side"},
              "Neighbor re-forms")],
        [_act({"ios": "show ip eigrp neighbors", "frr": "vtysh -c 'show ip eigrp neighbor'"},
              "Neighbor up with a stable uptime")],
        [_act({"any": "# use stub routing and summarization at the edge to bound query scope"},
              "Smaller blast radius for future losses")],
        ("Read the loss reason.", "Confirm alternate paths.", "Fix the mismatch or link.", "Neighbor stable.",
         "Bound query scope."),
    ),
    ["# EIGRP stub on spokes; summarize at distribution"],
    ["Alert: EIGRP neighbor loss on any interface", "Alert: > 3 neighbor flaps in 10 min"],
)

_ISIS_ADJ = _entry(
    r"is-?is",
    "An IS-IS adjacency went down or changed state. Causes: hold time expiry from link loss or packet loss, "
    "interface down, MTU or authentication mismatch after a change, or a neighbor restart.",
    "The IGP reconverges; if the adjacency carried the only path, routes and any MPLS/LDP sessions over it are lost.",
    "P2 — P1 if it is the only path to the neighbor.",
    ["Read the adjacency-down reason (hold time expired, interface down, neighbor restarted)",
     "Check the link, MTU and authentication on both ends", "Check whether LDP/BGP sessions over the link also dropped"],
    ["show isis adjacency", "show isis interface"], ["show isis neighbors", "show isis interface"],
    _phases(
        [_act({"junos": "show isis adjacency\nshow isis interface", "eos": "show isis neighbors\nshow isis interface",
               "frr": "vtysh -c 'show isis neighbor'", "ios": "show isis neighbors"},
              "Adjacency state, level, hold time and the interface")],
        [_act({"junos": "show isis database", "eos": "show isis database", "frr": "vtysh -c 'show isis database'"},
              "Alternate paths exist in the link-state database")],
        [_act({"any": "# fix the link or the MTU/authentication/level mismatch on one side"},
              "Adjacency re-forms")],
        [_act({"junos": "show isis adjacency", "eos": "show isis neighbors", "frr": "vtysh -c 'show isis neighbor'"},
              "Adjacency Up with a stable uptime")],
        [_act({"any": "# enable BFD for IS-IS and keep MTU/authentication identical on both ends"},
              "Faster and more predictable failure detection")],
        ("Read the loss reason.", "Confirm alternate paths.", "Fix the link or mismatch.", "Adjacency stable.",
         "Add BFD."),
    ),
    ["# BFD for IS-IS on point-to-point links; identical MTU and auth key on both ends"],
    ["Alert: IS-IS adjacency down on any interface", "Alert: > 3 adjacency flaps in 10 min"],
)

_LDP_DOWN = _entry(
    r"\bldp\b",
    "An LDP neighbor or session went down, so labels learned from it are withdrawn and LSPs through it break. "
    "Causes: loss of the underlying link or IGP adjacency, loopback unreachable (LDP uses the router-id), "
    "keepalive timeout, or MD5 key mismatch.",
    "MPLS services (L3VPN, L2VPN, EVPN over MPLS) that ride the LSP lose forwarding until it re-establishes.",
    "P1 for production MPLS services; P2 otherwise.",
    ["Check the IGP adjacency and the loopback reachability first (LDP rides the IGP)",
     "Read the LDP session-down reason", "Check authentication and the transport address"],
    ["show ldp neighbor", "show ldp session"], ["show mpls ldp neighbor"],
    _phases(
        [_act({"junos": "show ldp neighbor\nshow ldp session", "eos": "show mpls ldp neighbor",
               "frr": "vtysh -c 'show mpls ldp neighbor'", "ios": "show mpls ldp neighbor"},
              "Neighbor and session state with the down reason")],
        [_act({"junos": "show ldp interface", "ios": "show mpls interfaces", "frr": "vtysh -c 'show mpls ldp interface'"},
              "LDP enabled on the expected interfaces")],
        [_act({"any": "# restore the IGP adjacency / loopback reachability; fix the key or transport-address mismatch"},
              "LDP session re-establishes")],
        [_act({"junos": "show ldp session", "eos": "show mpls ldp neighbor", "ios": "show mpls ldp neighbor"},
              "Session Operational with labels exchanged")],
        [_act({"any": "# enable LDP-IGP synchronization and session protection so a link flap does not drop labels"},
              "LSPs survive short link flaps")],
        ("Check the IGP first.", "Confirm LDP interfaces.", "Fix the underlay.", "Session up.", "Add session protection."),
    ),
    ["# LDP-IGP synchronization and session protection on core links"],
    ["Alert: LDP session down on any neighbor", "Alert: LDP session flaps > 3 in 10 min"],
)

_RESOURCE_PRESSURE = _entry(
    r"memory|oom|swap|cpu|utili[sz]ation|allocation|resource",
    "A device is short of CPU or memory: a process is holding the CPU, memory is exhausted or fragmented, or a "
    "routing/forwarding table has grown past what the platform was sized for. Causes: route or MAC table growth, "
    "a leak or runaway process, an attack or flood hitting the control plane.",
    "The control plane slows (protocol timers miss, sessions flap) and the device can fail allocations or be "
    "killed by the OOM killer, causing a restart.",
    "P2 — P1 if free memory is near exhaustion or protocols are flapping.",
    ["Identify the top CPU/memory consumer", "Compare table sizes against the platform limits and the baseline",
     "Rate-limit or remove the source of load; plan a restart of the process only in a maintenance window"],
    ["show chassis routing-engine", "show system processes extensive"], ["show processes top once"],
    _phases(
        [_act({"junos": "show chassis routing-engine\nshow system processes extensive",
               "eos": "show processes top once", "ios": "show processes cpu sorted\nshow processes memory sorted",
               "frr": "top -b -n1 | head -20\nfree -m",
               "fortios": "get system performance status", "panos": "show system resources"},
              "Top consumers, free memory and CPU idle %")],
        [_act({"any": "# rate-limit or remove the load source (flood, scraper, polling) before touching the process"},
              "CPU/memory pressure stops growing", "Restart a process only in a maintenance window")],
        [_act({"any": "# fix the leak (upgrade/patch), trim the table (filters, summarization) or move to a larger platform"},
              "Utilization back under 70%")],
        [_act({"junos": "show chassis routing-engine", "eos": "show processes top once", "ios": "show processes cpu sorted"},
              "CPU idle > 30% and free memory stable")],
        [_act({"any": "# add CPU/memory threshold alerts and control-plane policing"},
              "Early warning before protocols are affected")],
        ("Find the consumer.", "Stop the growth.", "Fix the cause.", "Utilization stable.", "Alert earlier."),
    ),
    ["# Control-plane policing; alerts at 80% CPU and 85% memory"],
    ["Alert: CPU > 85% for 5 min", "Alert: free memory < 15%", "Alert: allocation failure or OOM-kill event"],
)

_PROCESS_RESTART = _entry(
    r"crash|restart|reload|process|service|switchover|failover|swss|syncd|orchagent|switchd",
    "A daemon, service or control-plane module crashed, was restarted, or the device reloaded or switched over "
    "to a standby. Causes: a software bug (core dump), resource exhaustion, a failed upgrade/config, a hardware or "
    "power event, or an operator action.",
    "Protocols and forwarding handled by that process restart: sessions drop and reconverge, and a repeating crash "
    "loop keeps the device unstable.",
    "P1 if repeating or on a core device; otherwise P2.",
    ["Establish whether it was planned (change/reload) or a crash", "Collect the core file / crash log for the vendor",
     "Check for a trigger: recent change, memory growth, a specific route or packet"],
    ["show system core-dumps", "show log messages | last 100"], ["show agent logs crash", "show logging last 100"],
    _phases(
        [_act({"junos": "show system core-dumps\nshow log messages | last 100",
               "eos": "show agent logs crash\nshow logging last 100",
               "frr": "systemctl status <service>\njournalctl -u <service> --since '1 hour ago'",
               "ios": "show version\nshow logging"},
              "Which process failed, when, and whether a core was written")],
        [_act({"any": "# for a crash loop, fail traffic away (drain/raise metric) before further restarts"},
              "Traffic leaves the unstable device", "Coordinate with the change owner first")],
        [_act({"any": "# open a vendor case with the core/crash log; roll back the change or upgrade the fixed release"},
              "Process stays up")],
        [_act({"junos": "show system uptime", "eos": "show version", "frr": "systemctl status <service>"},
              "No new restarts after 24 h")],
        [_act({"any": "# keep core files off-box and alert on any process restart"}, "Crashes are seen immediately")],
        ("Planned or crash?", "Drain if looping.", "Get the cause fixed.", "Stable.", "Alert on restarts."),
    ),
    ["# Export core files and syslog to a remote collector"],
    ["Alert: any process restart or core dump", "Alert: device uptime reset (reload)"],
)

# Matched before the existing entries of the same category.
PREPEND: dict[str, dict[str, dict[str, Any]]] = {
    "routing": {
        "bgp_max_prefix": _BGP_MAXPFX,
        "bgp_hold_timer": _BGP_HOLD,
        "bgp_admin_cease": _BGP_ADMIN,
        "bgp_notification_error": _BGP_NOTIF_ERR,
        "bgp_path_change": _BGP_PATH,
        # Ahead of the generic OSPF entry, whose `adj.*change` also matches "IS-IS adjacency change".
        "isis": _ISIS_ADJ,
        "ldp": _LDP_DOWN,
        "eigrp": _EIGRP_DOWN,
        "bfd": _BFD_DOWN,
    },
    "vpn": {"ike_phase1": _IKE_P1, "ike_phase2": _IKE_P2, "dpd": _DPD},
    "redundancy": {"fw_split_brain": _HA_SPLIT, "fw_failover": _FW_FAILOVER},
    "system": {"conserve_mode": _CONSERVE, "resource": _RESOURCE_PRESSURE, "process_restart": _PROCESS_RESTART},
    "security": {"ips_threat": _IPS_THREAT, "acl_deny": _ACL_DENY, "ddos": _DDOS_STORM},
}

# Whole new categories.
CATEGORIES: dict[str, dict[str, dict[str, Any]]] = {
    "sdwan": {
        "sla": _SDWAN_SLA,
        "bfd": _SDWAN_BFD,
        "omp": _SDWAN_OMP,
        "control": _SDWAN_CONTROL,
        "_default": _SDWAN_SLA,
    },
    "firewall": {"session_table": _SESSION_TABLE, "_default": _SESSION_TABLE},
    "aaa": {"_default": _AAA_DOWN},
    "dhcp": {"_default": _DHCP_EXHAUST},
    "wireless": {"_default": _AP_DOWN},
    "stp": {"_default": _STP_EVENTS},
    "switching": {"_default": _MAC_FLAP},
}


def merge_into(kb: dict[str, dict[str, dict[str, Any]]]) -> None:
    """Prepend vendor entries per category and add new categories (idempotent)."""
    for category, entries in PREPEND.items():
        existing = {k: v for k, v in kb.get(category, {}).items() if k not in entries}
        kb[category] = {**entries, **existing}
    for category, entries in CATEGORIES.items():
        kb[category] = dict(entries)
