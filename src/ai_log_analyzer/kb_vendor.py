"""Rule-based playbooks for security / SD-WAN vendors and BGP anomalies.

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

# Matched before the existing entries of the same category.
PREPEND: dict[str, dict[str, dict[str, Any]]] = {
    "routing": {
        "bgp_max_prefix": _BGP_MAXPFX,
        "bgp_hold_timer": _BGP_HOLD,
        "bgp_admin_cease": _BGP_ADMIN,
        "bgp_notification_error": _BGP_NOTIF_ERR,
        "bgp_path_change": _BGP_PATH,
    },
    "vpn": {"ike_phase1": _IKE_P1, "ike_phase2": _IKE_P2, "dpd": _DPD},
    "redundancy": {"fw_split_brain": _HA_SPLIT, "fw_failover": _FW_FAILOVER},
    "system": {"conserve_mode": _CONSERVE},
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
}


def merge_into(kb: dict[str, dict[str, dict[str, Any]]]) -> None:
    """Prepend vendor entries per category and add new categories (idempotent)."""
    for category, entries in PREPEND.items():
        existing = {k: v for k, v in kb.get(category, {}).items() if k not in entries}
        kb[category] = {**entries, **existing}
    for category, entries in CATEGORIES.items():
        kb[category] = dict(entries)
