"""Pattern-based syslog classifier — vendor-agnostic.

Each event is matched against a regex KB and assigned (severity, category, description).
Works on any normalized event regardless of source (Kibana, FRR docker logs, raw syslog).
"""
from __future__ import annotations

import os
import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field

import regex

from ai_log_analyzer.hostnames import short_host

# BGP "from X to Y" grammar. A match here reads the line's own transition, so it outranks the
# parser's coarser state (see _AUTHORITATIVE below).
_BGP_TRANSITION_DOWN = (
    r"(?:bgp|peer|neighbou?r).*(?:\bestablished\s*(?:->|\u2192|to)\s*(?:idle|active|connect|opensent|openconfirm|clearing|down|deleted)\b"
    r"|\bold state established\b.*\bnew state\s+(?:idle|active|connect|opensent|openconfirm|clearing)\b)"
)
_BGP_TRANSITION_UP = r"(?:bgp|peer|neighbou?r).*(?:->|\u2192|\bto|\bnew state|\bchanged to|(?<!old )\bstate)\s*established\b"

# (regex, severity, category, description) — first match wins.
# Patterns tested against f"{appname} {message}".lower()
_KB_PATTERNS: list[tuple[str, str, str, str]] = [
    # ── Operator CLI audit / accounting records ──
    # They quote the command text ("show chassis alarms", "show bgp ... | match down"), so every
    # keyword rule below would fire on the operator's own keystrokes. First match wins.
    (r"ui_cmdline_read_line|cfglog_loggedcmd|logged command\b|%accounting-\d-cmd\b|\bcommand=/"
     r"|\bcommand\s*[:=]?\s*['\"](?:show|display|get|ping|traceroute|clear|request|configure|set|delete|commit|run)\b",
                                                                         "low",      "config",     "CLI management activity"),
    # ── Security / SD-WAN vendors (gated on parser appnames / vendor tokens) ──
    # FortiOS appnames are "fortios-<subtype>", PAN-OS "panos-<subtype>";
    # Cisco SD-WAN lines carry bfd-/omp-/control-connection- notifications.
    (r"fortios.*(?:enters?|entered)\s+(?:memory\s+)?conserve mode|fortios.*extreme low memory",
                                                                         "critical", "system",     "FortiGate memory conserve mode"),
    (r"fortios.*(?:leaves?|left|exit\w*)\s+(?:memory\s+)?conserve mode", "low",      "system",     "FortiGate conserve mode cleared"),
    (r"session table.*(?:full|exhaust)|session limit.*(?:reached|exceed)|max\w*\s+sessions?\s+reached",
                                                                         "high",     "firewall",   "Firewall session table exhaustion"),
    (r"(?:fortios-ha|panos-ha).*(?:split.?brain|heartbeat.*(?:lost|down|fail)|hbdev.*down|ha1.*(?:link|connection).*down|both.*active)",
                                                                         "critical", "redundancy", "Firewall HA split-brain / heartbeat loss"),
    (r"(?:fortios-ha|panos-ha).*(?:failover|moved from state|state.*(?:changed|moved)|member state|master.*(?:change|elect)|non-functional)",
                                                                         "high",     "redundancy", "Firewall HA failover / state change"),
    (r"(?:fortios-vpn|panos-vpn|kmd|iked).*(?:phase[- ]?1|ike sa|ike-nego-p1).*(?:fail|error|timeout|mismatch|no proposal)|ipsec phase 1 error|negotiate_error",
                                                                         "high",     "vpn",        "IPsec IKE Phase 1 negotiation failure"),
    (r"(?:fortios-vpn|panos-vpn|kmd|iked).*(?:phase[- ]?2|quick mode|ike-nego-p2).*(?:fail|error|timeout|mismatch|no proposal)|action=phase2-down",
                                                                         "high",     "vpn",        "IPsec IKE Phase 2 negotiation failure"),
    (r"(?:fortios-vpn|panos-vpn).*(?:\bdpd\b|dead peer).*(?:fail|timeout|down)",
                                                                         "high",     "vpn",        "IPsec DPD failure / peer dead"),
    (r"(?:fortios-vpn|panos-vpn).*(?:tunnel-down|tunnel.*(?:\bdown\b|deleted)|ipsec.*\bdown\b)",
                                                                         "high",     "vpn",        "VPN/IPsec tunnel failure"),
    (r"(?:fortios-vpn|panos-vpn).*(?:tunnel-up|phase2-up|negotiation is succeeded|tunnel.*(?:\bup\b|established))|kmd_vpn_up",
                                                                         "medium",   "vpn",        "VPN/IPsec tunnel up"),
    (r"fortios-sdwan.*(?:out[- ]of[- ]sla|sla.*(?:fail|violat|miss)|miss(?:ed)? threshold|unreachable|stop forwarding|status=down|\bdead\b)|sd-?wan.*sla.*violat",
                                                                         "high",     "sdwan",      "SD-WAN SLA violation / member out of SLA"),
    (r"fortios-sdwan.*(?:in[- ]sla|back.*sla|start forwarding|is available|status=up|\balive\b)",
                                                                         "medium",   "sdwan",      "SD-WAN member back in SLA"),
    (r"(?:fortios-(?:ips|utm|anomaly|virus|attack)).*(?:critical|high|attack|signature)|panos-threat.*severity=(?:critical|high)",
                                                                         "high",     "security",   "IPS/threat signature match"),
    (r"panos-traffic.*\b(?:deny|drop|reset-\w+)\b|fortios-(?:traffic|forward|local).*action=(?:deny|blocked|dropped)",
                                                                         "medium",   "security",   "Firewall/ACL deny event"),
    (r"panos-globalprotect.*(?:auth\w*.*fail|fail\w*)|globalprotect\w*.*auth\w*[- ]fail",
                                                                         "high",     "security",   "Authentication failure"),
    (r"panos-routing.*bgp.*(?:left established|established\s*(?:->|to)\s*(?!established)\w+|to (?:idle|active|connect)\b|\bdown\b)",
                                                                         "high",     "routing",    "BGP peer down / connect failure"),
    (r"panos-routing.*bgp.*(?:enter(?:ed)? established|(?:->|to)\s*established|\bup\b)",
                                                                         "medium",   "routing",    "BGP peer established"),
    (r"(?:bfd-state-change|bfd-session).*(?:new-state:down|state down|\bdown\b)",
                                                                         "high",     "sdwan",      "SD-WAN BFD session down"),
    (r"(?:bfd-state-change|bfd-session).*(?:new-state:up|state up|\bup\b)",
                                                                         "medium",   "sdwan",      "SD-WAN BFD session up"),
    (r"omp-peer-state-change.*new-state:(?:init|down|handshake)|ompd.*(?:state changed to (?:init|down)|peer.*\bdown\b)",
                                                                         "high",     "sdwan",      "SD-WAN OMP peer down"),
    (r"omp-peer-state-change.*new-state:up|ompd.*state changed to up",   "medium",   "sdwan",      "SD-WAN OMP peer up"),
    (r"control-connection-state-change.*new-state:(?:down|tear_down|challenge|connect)|vdaemon.*(?:connection.*(?:is down|lost|tear)|state changed to down)",
                                                                         "high",     "sdwan",      "SD-WAN control connection down"),
    (r"control-connection-state-change.*new-state:up|vdaemon.*(?:connection.*is up|state changed to up)",
                                                                         "medium",   "sdwan",      "SD-WAN control connection up"),
    # An SD-WAN interface-state-change names its VPN, which the generic tunnel rule would misread.
    (r"interface-state-change.*\bdown\b",                                "high",     "interface",  "Interface link down"),
    (r"interface-state-change.*\bup\b",                                  "medium",   "interface",  "Interface link up"),
    # ── BGP anomaly signatures (vendor-neutral; before generic BGP rules) ──
    (r"max(?:imum)?[-_ ]?(?:number of )?prefix(?:es)?.*(?:exceed|reached|limit)|maxpfxexceed|prefix[-_ ]limit.*exceed|prefix limit exceeded",
                                                                         "high",     "routing",    "BGP max-prefix limit exceeded"),
    (r"%(?:bgp-\d-)?maxpfx\b|max(?:imum)?[-_ ]?prefix.*(?:threshold|warning|approach)|prefix.*threshold.*(?:reached|exceed)",
                                                                         "medium",   "routing",    "BGP max-prefix threshold warning"),
    (r"(?:origin(?:\s+as)?|as[-_ ]?path)\s*(?:change|changed|mismatch|conflict)|\bmoas\b|possible (?:hijack|route leak)|\broute leak\b",
                                                                         "high",     "routing",    "BGP origin / AS-path change (possible hijack or leak)"),
    (r"(?:cease|notification).*(?:admin\w*\s*(?:shutdown|reset)|peer de-?configured|other configuration change)|shutdown communication|(?:notification|cease).*\b6/[2346]\b",
                                                                         "medium",   "routing",    "BGP administrative shutdown / reset (Cease)"),
    (r"hold.?time(?:r)?\s*(?:expir|timeout|out\b)|\bevent holdtime\b|bgp_hold_timeout|notification.*\b4/0\b",
                                                                         "high",     "routing",    "BGP hold timer expired"),
    (r"notification.*\b[1235]/\d{1,2}\b|notification.*(?:open message error|update message error|fsm error|message header error|bad peer as|malformed)",
                                                                         "high",     "routing",    "BGP NOTIFICATION — protocol / OPEN / UPDATE error"),
    # ── BGP transition into Established, ahead of the keyword rules ──
    # "OpenConfirm to Established (last down 00:00:12 ago)" is UP; the "bgp.*down" rules below would
    # call it a failure. The DOWN direction ("Established to Active") sits next to the generic
    # "established" rule further down, after the specific hold-timer / idle verdicts.
    (_BGP_TRANSITION_UP,                                                "medium",   "routing",    "BGP peer established"),
    # ── CRITICAL ─────────────────────────────────────────────────────────
    # "Core dump disabled/enabled/limit" is configuration chatter, not a crash.
    (r"kernel\s*panic|core\s*dump(?!s?\s+(?:is |are |was |has been )?(?:disabled|off|enabled|not |limit|size))|watchdog.*reset|rpd.*panic",
                                                                         "critical", "system",     "Kernel panic / core dump — OS failure"),
    (r"swap_pager_getswapspace.*failed|swap.*exhaust",                  "critical", "system",     "Kernel swap space exhaustion"),
    # "memory: 20% full" is a status line; the guard only exempts fill levels below 90%.
    (r"out\s+of\s+memory|heap.*exhaust|(?!.*\b(?:[0-9]|[1-8][0-9])(?:\.\d+)?%\s*full\b)memory.*full|oom.?kill",
                                                                         "critical", "system",     "Memory exhaustion / OOM"),
    (r"parity\s+error|sbus\s+transaction|ser_overlay_mem_correction",   "critical", "hardware",   "ASIC memory parity error (hard)"),
    (r"fpc\d+.*(?:offline|power.?off|restart|crash|halt)",              "critical", "hardware",   "FPC/line card offline or crash"),
    (r"(?:major|minor|chassis)\s+alarm",                                "critical", "hardware",   "Chassis alarm triggered"),
    # Junos alarmd: the colour is the severity (RED = major, YELLOW = minor).
    (r"alarm set.*color=red",                                           "critical", "hardware",   "Chassis alarm triggered"),
    (r"alarm set.*color=yellow",                                        "medium",   "hardware",   "Chassis alarm triggered"),
    (r"power\s*supply.*fail|psu.*fail|fan.*(?:fail|offline)"
     r"|power\s*supply.{0,20}\b(?:offline|removed|absent)\b|psu.{0,20}\b(?:offline|removed|absent)\b"
     r"|psud.{0,60}(?:absence warning|not present|not ok|fault|insufficient)",
                                                                         "critical", "hardware",   "Power supply or fan failure"),
    (r"routing\s+engine.*failover|re\d+.*switchover|mastership",        "critical", "system",     "Routing Engine failover/switchover"),
    # ── HIGH ─────────────────────────────────────────────────────────────
    (r"bgp_connect_failed|bgp.*(?:down|cease|no\s+route|hold.?timer)",  "high",     "routing",    "BGP peer down / connect failure"),
    (r"rpd_bgp.*idle|bgp.*state.*idle|bgp.*notification",               "high",     "routing",    "BGP peer idle / notification"),
    (r"%bgp-3-notification|%bgp-5-adjchange.*down",                     "high",     "routing",    "BGP notification / adjacency down (FRR/IOS)"),
    (r"ospf.*(?:neighbor.*down|adj.*change|dead.*timer)",               "high",     "routing",    "OSPF neighbor state change"),
    (r"%ospf-5-adjchg.*down|ospf.*from\s+full\s+to",                    "high",     "routing",    "OSPF adjacency loss (FRR/IOS)"),
    # Cisco IOS-XE / NX-OS (%FACILITY-SEV-MNEMONIC) + Nokia SR Linux
    (r"%dual-5-nbrchange.*down",                                        "high",     "routing",    "EIGRP neighbor down (IOS)"),
    (r"bgp_mgr.*(?:to\s+(?:idle|active|connect)\b|session.*(?:down|fail))", "high", "routing",    "BGP peer down / connect failure"),
    (r"%(?:\w+-)?(?:link-\d-updown|lineproto-\d-updown).*to\s+down",    "high",     "interface",  "Interface link down"),
    (r"%ethport-5-if_down|%eth_port_channel.*down",                     "high",     "interface",  "Interface link down"),
    (r"\w+_mgr.*oper.*state.*down|srlinux.*port.*down",                 "high",     "interface",  "Interface link down"),
    (r"%sec_login-4-login_failed|%authpriv.*fail",                      "high",     "security",   "Authentication failure"),
    (r"%sysmgr-2-service_crashed|%sysmgr.*(?:crash|terminated)",        "critical", "system",     "NX-OS service crash"),
    (r"%vpc-2-|vpc.*peer.*(?:down|fail)",                               "high",     "lag",        "vPC peer failure (NX-OS)"),
    (r"%hsrp-5-statechange|%standby-\d-statechange|%fhrp",              "high",     "redundancy", "VRRP/gateway failover"),
    # Junos SRX chassis cluster (JSRPD): control-link loss is the HA heartbeat path.
    (r"jsrpd_ha_control_link_down",                                     "critical", "redundancy", "Firewall HA split-brain / heartbeat loss"),
    (r"jsrpd_rg_state_change",                                          "high",     "redundancy", "Firewall HA failover / state change"),
    # IOS-style system health: CPU, memory, restarts
    (r"%sys-\d-(?:mallocfail|memlow)|memory allocation of \d+ bytes failed",
                                                                         "high",     "system",     "Low memory / allocation failure"),
    (r"%sys-\d-cpurisingthreshold|\b(?:cpu|memory)\s+(?:usage|utili[sz]ation)\s+(?:is\s+)?(?:too\s+)?(?:high|critical|exceed\w*)"
     r"|high\s+(?:cpu|memory)\s+(?:usage|utili[sz]ation)|matches resource limit",
                                                                         "high",     "system",     "High CPU / memory utilization"),
    (r"%sys-\d-cpuhog|\bcpu\s*hog\b",                                  "medium",   "system",     "CPU hog — process holding the CPU"),
    (r"%sys-5-restart|%sys-\d-reload\b|\breload requested by\b",       "high",     "system",     "Device restart / reload"),
    (r"monit.*(?:process is not running|does not exist|status failed)", "high",     "system",     "Monitored process not running"),
    # AAA servers (TACACS+/RADIUS) going dark locks operators out or forces local fallback
    (r"%aaa-\d-tacacs_server_down|tacacs.{0,80}(?:is down|\bdead\b|unreachable|not responding)"
     r"|%radius-\d-radius_dead|radius.{0,80}(?:\bdead\b|unreachable|not responding)",
                                                                         "high",     "aaa",        "AAA server unreachable (TACACS+/RADIUS)"),

    # Work edge — IOS-XE, Aruba, Meraki. Specific tokens before the generic
    # auth and vpn rules so those descriptions stay distinct.
    (r"(?:aruba|meraki).*(?:\bap\b|access point).*(?:down|offline)|\bap\s+\S+\s+(?:is\s+)?(?:down|offline)",
                                                                         "high",     "wireless",   "Access point down"),
    (r"dot1x.*fail|802\.1x.*(?:fail|unauth)|eap.*fail|access-reject",   "high",     "security",   "802.1X authentication failure"),
    (r"dhcp.*(?:pool|scope).*(?:exhaust|full|deplet)|no\s+(?:free\s+)?addresses\s+(?:left|available)",
                                                                         "high",     "dhcp",       "DHCP pool exhausted"),
    (r"wan.*failover|uplink.*failover|cellular.*(?:failover|active)",   "high",     "redundancy", "WAN uplink failover"),
    (r"non-meraki.*vpn.*down|vpn\s+registry.*(?:down|fail)|site-to-site.*vpn.*down",
                                                                         "high",     "vpn",        "VPN/IPsec tunnel failure"),
    (r"%envmon.*(?:fan|temperature|supply)|%platform.*(?:thermal|power)", "critical", "hardware", "Power supply or fan failure"),
    (r"%module-2-|%platform-2-",                                        "critical", "hardware",  "Chassis alarm triggered"),
    # SONiC + Cumulus (specific tokens first so they win over generic link-down)
    (r"orchagent.*(?:crash|fail|exception|abort)",                      "critical", "system",     "SONiC orchagent crash"),
    (r"syncd.*(?:crash|fail|segfault)",                                 "critical", "system",     "SONiC syncd/ASIC crash"),
    (r"switchd.*(?:crash|fail|restart)",                                "critical", "system",     "Cumulus switchd crash"),
    (r"swss.*(?:fail|down|crash)",                                      "high",     "system",     "SONiC SWSS failure"),
    (r"teamd.*(?:slave.*down|link.*down|failover)",                     "high",     "lag",        "SONiC teamd LAG member down"),
    (r"clagd.*(?:peer.*down|conflict|fail)",                            "high",     "lag",        "Cumulus clagd peer down"),
    (r"ifupdown2.*(?:fail|error|unable)",                               "high",     "interface",  "Cumulus ifupdown2 failure"),
    (r"ptmd.*(?:link.*down|bfd.*down|fail)",                            "high",     "routing",    "Cumulus PTMD link/BFD down"),
    (r"bfd.*(?:down|removed|session.*fail)",                            "high",     "routing",    "BFD session down"),
    # IS-IS / LDP, matched on message text: "Adjacency to r2 (Gi0/0/1) Down" vs "... Up".
    (r"rpd_isis_adjdown|is-is lost .{0,20}adjacency"
     r"|(?:isis|clns).{0,80}adjacency to .{0,80}\)\s*(?:\(l\d\)\s*)?down\b|\badj\b.{0,100}\s-\s*down\b",
                                                                         "high",     "routing",    "IS-IS adjacency down"),
    (r"rpd_isis_adjup|is-is new .{0,20}adjacency"
     r"|(?:isis|clns).{0,80}adjacency to .{0,80}\)\s*(?:\(l\d\)\s*)?up\b|\badj\b.{0,100}\s-\s*up\b",
                                                                         "low",      "routing",    "IS-IS adjacency up"),
    (r"isis.*(?:adj.*down|adj.*change|lsp.*purge)",                     "high",     "routing",    "IS-IS adjacency change"),
    (r"rpd_ldp_(?:nbrdown|sessiondown)|ldp.{0,40}(?:neighbou?r|nbr|session).{0,100}\bis\s+down\b",
                                                                         "high",     "routing",    "LDP neighbor/session down"),
    (r"rpd_ldp_(?:nbrup|sessionup)|ldp.{0,40}(?:neighbou?r|nbr|session).{0,100}\bis\s+up\b",
                                                                         "low",      "routing",    "LDP neighbor/session up"),
    (r"license.*(?:expir|invalid|warn)|expir.*license",                 "high",     "compliance", "License expiration warning"),
    # VXLAN data-plane tunnels are not IPsec VPNs: match them before the generic tunnel rule.
    (r"vxlan[_ -]?tunnel[_ -]?down|vtep[_ -]?down|vtep\s+\S+\s+(?:is\s+)?(?:down|unreachable)|nve\d*.*peer.*(?:down|lost)|nve: nve peer .* lost",
                                                                         "high",     "evpn",       "VXLAN tunnel / VTEP down"),
    (r"(?<![a-z])ike.*fail|ipsec.*fail|vpn.*down|tunnel.*down|advpn",   "high",     "vpn",        "VPN/IPsec tunnel failure"),
    (r"lacp.*(?:timeout|expired|down)|lag_bundle.*down|ae\d+.*down",    "high",     "lag",        "LACP/LAG member down"),
    (r"lag_bundle.*leaving|lag.*member.*removed|%ec-\d-unbundle",       "high",     "lag",        "LAG member leaving bundle"),
    (r"mlag.*(?:fail|inconsist|disabled)|mlag.*inactive",               "high",     "lag",        "MLAG failure/inconsistency"),
    # "<Intf|Interface|Port> <name> is [now] down" (FRR, SR Linux, FortiOS, SR OS) and "Link is Down" (Linux
    # NICs); admin-down and bare port numbers ("port 22 is down") are not link faults.
    (r"snmp_trap_link_down|link\s*down|\blink\s+is\s+down\b|carrier.*down|if_down"
     r"|\b(?:intf|interface|port)\s+(?!\d+\s)[\w/.:\-]+(?:\(\d+\))?[,:]?\s+is\s+(?:now\s+)?(?:down|not operational)\b"
     r"|\bport\s+[\w/.\-]+:\s*down\b",                                  "high",     "interface",  "Interface link down"),
    # STP protection: guard recovery first ("unblocking" contains "blocking").
    (r"%spantree-\d-(?:rootguard|loopguard)_unblock|(?:root|loop)[ _-]?guard unblocking",
                                                                         "low",      "stp",        "STP guard recovered"),
    (r"%spantree-\d-(?:rootguard_block|loopguard_block|block_bpduguard)|%stp-\d-block_bpduguard"
     r"|(?:root|loop)[ _-]?guard blocking",
                                                                         "high",     "stp",        "STP root/loop/BPDU guard block"),
    (r"err.?disabl|errdisable|shutdown.*error",                         "high",     "interface",  "Interface error-disabled"),
    # sshd brute-force signatures the generic auth rule misses
    (r"failed (?:password|publickey|keyboard-interactive|none) for|invalid user\b|pam: authentication error|maximum authentication attempts exceeded",
                                                                         "high",     "security",   "Authentication failure"),
    (r"authentication.*fail|login.*fail|auth.*invalid|pam_unix.*fail",  "high",     "security",   "Authentication failure"),
    (r"vrrp.*(?:master.*change|backup|failover)|hsrp.*change",          "high",     "redundancy", "VRRP/gateway failover"),
    (r"(?:rx|receive|input)[ _-]?(?:optical )?power.{0,40}(?:low|high)[ _-]?alarm|(?:low|high)[ _-]?(?:rx|receive)[ _-]?power[ _-]?alarm",
                                                                         "high",     "hardware",   "Optical Rx power alarm"),
    (r"fpc\d+.*(?:error|mem:|unit:)",                                   "high",     "hardware",   "FPC hardware error"),
    (r"l3_entry|l2_entry|memory\s+block|blk:",                          "high",     "hardware",   "ASIC forwarding table error"),
    # Established -> Active/Connect/Clearing is a DOWN event; without this the generic
    # "bgp.*established" rule below ranks it as a medium "peer established".
    (_BGP_TRANSITION_DOWN,                                              "high",     "routing",    "BGP peer down / connect failure"),
    # ── MEDIUM ───────────────────────────────────────────────────────────
    (r"snmp_trap_link_up|link\s*up|\blink\s+is\s+up\b|carrier.*up|if_up"
     r"|\b(?:intf|interface|port)\s+(?!\d+\s)[\w/.:\-]+(?:\(\d+\))?[,:]?\s+is\s+(?:now\s+)?up\b|\bport\s+[\w/.\-]+:\s*up\b",
                                                                         "medium",   "interface",  "Interface link up"),
    (r"%(?:\w+-)?(?:link-\d-updown|lineproto-\d-updown).*to\s+up",      "medium",   "interface",  "Interface link up"),
    (r"%ec-\d-bundle\b",                                                "medium",   "lag",        "LAG member joining bundle"),
    (r"rpd_bgp.*establ|bgp.*established|%bgp-5-adjchange.*up|%adjchange.*\bup\b",
                                                                         "medium",   "routing",    "BGP peer established"),
    (r"ospf.*(?:neighbor.*full|adj.*full)|%ospf-5-adjchg.*full",        "medium",   "routing",    "OSPF neighbor established"),
    (r"ntp.*(?:unreachable|stratum.*16|no.*server|sync\s+lost)",        "medium",   "ntp",        "NTP sync lost/unreachable"),
    (r"stp.*(?:tcn|topology.*change|root.*change)",                     "medium",   "stp",        "STP topology change"),
    (r"pfe.*discard|packet.*drop|policer.*drop|congestion",             "medium",   "performance","Packet drops/policer discard"),
    (r"pause.*frame|flow.?control|flowcontrol",                         "medium",   "performance","Flow control / pause frames"),
    # "Started thermal control daemon" is a service banner, not a reading.
    (r"temperature.*(?:warn|high|threshold)|\bthermal\b(?! control daemon)|overheat|thermalctld.{0,100}(?:warn|insufficient|abnormal|over|critical|shutdown)",
                                                                         "medium",   "hardware",   "Temperature warning"),
    (r"acl.*deny|firewall.*deny|filter.*block|security.*deny",          "medium",   "security",   "Firewall/ACL deny event"),
    # a VXLAN "flood list" / flood-and-learn is forwarding state, not an attack
    (r"ddos|\bflood(?:ing)?\b(?![- ](?:list|domain|group|vtep|and|lsa|lsp))|storm.?control",
                                                                         "medium",   "security",   "DDoS/storm detected"),
    (r"lag_bundle.*joining|lag.*member.*added",                         "medium",   "lag",        "LAG member joining bundle"),
    (r"lacp.*activity|lacpd",                                           "medium",   "lag",        "LACP activity/negotiation"),
    (r"evpn.*(?:route|update|withdraw|type)",                           "medium",   "routing",    "EVPN route update"),
    (r"l2ald|l2.?learning|mac.*(?:move|flap|learn)",                    "medium",   "switching",  "MAC learning/move event"),
    (r"jddosd|ddos.*prot",                                              "medium",   "security",   "DDoS protection event"),
    # ── LOW ──────────────────────────────────────────────────────────────
    (r"accepted\s+(?:publickey|password|keyboard)|sshd.*accept",        "low",      "auth",       "SSH login accepted"),
    (r"session\s+(?:opened|closed)|pam_unix.*session",                  "low",      "auth",       "User session opened/closed"),
    (r"nvue.*(?:commit|apply)|nclu.*commit",                            "low",      "config",     "Cumulus NVUE/NCLU config commit"),
    (r"configdb.*(?:update|modify)|sonic-cfggen",                       "low",      "config",     "SONiC ConfigDB change"),
    (r"commit.*confirmed|config.*change|commit\b",                      "low",      "config",     "Configuration change committed"),
    (r"%sys-5-config_i|%vshd-5-vshd_syslog_config_i|object attribute (?:configured|deleted)|\bcfgpath=",
                                                                         "low",      "config",     "Configuration change committed"),
    (r"%sec_login-5-login_success",                                     "low",      "auth",       "SSH login accepted"),
    (r"lldp.*(?:neighbor|add|delete|update)",                           "low",      "discovery",  "LLDP neighbor change"),
    (r"snmpd|agentx|snmp.*trap",                                        "low",      "monitoring", "SNMP daemon/trap activity"),
    (r"sshd.*(?:disconnect|close|exit)",                                "low",      "auth",       "SSH session disconnected"),
    (r"mgd.*(?:ui_login|ui_commit|cli_command)",                        "low",      "config",     "CLI management activity"),
    (r"alarmd|alarm.*(?:set|clear)",                                    "low",      "hardware",   "Alarm set/clear event"),
    (r"chassisd|craft.*interface",                                      "low",      "hardware",   "Chassis daemon activity"),
    (r"rpd_isis|rpd_ospf|rpd.*(?:start|init|ready)",                    "low",      "routing",    "Routing daemon activity"),
    (r"pfed|dfwd|dcd",                                                  "low",      "system",     "Forwarding daemon activity"),
    (r"inetd|xinetd|ftpd",                                              "low",      "system",     "inetd service activity"),
    (r"(?:arista|strata|eos).*(?:agent|process)",                       "low",      "system",     "EOS agent/process activity"),
    (r"jlaunchd|process.*(?:start|stop|restart)",                       "low",      "system",     "Process lifecycle event"),
    (r"last\s+message\s+repeated",                                      "low",      "system",     "Repeated message suppressed"),
]

SEV_ORDER: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ── ReDoS bounds ─────────────────────────────────────────────────────────
# Ingest caps a line at 64 KB and any syslog sender controls the text, so the
# built-in table must not be able to pin a worker. Two layers: the text the KB
# loop sees is cut to _MAX_MATCH_CHARS (head and tail kept, so trailing state
# words such as "... changed state to down" survive), and every unbounded `.*`
# gap between keywords is compiled as `.{0,_GAP_CHARS}` so backtracking per
# start position is bounded. Real log lines keep their keywords well inside 300
# characters of each other; the bound only bites on adversarial input.
_MAX_MATCH_CHARS = 4096
_HEAD_CHARS = 3072
_GAP_CHARS = 300


def _bound_for_kb(text: str) -> str:
    """Head + tail of an over-long line (the KB loop never scans more than 4 KB)."""
    if len(text) <= _MAX_MATCH_CHARS:
        return text
    return f"{text[:_HEAD_CHARS]} {text[-(_MAX_MATCH_CHARS - _HEAD_CHARS - 1):]}"


def _bound_gaps(pattern: str, limit: int = _GAP_CHARS) -> str:
    """Rewrite every top-level-syntax ``.*`` as ``.{0,limit}`` (escapes and [classes] untouched)."""
    out: list[str] = []
    i, in_class = 0, False
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\":
            out.append(pattern[i:i + 2])
            i += 2
        elif in_class:
            in_class = ch != "]"
            out.append(ch)
            i += 1
        elif ch == "[":
            in_class = True
            out.append(ch)
            i += 1
        elif ch == "." and pattern[i + 1:i + 2] == "*":
            out.append(f".{{0,{limit}}}")
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


# Pre-compile patterns once for speed
_COMPILED: list[tuple[re.Pattern[str], str, str, str]] = [
    (re.compile(_bound_gaps(p), re.IGNORECASE), s, c, d) for (p, s, c, d) in _KB_PATTERNS
]
_AUTHORITATIVE: frozenset[int] = frozenset(
    id(_COMPILED[i][0]) for i, row in enumerate(_KB_PATTERNS) if row[0] in (_BGP_TRANSITION_DOWN, _BGP_TRANSITION_UP)
)

# ── Fast-path literal gate ───────────────────────────────────────────────
# In real syslog the vast majority of lines match no KB pattern, yet each one
# paid all ~75 regex scans. The gate below extracts, from every pattern's
# parse tree, a set of literal keywords such that a line CANNOT match the
# pattern without containing one of them. A cheap str-in scan over those
# keywords then decides whether the ordered regex loop needs to run at all.
# Patterns where no literal can be proven stay in an always-checked list, so
# the gate is sound by construction and self-maintains as rules are added.

try:  # Python 3.11+ moved sre_parse under re._parser
    from re import _parser as _sre_parse  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - Python 3.10
    import sre_parse as _sre_parse  # type: ignore[import-not-found]


def _guaranteed_literals(parsed) -> set[str] | None:
    """Lowercase literals, ≥1 of which appears in any match; None = no proof."""
    best: set[str] | None = None
    runs: list[str] = []
    run: list[str] = []

    def _flush() -> None:
        if run:
            runs.append("".join(run))
            run.clear()

    def _prefer(cur: set[str] | None, new: set[str] | None) -> set[str] | None:
        if not new: return cur
        if cur is None: return new
        return new if len(new) < len(cur) else cur

    for op, av in parsed:
        name = op.name
        if name == "LITERAL":
            run.append(chr(av).lower())
            continue
        _flush()
        if name == "SUBPATTERN":  # av = (group, add_flags, del_flags, sub)
            best = _prefer(best, _guaranteed_literals(av[3]))
        elif name == "BRANCH":  # av = (None, [alternatives])
            union: set[str] = set()
            for alt in av[1]:
                alt_lits = _guaranteed_literals(alt)
                if not alt_lits:
                    union = set()
                    break
                union |= alt_lits
            best = _prefer(best, union)
        elif name in ("MAX_REPEAT", "MIN_REPEAT"):  # av = (min, max, item)
            if av[0] >= 1:  # only required (non-optional) repeats guarantee
                best = _prefer(best, _guaranteed_literals(av[2]))
        # IN / ANY / AT / NOT_LITERAL etc. prove nothing — skip
    _flush()

    # Prefer a solid (≥3 char) literal run; else fall back to branch-derived
    # literals (sre hoists common alternation prefixes like '%' into a short
    # run, which would otherwise mask the long per-alternative literals);
    # else settle for the short run.
    solid = [r for r in runs if len(r) >= 3]
    if solid:
        return {max(solid, key=len)}
    if best and all(len(b) >= 3 for b in best):
        return best
    if runs:
        return {max(runs, key=len)}
    return best


_KEYWORDS: tuple[str, ...]
_UNGUARDED: list[tuple[re.Pattern[str], str, str, str]] = []
_UNGUARDED_IDX: list[int] = []
# Per-pattern gate: literal → indices of the patterns that literal guards.
# A line only needs the patterns whose guaranteed literal it contains (plus
# the unguarded ones), tried in table order so first-match precedence holds.
_LITERAL_PATTERNS: dict[str, list[int]] = {}
_kw: set[str] = set()
for _i, (_p, _s, _c, _d) in enumerate(_KB_PATTERNS):
    try:
        _lits = _guaranteed_literals(_sre_parse.parse(_p))
    except Exception:  # unparseable construct — never skip this pattern
        _lits = None
    # Literals under 3 chars match almost every line and would neuter the
    # gate — such patterns go to the always-checked list instead.
    if _lits and all(len(_l) >= 3 for _l in _lits):
        _kw |= _lits
        for _l in _lits:
            _LITERAL_PATTERNS.setdefault(_l, []).append(_i)
    else:
        _UNGUARDED.append(_COMPILED[_i])
        _UNGUARDED_IDX.append(_i)
_GATE_LITERALS: tuple[str, ...] = tuple(sorted(_LITERAL_PATTERNS))
_CANDIDATE_CACHE: dict[tuple[str, ...], list[tuple[re.Pattern[str], str, str, str]]] = {}
_CANDIDATE_CACHE_MAX = 4096


def _present_literals(text: str) -> tuple[str, ...]:
    """Every gate literal contained in ``text``, via one compiled alternation.

    ``_KEYWORDS`` is substring-free, so at most one keyword can start at any
    index (two starting together would make the shorter a prefix of the longer)
    and stepping the search one past each hit finds every keyword, overlapping
    ones included. A literal that contains a keyword is then confirmed with a
    plain ``in`` check, so the result equals a scan of all ``_GATE_LITERALS``.
    """
    found: set[str] = set()
    pos = 0
    while (m := _GATE_RE.search(text, pos)):
        found.add(m.group())
        pos = m.start() + 1
    if not found:
        return ()
    return tuple(sorted({lit for k in found for lit in _LITERALS_WITH[k] if lit in text}))


def _gated_candidates(combined: str) -> list[tuple[re.Pattern[str], str, str, str]]:
    """Ordered KB patterns that can possibly match ``combined`` (ASCII only)."""
    if not _KEYWORDS:
        return _UNGUARDED
    present = _present_literals(combined)
    if not present:
        return _UNGUARDED
    cached = _CANDIDATE_CACHE.get(present)
    if cached is None:
        ids = set(_UNGUARDED_IDX)
        for k in present:
            ids.update(_LITERAL_PATTERNS[k])
        cached = [_COMPILED[i] for i in sorted(ids)]
        if len(_CANDIDATE_CACHE) >= _CANDIDATE_CACHE_MAX:
            _CANDIDATE_CACHE.clear()
        _CANDIDATE_CACHE[present] = cached
    return cached
# Prune redundant keywords: if k2 is a substring of k1, any line containing
# k1 also contains k2 — k2 alone suffices for the gate.
_KEYWORDS = tuple(sorted(
    k for k in _kw
    if not any(other != k and other in k for other in _kw)
))
# One alternation over the substring-free keywords (longest first) replaces the
# per-line scan of every literal; see _present_literals for why it is exact.
_GATE_RE = re.compile("|".join(re.escape(k) for k in sorted(_KEYWORDS, key=len, reverse=True)))
_LITERALS_WITH: dict[str, tuple[str, ...]] = {
    k: tuple(lit for lit in _GATE_LITERALS if k in lit) for k in _KEYWORDS
}

# ── Custom user rules ────────────────────────────────────────────────────
# Loaded from a JSON file (env AI_LOG_ANALYZER_CUSTOM_RULES or add_custom_rules()).
# Custom rules are checked BEFORE the built-in KB so operators can override
# any built-in verdict. They bypass the literal gate — rule counts are small,
# so the extra scans are negligible.
_MAX_CUSTOM_RULES = 100
_MAX_CUSTOM_PATTERN_LENGTH = 512
_CUSTOM_REGEX_TIMEOUT_SECONDS = 0.01
_CUSTOM_RULES: list[tuple[regex.Pattern, str, str, str]] = []


def add_custom_rules(rules: list[dict]) -> tuple[int, list[str]]:
    """Register user-defined classification rules at runtime.

    Each rule: {"pattern": regex, "severity": critical|high|medium|low|info,
    "category": str, "description": str}. Returns (added_count, errors);
    invalid rules are skipped, never fatal.
    """
    added, errors = 0, []
    for i, rule in enumerate(rules):
        if len(_CUSTOM_RULES) >= _MAX_CUSTOM_RULES:
            errors.append(f"rule {i}: custom rule limit ({_MAX_CUSTOM_RULES}) reached")
            continue
        if not isinstance(rule, dict):
            errors.append(f"rule {i}: not an object")
            continue
        pattern = rule.get("pattern", "")
        severity = str(rule.get("severity", "")).lower()
        category = str(rule.get("category", "custom")) or "custom"
        description = str(rule.get("description", "")) or "Custom rule match"
        if severity not in SEV_ORDER:
            errors.append(f"rule {i}: invalid severity {severity!r}")
            continue
        if not isinstance(pattern, str) or not pattern:
            errors.append(f"rule {i}: pattern must be a non-empty string")
            continue
        if len(pattern) > _MAX_CUSTOM_PATTERN_LENGTH:
            errors.append(
                f"rule {i}: pattern exceeds {_MAX_CUSTOM_PATTERN_LENGTH} characters"
            )
            continue
        try:
            compiled = regex.compile(pattern, regex.IGNORECASE)
        except regex.error as exc:
            errors.append(f"rule {i}: bad regex: {exc}")
            continue
        _CUSTOM_RULES.append((compiled, severity, category, description))
        added += 1
    return added, errors


def load_custom_rules_file(path: str) -> tuple[int, list[str]]:
    """Load custom rules from a JSON file: a list of rule objects."""
    import json
    from pathlib import Path
    p = Path(path).expanduser()
    if not p.is_file():
        return 0, [f"custom rules file not found: {p}"]
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return 0, [f"custom rules file unreadable: {exc}"]
    if not isinstance(data, list):
        return 0, ["custom rules file must contain a JSON list"]
    return add_custom_rules(data)


def custom_rules() -> list[dict]:
    """JSON-ready view of the currently registered custom rules."""
    return [
        {"pattern": p.pattern, "severity": s, "category": c, "description": d}
        for (p, s, c, d) in _CUSTOM_RULES
    ]


_rules_path = os.environ.get("AI_LOG_ANALYZER_CUSTOM_RULES", "")
if _rules_path:
    load_custom_rules_file(_rules_path)

# ANSI/VT100 terminal escape sequences — systemd, journald, FRR vtysh, and
# any source piping colored output leaks these into the message field.
# Pattern covers CSI (\x1b[...m), OSC (\x1b]...\x07), and SGR-style codes.
_ANSI_ESCAPE_RE: re.Pattern[str] = re.compile(
    r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])"
)


def strip_ansi(text: str) -> str:
    """Remove ANSI/VT100 escape sequences from log message text.

    systemd boot messages (`\\x1b[0;32m  OK  \\x1b[0m Started ...`), FRR vtysh
    output, and any colorized source leaks raw escape codes that render as
    `[0;32m` / `[0m` garbage in the UI. Stripping at the LogEvent → Classified
    boundary catches every source path with one call.
    """
    if not text or "\x1b" not in text:
        return text
    return _ANSI_ESCAPE_RE.sub("", text)


# Canonical structured fields shared by LogEvent and ClassifiedEvent. All are
# optional ("" = unknown) so the five-field positional constructor every
# adapter and test uses keeps working unchanged.
STRUCTURED_FIELDS: tuple[str, ...] = (
    "vendor",             # fortinet | paloalto | cisco_sdwan | juniper | arista | cisco_ios | cisco_nxos | frr | sonic | cumulus | nokia_srl
    "event_type",         # bgp_session | ipsec_tunnel | ike_phase1 | sdwan_sla | bfd_session | omp_peer | interface_link | ...
    "interface",
    "peer_ip",
    "asn",
    "vrf",
    "vni",
    "tunnel_id",
    "action",             # vendor action verb (FortiOS action=, PAN-OS action field, …)
    "state",              # "down" | "up" | "" — drives down→up recovery pairing
    "normalized_utc_ts",  # ISO-8601 UTC when the source carried enough to compute it
)


@dataclass(frozen=True)
class LogEvent:
    """Normalized input event — what every adapter produces.

    The first five fields are the legacy contract. The structured fields are
    filled by ``ai_log_analyzer.parsers`` (or left blank by adapters that
    only know raw text — the classifier enriches those lazily). ``attrs``
    carries vendor extras (remip, locip, healthcheck, eventid, …); it is
    excluded from equality/hash so events stay hashable.
    """
    timestamp: str
    hostname: str
    appname: str
    severity_raw: str
    message: str
    vendor: str = ""
    event_type: str = ""
    interface: str = ""
    peer_ip: str = ""
    asn: str = ""
    vrf: str = ""
    vni: str = ""
    tunnel_id: str = ""
    action: str = ""
    state: str = ""
    normalized_utc_ts: str = ""
    attrs: Mapping[str, str] = field(default_factory=dict, compare=False, hash=False, repr=False)

    def structured(self) -> dict[str, str]:
        """Non-empty structured fields (no attrs)."""
        return {f: getattr(self, f) for f in STRUCTURED_FIELDS if getattr(self, f)}


@dataclass
class ClassifiedEvent:
    """Output event after classification."""
    timestamp: str
    hostname: str
    appname: str
    severity: str           # critical | high | medium | low | info
    severity_raw: str
    category: str
    description: str
    action: str
    message: str
    sample_message: str = field(default="")  # short version for UI
    # How the verdict was reached: 1.0 custom rule, 0.9 KB pattern,
    # 0.7 derived from the parsed (event_type, state), 0.6 raw-severity
    # promotion, 0.3 unmatched (description = raw snippet).
    confidence: float = field(default=0.9)
    # Structured entity fields carried over from the LogEvent (see STRUCTURED_FIELDS).
    vendor: str = ""
    event_type: str = ""
    interface: str = ""
    peer_ip: str = ""
    asn: str = ""
    vrf: str = ""
    vni: str = ""
    tunnel_id: str = ""
    # `action` above is the recommended next step; the vendor's own action
    # verb (FortiOS action=, PAN-OS action) lives here.
    vendor_action: str = ""
    state: str = ""
    normalized_utc_ts: str = ""
    attrs: Mapping[str, str] = field(default_factory=dict, repr=False)

    def structured(self) -> dict[str, str]:
        out = {}
        for f in STRUCTURED_FIELDS:
            value = self.vendor_action if f == "action" else getattr(self, f)
            if value:
                out[f] = value
        return out

    def to_dict(self) -> dict:
        d = {
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "appname": self.appname,
            "severity": self.severity,
            "severity_raw": self.severity_raw,
            "category": self.category,
            "description": self.description,
            "action": self.action,
            "message": self.message,
            "sample_message": self.sample_message,
            "confidence": self.confidence,
        }
        entities = self.structured()
        if entities:
            d["entities"] = entities
        return d


_DEFAULT_ACTIONS: dict[tuple[str, str], str] = {
    ("critical", "system"):     "Escalate immediately — possible OS/hardware failure",
    ("critical", "hardware"):   "Check chassis hardware — FPC/PSU/Fan replacement may be needed",
    ("critical", "compliance"): "Renew license urgently — feature may stop working",
    ("high", "routing"):        "Check BGP/OSPF neighbors — verify reachability and peering config",
    ("high", "interface"):      "Investigate physical link — check fiber/SFP/patch panel",
    ("high", "lag"):            "Check LAG member links — verify LACP config and cabling",
    ("high", "vpn"):            "Investigate VPN tunnel — check IKE Phase 1/2",
    ("high", "security"):       "Investigate auth failure — check logs for brute force",
    ("high", "redundancy"):     "Verify redundancy state — check VRRP priority and uplink",
    ("medium", "performance"):  "Monitor traffic — check for congestion or rate limiting",
    ("medium", "interface"):    "Verify link stability — check SFP Rx/Tx power",
    ("medium", "security"):     "Review ACL/firewall hits — check for policy violation",
    ("medium", "ntp"):          "Verify NTP reachability — time skew may affect logs",
    ("critical", "redundancy"): "Isolate the HA pair — confirm which node owns traffic before any failback",
    ("high", "sdwan"):          "Check SD-WAN overlay — BFD/OMP/control connections and transport SLA",
    ("high", "firewall"):       "Check firewall session/memory headroom — risk of new-session drops",
    ("medium", "sdwan"):        "Monitor SD-WAN path quality — confirm SLA recovery",
    ("high", "system"):         "Check device resources and process health — look at CPU/memory consumers and recent restarts",
    ("medium", "system"):       "Check which process is holding the CPU — compare against the usual baseline",
    ("high", "stp"):            "Find the port that received the unexpected BPDU — fix the neighbor or edge-port config",
    ("high", "aaa"):            "Verify AAA server reachability — confirm local/fallback login still works",
    ("high", "hardware"):       "Inspect hardware — check optics Rx power, line card and chassis alarms",
    ("low", "auth"):             "Informational — log user access for audit",
    ("low", "config"):           "Informational — track config changes in change log",
}


def _action_for(sev: str, cat: str) -> str:
    return _DEFAULT_ACTIONS.get((sev, cat), "Review and investigate as needed")


# (event_type, state) -> verdict, for events no rule matched (or only a catch-all matched).
# Descriptions reuse the KB rules' own strings so recovery pairing and playbooks line up. OSPF and
# BFD are left to their keyword rules: their parsed state reads "dead" in "ip ospf dead-interval 20".
_STATE_VERDICTS: dict[tuple[str, str], tuple[str, str, str]] = {
    ("bgp_session", "down"):    ("high",   "routing",   "BGP peer down / connect failure"),
    ("bgp_session", "up"):      ("medium", "routing",   "BGP peer established"),
    ("interface_link", "down"): ("high",   "interface", "Interface link down"),
    ("interface_link", "up"):   ("medium", "interface", "Interface link up"),
    ("ipsec_tunnel", "down"):   ("high",   "vpn",       "VPN/IPsec tunnel failure"),
    ("ipsec_tunnel", "up"):     ("medium", "vpn",       "VPN/IPsec tunnel up"),
    ("lag_member", "down"):     ("high",   "lag",       "LACP/LAG member down"),
    ("lag_member", "up"):       ("medium", "lag",       "LAG member joining bundle"),
    ("isis_adjacency", "down"): ("high",   "routing",   "IS-IS adjacency down"),
    ("isis_adjacency", "up"):   ("low",    "routing",   "IS-IS adjacency up"),
    ("ldp_session", "down"):    ("high",   "routing",   "LDP neighbor/session down"),
    ("ldp_session", "up"):      ("low",    "routing",   "LDP neighbor/session up"),
}
# Catch-all "daemon activity" rules say nothing about health; a typed state outranks them.
_GENERIC_ACTIVITY: frozenset[str] = frozenset({
    "Routing daemon activity", "Chassis daemon activity", "Forwarding daemon activity",
    "SNMP daemon/trap activity", "Alarm set/clear event", "Process lifecycle event",
    "inetd service activity", "EOS agent/process activity", "LLDP neighbor change",
})
# BGP keyword rules that are blind to direction; the parsed state may flip them.
_BGP_DOWN_DESCRIPTIONS: frozenset[str] = frozenset({
    "BGP peer down / connect failure", "BGP peer idle / notification",
    "BGP notification / adjacency down (FRR/IOS)",
})


_ADMIN_DOWN_RE = re.compile(r"administratively|admin[- ]down|\bshut(?:down)?\b")


def _state_verdict(event_type: str, state: str, sev: str, desc: str, text: str) -> tuple[str, str, str] | None:
    """Verdict implied by a parsed (event_type, state), or None to keep the rule match."""
    target = _STATE_VERDICTS.get((event_type, state))
    if target is None:
        return None
    # An operator shutting a port is intent, not a fault: the parser reads "administratively down" as down.
    if event_type == "interface_link" and state == "down" and _ADMIN_DOWN_RE.search(text):
        return None
    if not desc or (sev == "low" and desc in _GENERIC_ACTIVITY):
        return target
    if event_type == "bgp_session":
        if state == "down" and desc == "BGP peer established":
            return target
        if state == "up" and desc in _BGP_DOWN_DESCRIPTIONS:
            return target
    return None


def iter_classify(events: Iterable[LogEvent]) -> Iterator[ClassifiedEvent]:
    """Classify a stream of LogEvents lazily, one at a time.

    Pure streaming: no sorting, no counting, O(1) memory regardless of input
    size. Building block for analyze()'s single-pass aggregation; use
    classify_events() when you need the sorted list + counters.
    """
    from ai_log_analyzer.parsers import ensure_structured

    for ev in events:
        # Events from API connectors (Kibana, Splunk, …) arrive as raw text;
        # give them the same entity extraction the file/syslog parsers do.
        ev = ensure_structured(ev)
        # Strip ANSI escapes once at the boundary — catches systemd green-OK
        # markers, FRR vtysh color codes, and any colorized adapter output.
        clean_message = strip_ansi(ev.message)
        combined = f"{ev.appname} {clean_message}".lower()
        kb_text = _bound_for_kb(combined)
        sev, cat, desc = "info", "other", ""
        confidence = 0.9
        authoritative = False

        if type(ev) is LogEvent:
            vendor, event_type, interface, peer_ip = ev.vendor, ev.event_type, ev.interface, ev.peer_ip
            asn, vrf, vni, tunnel_id, vendor_action = ev.asn, ev.vrf, ev.vni, ev.tunnel_id, ev.action
            state, norm_ts, attrs = ev.state, ev.normalized_utc_ts, ev.attrs
        else:  # duck-typed events from third-party adapters
            vendor, event_type, interface, peer_ip, asn, vrf, vni, tunnel_id, vendor_action, state, norm_ts = (
                getattr(ev, f, "") for f in ("vendor", "event_type", "interface", "peer_ip", "asn", "vrf",
                                             "vni", "tunnel_id", "action", "state", "normalized_utc_ts"))
            attrs = getattr(ev, "attrs", None) or {}

        # Custom user rules take precedence over the built-in KB.
        for pattern, p_sev, p_cat, p_desc in _CUSTOM_RULES:
            try:
                matched = pattern.search(
                    combined, timeout=_CUSTOM_REGEX_TIMEOUT_SECONDS
                )
            except TimeoutError:
                # Treat pathological rules as non-matches rather than letting
                # attacker-controlled log text monopolize a worker.
                matched = None
            if matched:
                sev, cat, desc = p_sev, p_cat, p_desc
                confidence = 1.0
                break

        if not desc:
            # re.IGNORECASE has additional Unicode matches that plain lowercase
            # substring checks do not, so only use the literal gate for ASCII.
            # No keyword → only the unproven patterns can possibly match (their
            # relative order is preserved, so precedence holds).
            candidates = _COMPILED if not kb_text.isascii() else _gated_candidates(kb_text)
            for pattern, p_sev, p_cat, p_desc in candidates:
                if pattern.search(kb_text):
                    sev, cat, desc = p_sev, p_cat, p_desc
                    authoritative = id(pattern) in _AUTHORITATIVE
                    break

        # The parser's (event_type, state) is the direction of record: it fixes a state-blind
        # keyword verdict and classifies events no rule matched. Custom rules are never overridden.
        if confidence != 1.0 and not authoritative and state in ("up", "down"):
            derived = _state_verdict(event_type, state, sev, desc, kb_text)
            if derived:
                sev, cat, desc = derived
                confidence = 0.7

        if not desc:
            snippet = clean_message[:120].strip() or ev.appname or "General log message"
            desc = snippet
            confidence = 0.3

        # Promote raw severity if syslog says critical but classifier missed it
        if ev.severity_raw.lower() in ("crit", "emerg", "alert") and sev == "info":
            sev = "high"
            confidence = 0.6

        yield ClassifiedEvent(
            timestamp=ev.timestamp,
            hostname=short_host(ev.hostname, fold=False),
            appname=ev.appname,
            severity=sev,
            severity_raw=ev.severity_raw,
            category=cat,
            description=desc,
            action=_action_for(sev, cat),
            message=clean_message[:500],
            sample_message=clean_message[:200],
            confidence=confidence,
            vendor=vendor,
            event_type=event_type,
            interface=interface,
            peer_ip=peer_ip,
            asn=asn,
            vrf=vrf,
            vni=vni,
            tunnel_id=tunnel_id,
            vendor_action=vendor_action,
            state=state,
            normalized_utc_ts=norm_ts,
            attrs=attrs,
        )


def _time_sort_key(ev: ClassifiedEvent) -> tuple[str, str]:
    """(UTC ISO stamp, raw fallback): unparseable stamps sort oldest, then lexicographically."""
    from ai_log_analyzer.parsers.timeutil import normalize_ts

    norm = ev.normalized_utc_ts or normalize_ts(ev.timestamp)[0]
    return (norm, "" if norm else ev.timestamp)


def classify_events(events: Iterable[LogEvent]) -> tuple[list[ClassifiedEvent], dict[str, int], dict[str, int]]:
    """Classify a stream of LogEvents.

    Returns: (sorted classified events, severity_counts, category_counts).
    Sort order: critical → high → medium → low → info, then by timestamp desc.

    Materializes the full list — fine for bounded inputs (API fetches, lab
    logs). For huge files, analyze() streams via iter_classify() instead.
    """
    classified: list[ClassifiedEvent] = []
    sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    cat_counts: dict[str, int] = {}

    for ce in iter_classify(events):
        classified.append(ce)
        sev_counts[ce.severity] = sev_counts.get(ce.severity, 0) + 1
        cat_counts[ce.category] = cat_counts.get(ce.category, 0) + 1

    # Stable sort: pass 1 sorts newest first; pass 2 buckets by severity. The time key is the
    # parser's UTC-normalized stamp, so ISO, RFC 3164 and PAN-OS stamps order against each other.
    classified.sort(key=_time_sort_key, reverse=True)
    classified.sort(key=lambda e: SEV_ORDER.get(e.severity, 5))
    return classified, sev_counts, cat_counts
