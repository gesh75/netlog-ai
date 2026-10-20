# Parsers, canonical schema, and cross-vendor correlation

netlog-ai turns every log line into a canonical `LogEvent` with structured
entity fields. Downstream state pairing, BGP anomaly detection and
cross-vendor correlation join events on those fields, not on hostnames.

## Canonical schema

`LogEvent(timestamp, hostname, appname, severity_raw, message)` is unchanged,
and every existing caller keeps working. Parsers add these optional fields
(`""` means unknown):

| Field | Meaning | Example |
|---|---|---|
| `vendor` | Source platform | `fortinet`, `paloalto`, `cisco_sdwan`, `juniper`, `arista`, `cisco_ios`, `cisco_nxos`, `frr`, `sonic`, `cumulus`, `nokia_srl` |
| `event_type` | What the line is about | `bgp_session`, `bgp_max_prefix`, `bgp_path_change`, `ipsec_tunnel`, `ike_phase1`, `ike_phase2`, `sdwan_sla`, `bfd_session`, `omp_peer`, `control_connection`, `interface_link`, `lag_member`, `ospf_adjacency`, `ha_state`, `conserve_mode`, `session_table`, `traffic`, `threat`, `vpn_auth`, `evpn`, `config_change` |
| `interface` | Device-local interface | `wan1`, `xe-0/0/1`, `Ethernet12`, `ethernet1/1` |
| `peer_ip` | Remote end (BGP neighbor, IPsec peer, BFD/OMP peer) | `169.254.10.2` |
| `asn` | Peer AS | `65010` |
| `vrf` | VRF / routing instance (`master` → `default`) | `default` |
| `vni` | VXLAN VNI | `10010` |
| `tunnel_id` | VPN tunnel / SD-WAN TLOC pair / controller | `HQ-DC1`, `biz-internet->mpls@10.255.0.11` |
| `action` | Vendor action verb (`ClassifiedEvent.vendor_action`) | `tunnel-down`, `drop` |
| `state` | `down` / `up` — drives recovery pairing | `down` |
| `normalized_utc_ts` | ISO-8601 UTC | `2026-10-20T07:01:02Z` |

`attrs` carries vendor extras such as `remip`, `locip`, `healthcheck`,
`eventid`, `flap_reason`, `system_ip`, `local_ip`, `vdom` and `parser`. If a
timestamp carried no offset (RFC 3164, PAN-OS), it is treated as UTC and
marked `attrs["tz_assumed"] = "utc"`. Run devices on UTC, or widen the
correlation window to absorb the skew.

## Parser registry

`ai_log_analyzer.parsers.registry` tries plugins in priority order:

| Priority | Plugin | Claims |
|---|---|---|
| 10 | `fortios` | FortiOS `key=value` logs (`devname=` + `logid=`/`type=`), bare, behind PRI, or behind an rsyslog relay header |
| 20 | `panos` | PAN-OS CSV: SYSTEM (routing / vpn / ha / globalprotect …), TRAFFIC, THREAT, GLOBALPROTECT |
| 30 | `cisco_sdwan` | `%Viptela-…` / `%Cisco-SDWAN-…` messages and `bfd-` / `omp-peer-` / `control-connection-state-change` notifications |
| 50 | `syslog` | RFC 5424 / RFC 3164 / Junos envelopes. Legacy fields are byte-identical to the old parser, plus NOS entity enrichment |
| 60 | `securecrt` | SecureCRT session recordings |
| 1000 | `fallback` | Anything else (whole line as message, still enriched) |

Add a parser with `registry.register(MyParser())`. A plugin returns a
`LogEvent` (claimed), `None` (try the next plugin) or `SKIP` (drop the line).

Events built outside the registry go through `parsers.ensure_structured()`
inside the classifier. These come from API connectors such as Kibana, Splunk
and Loki. A raw FortiGate or PAN-OS line inside a Splunk hit is parsed by the
vendor plugin, and the connector's own hostname and timestamp are kept.

**Privacy at parse time:** FortiOS `user`/`xauthuser`/`group` and the device
serial are never copied into the message. PAN-OS `User name:` values are
replaced with `<redacted>`. GLOBALPROTECT logs keep only the event ID and the
outcome.

## Down → up state pairing

`entity_state.EntityStateTracker` keys each event on its entity: host plus BGP
peer, interface, tunnel, SLA, BFD, OMP or control connection. Each entity gets
one of these statuses:

* `active`: the last transition is down.
* `recovered`: down, then a matching up. `outage_seconds` gives the length.
* `flapping`: at least `AI_LOG_ANALYZER_FLAP_THRESHOLD` (3) downs within
  `AI_LOG_ANALYZER_FLAP_WINDOW_S` (600 s).

Each action item carries a `state` and an `entity_states` breakdown. Within
the same severity, active items rank above flapping ones, and flapping above
recovered ones, so the LLM budget goes to live outages first.

## BGP anomalies (`bgp_anomaly.py`)

`AnalysisResult.bgp_anomalies` provides:

* NOTIFICATION code and subcode decoding (RFC 4271, RFC 4486 Cease subcodes).
* RFC 8203 shutdown communications.
* A `planned` flag that separates administrative Cease from failures.
* Max-prefix warning vs. exceeded, with received and limit counts.
* Origin AS / AS-path changes, with prefix and old/new origin or path.
* Per-peer flapping, plus a fabric-wide `route_flap_storm` when 3 or more peers flap.

## Cross-vendor correlation (`correlate.correlate_entities`)

Failure events are joined when they share one of these entity keys within
300 s:

* **IP address:** `peer_ip`, or `remip`/`locip`/`local_ip`/TLOC IPs from `attrs`.
* **/30 or /31 subnet:** for BGP/OSPF session peers only, so both ends of a
  point-to-point session match.
* **Device interface.**
* **Device tunnel.**

Events on the same device also join within 60 s. A transport → routing step on
one device is allowed up to 240 s, because a hold timer expires after the
tunnel under it dies.

Each incident lists:

* the **root**: the lowest layer (platform → physical → transport → routing → overlay), then the earliest event;
* the chain of events;
* the devices and vendors involved;
* the evidence keys;
* a confidence rating. `high` means at least one entity join and the root came first.

## Fixtures

`tests/fixtures/multivendor/*.log` are representative lines modeled on each
vendor's documented syslog format (FortiOS 7.x key=value, PAN-OS syslog field
positions, Viptela notification form). They are not captures from a
production network. Validate the parsers against your own devices' logs
before relying on them, especially PAN-OS GLOBALPROTECT layouts, which vary by
release.
