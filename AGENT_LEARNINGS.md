# AGENT_LEARNINGS.md

Repo-only lessons for netlog-ai. Cross-repo lessons stay in `~/.cursor/AGENT_LEARNINGS.md`.

## Entries

### [2026-09-25] [env] The src-layout .env path was already the repo root
- **Mistake:** Replacing `pkg_dir.parent.parent` with `pkg_dir.parents[1]` and treating it as the reason `.env` did not load.
- **Avoid:** Committing that edit. Both expressions resolve to the repo root (`/Users/georgigaydarov/Projects/netlog-ai`).
- **Instead:** Check the serve process. `ps eww -p <listener>` must show `AI_LOG_ANALYZER_INCIDENT_STORE`. A `.env` on disk does nothing for a process that started without it.

### [2026-09-25] [journal] No action items means nothing is stored
- **Mistake:** Two analyzes of `de-fra-core-01` with tail 40 left `incidents.jsonl` unchanged and the brief had no `Repeat:` line.
- **Avoid:** Treating a score of 100 as proof the journal ran. That tail had 34 events and 0 action items, so `record()` returned 0.
- **Instead:** Use tail 500 on `de-fra-core-01`. A ranked BGP peer-down item is what gets appended. The second run in 7 days prints `Repeat: de-fra-core-01 routing N times in 7 days`. July rows stay outside the window.

### [2026-09-25] [journal] Fixture proof rows stay out of the live journal
- **Mistake:** Posting the five test-suite lines (AP down, 802.1X, DHCP, WAN failover, VPN) through the live `/api/analyze` appended them to `~/.cache/netlog-ai/incidents.jsonl`.
- **Avoid:** Leaving those hosts in the 7-day window.
- **Instead:** Snapshot the file, run the proof, then write the previous lines back. Say in the reply that the lines were fixtures, not a router log.

### [2026-09-25] [syslog] The Listen button binds on source create
- **Mistake:** Expecting the button label alone to open UDP 5514.
- **Avoid:** Stopping after the toast text.
- **Instead:** `POST /api/sources` with `type: syslog` and `extra.port: 5514` binds immediately (`SyslogListenerSource.__init__`). Confirm with `lsof -nP -iUDP:5514` and `POST /api/sources/lab-syslog/test` returning `{"ok":true}`.

### [2026-09-25] [serve] Exit 143 is the previous UI
- **Mistake:** Reading exit 143 on an old `ai_log_analyzer.cli serve` as a crash of the current UI.
- **Avoid:** Restarting again because a killed process reported 143.
- **Instead:** `curl -sS http://127.0.0.1:6060/api/health`. Version `1.1.1` and `"ok":true` means the replacement is up. Interpreter is `.venv/bin/python3.14`, not `.venv/bin/python`.

### [2026-10-13] [dedup] Drain-Style Pre-LLM Log Deduplication (`dedup.py`)
- **Pattern:** Mask variable tokens (IPv4/IPv6, MAC, ASN, interfaces, numbers, hex, PIDs) into canonical placeholders (`<IP>`, `<MAC>`, `<INTF>`), then cluster logs via a fixed-depth parse tree using token-count and similarity thresholds.
- **Gotcha:** Sample logs from Arista EOS, Juniper Junos, Cisco, and FRR contain leading syslog priority tags (`<134>`), Cisco sequence prefixes (`004122:`), or leading asterisks (`*Oct 13`), which break standard timestamp/hostname regexes if not explicitly matched.
- **Solution:** Reconciled `_SYSLOG_HEADER_RE = re.compile(r"^(?:<\d+>(?:\d+\s+)?)?(?:\d+:\s+)?\*?(?P<ts>...)\s+(?P<host>...)\s+(?P<body>.*)$")`. Emits compressed `[DEDUP xN] <template>` lines to LLM prompts, achieving 90%+ prompt token savings during syslog storms while keeping memory strictly bounded.

### [2026-10-13] [sanitize] Reversible Token Vault for EVPN Type-2 Routes (`sanitize_vault.py`)
- **Pattern:** `SanitizeVault` provides stateful, bidirectional anonymization (`anonymize()` / `deanonymize()`) using deterministic SHA-256 tokens (`HOST-xxxx`, `IPV4-xxxx`, `IPV6-xxxx`, `MAC-xxxx`, `ASN-xxxx`).
- **Gotcha:** Standard IP sanitizers only redact IPv4 and ignore IPv6 or MAC addresses. In EVPN-VXLAN environments, Type-2 route log lines heavily leak customer MAC addresses and IPv6 link-local addresses to external LLMs.
- **Solution:** Integrated regex tokenizers `_IPV6_RE` and `_MAC_RE` (covering colon `00:11:22:33:44:55`, dash `00-11-22-33-44-55`, and Cisco dot `0011.2233.4455` formats) directly into `SanitizeVault.anonymize()`, ensuring EVPN control-plane dumps are sanitized before LLM ingestion.

### [2026-10-13] [netbox] NetBox v4.x Cable Termination Guardrails (`sources/netbox.py`)
- **Pattern:** `build_site_manifest()` queries the NetBox REST API via stdlib `urllib` to dynamically build site topology manifests (`devices` + `cables` adjacency).
- **Gotcha:** In NetBox v4.x, cable terminations can attach to `dcim.frontport`, `dcim.rearport` (patch panels), or `circuits.circuittermination` where the termination object's `device` attribute is `None`. Accessing `term["device"]["name"]` raises an unhandled `AttributeError`.
- **Solution:** Explicit guard: `if not isinstance(dev_obj, dict) or not dev_obj.get("name"): continue`. Skips non-device hops gracefully, allowing multi-hop patch panel cabling to resolve without crashing site discovery.

### [2026-10-13] [causality] 5-Layer CLOS Bipartite Causal Engine (`evpn_causal.py`)
- **Pattern:** Multi-layer network root-cause inference requires strict hierarchical ordering: `L1_PHYSICAL (1) -> L2_LAG_MLAG (2) -> L3_UNDERLAY (3) -> L4_VTEP_NVE (4) -> L5_OVERLAY_EVPN (5)`.
- **Gotcha:** Fabric link flaps cause simultaneous bursts of underlay IGP/BFD drops, VTEP reachability drops, and thousands of EVPN Type-2/Type-5 route withdrawals across all leafs. Treating every syslog event as an independent incident floods NOC queues with secondary symptoms.
- **Solution:** `EVPNBipartiteCausalEngine` correlates events inside a 120s sliding window with 2-hop topological coupling. When a lower-layer event (e.g., L1 physical loss or L3 underlay BFD drop) occurs on a node or adjacent spine, all downstream L4 VTEP and L5 EVPN symptoms are suppressed, directly naming the physical/underlay root cause.

### [2026-10-13] [telemetry] Optical DOM vs. Output Queue Congestion Interlocking (`sources/telemetry.py`)
- **Pattern:** Telemetry interlocking correlates physical optical transceiver diagnostics (DOM/DDM Rx dBm) with hardware error counters (FCS/CRC) and output queue discards.
- **Gotcha:** Both optical degradation and control-plane buffer microbursts manifest in syslog as BFD timeouts and BGP adjacency loss. Blindly bouncing interfaces during microburst congestion worsens buffer overflow.
- **Solution:** `TelemetryCorrelator` applies a deterministic decision matrix:
  1. Low Rx dBm (< -15 dBm) + rising FCS/CRC errors = **Optical Degradation** (clean ferrule, replace SFP).
  2. Hard Rx LOS (< -40 dBm) + 0 CRC delta = **Dark-Fiber Cut / Remote Admin Shutdown**.
  3. Healthy optics (> -10 dBm) + 0 CRC + rising egress queue discards = **Control-Plane Microburst Congestion** (requires QoS strict-priority Queue 6/7 or CoPP rate boost, not physical cable work).

### [2026-10-14] [remediation] Multi-Vendor Rollback Guardrails & Timer Caps (`remediation.py`)
- **Pattern:** Network remediation change plans must be transactional and self-reverting to protect remote management access in the event of misconfiguration.
- **Gotcha:** Different network OSes have completely different rollback paradigms: Junos uses `commit confirmed <min>`, Arista EOS uses `configure session ... commit timer <min>`, Cisco NX-OS uses rollback checkpoints, Cisco IOS-XE uses `configure terminal revert timer <min>`, and FRR uses `vtysh -c 'copy running startup'`. A single generic template causes syntax failures.
- **Solution:** `RemediationGenerator` models vendor-specific transactional sequences with mandatory pre-checks, timed commit blocks, verification checks, and explicit manual rollback blocks. Enforces `SafetyGuardrail`: blocks destructive regexes (`write erase`, `zeroize`, `reload`, `no router bgp`, `delete`) and strictly clamps auto-revert timers between 1 and 30 minutes.

### [2026-10-14] [itsm] Deterministic SHA-256 Incident Fingerprinting (`itsm.py`)
- **Pattern:** Closed-loop ITSM incident management requires idempotent correlation between automated log analysis and ticketing systems (Jira Service Management, ServiceNow).
- **Gotcha:** Dynamic syslog timestamps and per-device hostname differences cause naive integrations to create hundreds of duplicate tickets during a single network outage.
- **Solution:** `generate_incident_fingerprint(fabric_or_site, root_cause_type, affected_entities)` generates a deterministic key `NETLOG-<SHA256>`. `enrich_incident()` uses this fingerprint as the Jira custom field or ServiceNow correlation ID: if an incident with the fingerprint already exists, it updates the work notes and remediation plan; otherwise, it creates a new ticket.
