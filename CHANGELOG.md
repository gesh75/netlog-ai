# Changelog

All notable changes to **netlog-ai** are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); this project uses
loose semantic versioning.

## [Unreleased]

Security, privacy, reliability and correctness hardening from a full code review (see the PR for the
per-finding evidence). **Several defaults are now fail-closed**; see *Changed (breaking)*.

### Security
- **Sanitizer:** every secret format found leaking through the LLM gateway is now redacted: `password 0|7 X` (the digit stays, the secret goes), `enable password|secret`, `username … secret 5|8|9|sha512`, OSPF/IS-IS authentication and message-digest keys, TACACS/RADIUS keys, `crypto isakmp key`, Junos pre-shared keys, SNMP communities in `snmp-server host`, `key-string`, Bearer/Basic headers, `api_key=`/`token=`/`password=` pairs, URL credentials, cloud/API tokens, JWTs, bare crypt hashes and PEM/PGP blocks (including truncated ones). `sanitize()` runs to a fixed point, so it is idempotent, and every rule is ReDoS-safe.
- **Pseudonyms** (`PUB-…`, `user-…`) are HMAC-SHA256 with a per-process key (`AI_LOG_ANALYZER_PSEUDONYM_KEY` for stable tokens) instead of an unsalted 32-bit hash that could be brute-forced.
- **Credential forwarding:** ITSM clients refuse to send server-held credentials to a URL other than the configured one, require `https://`, reject `file://`/`ftp://`, and never follow redirects on authenticated requests.
- **SSRF guard** resolves hostnames and checks every address (loopback, link-local, metadata, CGNAT, private, IPv4-mapped IPv6), normalises `127.1`/`2130706433`/`0x7f.0.0.1`, fails closed, and is applied to every connector. `allow_private` can no longer be set from a request body or MCP `extra`.
- **Remediation:** the command guardrail normalises case, whitespace, `do`/`sudo` and IOS-style abbreviations (`rel`, `wr er`, `cle ip bgp *`, `request vmhost reboot`, `init 6`, `erase /all nvram:` …); device, interface and neighbor inputs are validated; generated Nornir/Ansible files cannot be injected through device names or rationale text; pre/post checks are screened and limited to read-only verbs.
- **MCP server:** write tools are gated behind `NETLOG_MCP_ALLOW_WRITE`; HTTP transports require a bearer token; outputs are sanitized; `search_logs` uses a time-limited regex; list sizes are bounded; tool calls are audited; `list_sources` no longer returns connector option values.
- **Web:** the Docker image is non-root and fail-closed; file analysis is confined to `/var/log` plus `AI_LOG_ANALYZER_DATA_DIR`, with dotfiles and credential files always denied and responses sanitized; every previously open GET route requires a viewer token; `/api/postmortem` regexes are time-limited; Host-header allow-list (DNS-rebinding defense) while auth is off; request size limit; `nosniff`/`DENY`/`no-referrer` headers; rate-limited audit of failed logins; at most `AI_LOG_ANALYZER_MAX_SSE` live streams.
- **Release pipeline** runs the CI workflow, asserts the tag equals the package version, runs `twine check` and a clean-venv wheel smoke test before anything is published. CodeQL, Dependabot and `SECURITY.md` are new.

### Fixed
- **Ingest:** the triage worker drains backlogs instead of reading 5,000 rows per 15 s, and counts rows the spool pruned before triage read them (`gap_rows`); spool pruning is O(excess); `load_from_env()` no longer rebuilds live listeners (and drops their buffered lines) on every request; only "address in use" makes a listener a reader; UDP drops are counted (`SO_RXQ_OVFL`) and spool writes moved off the event loop; failed flushes re-queue instead of dropping; a TCP line starting with `<digits><space>` is no longer read as an octet count.
- **Triage:** cursors commit after delivery, pending deliveries survive a crash, per-sink backoff and circuit breaker, partial multi-sink failure is retried, critical incidents are sent first, repeats no longer hide an ongoing incident, send times persist across restarts, the lease is checked between candidates.
- **Parsing:** asdot ASNs are no longer truncated (`1.10` and `1.20` previously joined as AS `1`); rsyslog ISO, SONiC microsecond, PRI-prefixed IOS/NX-OS and IOS-XR framings parse with host, time and vendor; IS-IS and OSPF `ADJCHANGE` are no longer labelled BGP; CLI-audit lines are no longer incidents; JSON, CEF and LEEF lines are parsed; NX-OS/FRR/PAN-OS/IOS-XR peer and VRF forms; New Year and Feb 29 timestamps.
- **Classification:** state-aware BGP severity (`Established → Idle` is a failure); built-in regexes are bounded (an 11.6 KB line took 13.6 s, now under 1 s); known-down interface/LAG/IPsec/IS-IS/LDP events no longer stay at info; new rules for STP guards, CPU/memory, restarts, AAA, SRX HA, PSU/alarm severity, optics, `sshd` brute force; 14 new playbooks so every incident category gets one.
- **Correlation:** IP-addressed devices are no longer merged into host `10`; suppression requires a shared entity and one root rule is used by both engines; order-independent clustering; confidence is capped at *medium* when clusters are bridged only by same-device timing; transit-AS clusters are rooted at the shared AS instead of an arbitrary device; the 2,000-event pool is deduplicated and warns when it truncates; the health score counts distinct active entities; flaps are per entity; `cause_of` needs the same host or a shared entity.
- **Performance:** suppression 3.1 s → 0.09 s at 2,000 events; topology inference 79 s → 0.1 s at 120 devices; RFC 3164 timestamp parsing 5× faster.
- **Remediation wording:** only Junos, IOS-XE and EOS claim an automatic revert; the exports gate the confirm step on a post-check assertion (or an operator prompt) instead of confirming unconditionally.
- **LLM gateway** never raises on malformed provider replies, has an overall deadline (`LLM_TOTAL_TIMEOUT_S`) and a per-provider circuit breaker; an off-host `OLLAMA_URL` is reported as `remote-host` instead of "local only".
- **Connectors:** ServiceNow change queries (reference-field match, `^` escaping, newest first, `active=true`), SolarWinds fair per-stream cap and ordering, Loki truncation flag, Jira label sanitising, NetBox errors no longer reported as "not found", host-filter injection.
- **RAG:** citations keep original line numbers; changed site files are re-indexed automatically; same host in different sites no longer collides.
- **CLI:** `analyze --remediation` derives vendor and interface from the events; clean exit 2 on usage errors; `--version`; new `doctor` command.

### Changed (breaking)
- The Docker image and compose refuse to start without `AI_LOG_ANALYZER_API_TOKEN`/RBAC tokens; compose publishes on `127.0.0.1` only and mounts the Docker socket only in the `lab` profile. RBAC tokens under 16 characters are refused. A non-loopback `python -m` bind without a token exits unless `AI_LOG_ANALYZER_ALLOW_NOAUTH=1`.
- Default file-analysis roots shrink to `/var/log` (+ `AI_LOG_ANALYZER_DATA_DIR`).
- Connectors refuse private, loopback and unresolvable hosts unless the URL is operator-configured or `NETLOG_ALLOW_PRIVATE_OUTBOUND=1`; ServiceNow/Jira clients require `https://` (`NETLOG_ALLOW_INSECURE_HTTP=1`).
- MCP write tools are off by default (`NETLOG_MCP_ALLOW_WRITE=1`).
- Remediation exports without an assertable post-check require an interactive `yes`; non-interactive runs roll back. Custom plans reject non-read-only checks. `RemediationPlan.to_dict()` gains `interface` and `bgp_neighbor_ip`.
- `DOCKER_EXEC_FALLBACK` defaults to `false`.
- `/api/postmortem` returns 400 for invalid input.
- Fewer events are suppressed, some incidents drop from *high* to *medium* confidence, and the health score is lower for noisy runs.
- Pseudonym tokens differ per worker and restart unless `AI_LOG_ANALYZER_PSEUDONYM_KEY` is set.

### Added
- `docs/ENVIRONMENT.md` (every environment variable, enforced by a test), `SECURITY.md`, `CODEOWNERS`, Dependabot, CodeQL, issue and PR templates, a mypy baseline and `py.typed`, Python 3.13 classifier.
- Dashboard: triage backlog and loss signals (spool rows lost, pending deliveries, open sink circuits, UDP drops) and a "Remote LLM host" egress label.
- New event types `isis_adjacency` and `ldp_session`; `netlog-ai doctor`; `hostnames.short_host`.
- Incident output: `device_count`, `warning`, `collapsed`, `flapping_entity_id`, `external_as`/`shared_vrf` roots.

### Known limitations
- FQDN short-naming is unchanged: `edge1.dc1.example.com` and `edge1.dc2.example.com` still share `edge1`.
- Content-Security-Policy and subresource-integrity hashes for the mermaid CDN script are not set (the UI relies on inline styles; no vendored copy to hash).
- Jira find-then-create can still duplicate under search-index lag; a local idempotency record owned by the caller is the real fix.
- The `requests`-based connectors re-validate redirects but have no connect-time address re-check (a DNS-rebinding window remains there).
- A tunnel failure followed within 240 s by an unrelated BGP drop on the same device is still suppressed as a child of the tunnel failure (the BGP hold timer can legitimately take that long, and logs alone cannot tell the two apart).
- Suppression's /31 peer-ownership guess is unchanged (not derivable from logs alone).

## [2.1.0] - 2026-10-20

### Added
- **ASN and VRF entity correlation.** `correlate_entities` now joins failures across devices that drop sessions to the same external / origin AS (`shared_asn`) or fail in the same tenant VRF (`same_vrf`) inside the correlation window, so for example a transit outage that takes down eBGP on Junos, EOS and PAN-OS edges becomes one incident. Incidents carry a `shared` block (`{"asn": [...], "vrf": [...]}`), and the summary names the shared AS / VRF. The dashboard shows ASN / VRF entity chips.
- **Noise guardrails for those joins:**
  - ASNs join only on active routing / transport failures. Recoveries do not join on them.
  - iBGP sessions, the local AS (learned from iBGP lines in the batch) and reserved ASNs (0, 23456, 65535, 4294967295) are never join keys.
  - ASN spellings (`AS65010`, asdot `1.10`) are normalized first.
  - Default-like tables (`default`, `global`, `main`, `0`, `root`, `mgmt`, `master`, `inet.0` and similar) never group events on their own. They join only when paired with the same external AS on an active routing failure.
  - ASN / VRF evidence is not "strong", so an ASN- or VRF-only incident stays `medium` confidence.

## [2.0.0] - 2026-10-20

**netlog-ai V2.** This release builds a sanitize-first, multi-vendor, evidence-cited network operations platform on top of 1.x, in five milestones:

| # | Milestone | PR |
|---|---|---|
| 1 | **LLM gateway & reversible vault.** One `llm.query()` boundary for every call: secret/PII redaction, then per-incident reversible tokens (`<IP_n>`, `<HOST_n>`, `<ASN_n>`), per-provider budgets, retry/backoff and no silent cloud egress. The SafetyGuardrail screens all model-generated CLI. | [#57](https://github.com/gesh75/netlog-ai/pull/57) |
| 2 | **Multi-vendor security & SD-WAN.** FortiOS, PAN-OS and Catalyst SD-WAN parsers on a pluggable registry with a canonical event schema; down → up pairing; BGP anomaly detection; cross-vendor correlation. | [#58](https://github.com/gesh75/netlog-ai/pull/58) |
| 3 | **Durable ingest & automation.** Multi-worker TCP/TLS syslog into a SQLite WAL spool; topology-aware suppression; Ansible (check mode, guarded apply, rollback) and Nornir export. | [#59](https://github.com/gesh75/netlog-ai/pull/59) via [#60](https://github.com/gesh75/netlog-ai/pull/60) |
| 4 | **Evidence, triage, RBAC & evaluation.** Local BM25 retrieval with `[S#]` citations (configs, golden drift, NetBox, runbooks, resolved incidents); streaming triage worker with ticket-storm controls; viewer / operator / admin roles; append-only hash-chained audit log; golden-incident regression harness. | [#61](https://github.com/gesh75/netlog-ai/pull/61) |
| 5 | **V2 dashboard.** Role-token sign-in, live status bar (spool, triage, LLM egress, vault), root-cause incident cards, CLI / Ansible / Nornir remediation tabs with ⛔ guardrail flags, clickable citations, audit-log viewer. | [#62](https://github.com/gesh75/netlog-ai/pull/62) |

**Supported vendors:**
- **Fully supported:** Cisco IOS-XE, NX-OS and Catalyst SD-WAN; Juniper Junos; Arista EOS; Fortinet FortiOS; Palo Alto PAN-OS; FRR. These have parsing, remediation plans and automation export where the platform allows it; SD-WAN changes go through vManage.
- **Parsing and classification only:** Nokia SR Linux, SONiC and Cumulus.

**Upgrading from 1.x**
- **Cloud fallback is now opt-in.** `ollama` / `local` no longer fall back to Claude or Grok. Set `ALLOW_CLOUD_FALLBACK=true` to restore it.
- **API token maps to admin.** `AI_LOG_ANALYZER_API_TOKEN` maps to the `admin` role, so existing integrations keep full access. Add `AI_LOG_ANALYZER_{VIEWER,OPERATOR}_TOKENS` to narrow access. With RBAC on, the dashboard asks for a token via the 👤 chip.
- **Syslog hostnames:** header-less syslog lines are attributed to their sender IP instead of the literal `syslog`.
- **Shared state DB recommended.** Set `AI_LOG_ANALYZER_STATE_DB` for multi-worker deployments. It also enables the durable spool, incident memory with stable `INC-` IDs, retrieval evidence, the audit log and the triage worker.
- **Evidence retrieval cost.** Analyses retrieve evidence when a state or RAG DB is configured, adding about 25 ms per playbook. Set `AI_LOG_ANALYZER_RAG=0` to turn it off.
- **Classifier change:** `VXLAN_TUNNEL_DOWN` / VTEP-down lines are classified as `evpn` (were "VPN/IPsec tunnel failure").

**Verification:**
- **Tests:** 901 tests pass on Python 3.10, 3.11 and 3.12.
- **Eval harness:** `ai-log-analyzer eval --golden` scores 1.00 on RCA accuracy, de-tokenization, guardrail compliance and evidence across the four labeled incidents (EVPN underlay cascade, BGP route leak + flap, FortiGate SD-WAN/IPsec cascade, PAN-OS HA failover).

### Added — V2 dashboard

- **API-token sign-in.** The UI now works on RBAC deployments: a 👤 chip next to the brand takes a viewer / operator / admin token. The token is kept in `sessionStorage` and sent as `Authorization: Bearer` on every `/api/*` call, or as `?token=` for the SSE live tail. Before this, the dashboard could not call protected routes once tokens were configured.
- **Header status bar** from the new `GET /api/status/overview` (viewer). One cheap poll every 10 s, with no provider probing, shows:
  - spool depth and age per source, plus listener counters;
  - the streaming triage worker's role and ticket count;
  - the LLM egress policy: 🔒 *Local only · no cloud fallback*, ☁ *Cloud fallback enabled* or ☁ *Cloud: provider*;
  - vault stats from the last call: entities tokenized and secrets redacted.
- **Remediation card.** Remediations can be viewed as Vendor CLI, Ansible playbook (YAML) or Nornir script tabs, each with download and copy.
  - Badges mark the check-mode dry run and the rollback timer.
  - The panel gains an interface field and FortiOS / PAN-OS / SD-WAN vendors.
  - Exports a vendor cannot support show the reason, for example SD-WAN → vManage.
- **SafetyGuardrail highlighting.** `# BLOCKED` lines carry a ⛔ GUARDRAIL badge wherever CLI is shown.
  - Platforms whose command was withheld are marked in the selector, and their ▶ Run button is disabled.
  - Playbooks list the withheld commands and the rules that caught them.
- **Vendor and event-type badges** (FortiOS, PAN-OS, SD-WAN, Junos, EOS, IOS-XE, NX-OS, FRR, …; SLA, IPsec, IKE P1/P2, HA, BGP, BFD, OMP, …) on event rows and incident cards.
- **Root-cause incident cards** for every topology-suppression root and every uncovered cross-vendor correlation cluster.
  - Cards show the shared peer IPs, ASNs, tunnels, VRFs, point-to-point subnets and interfaces, with a collapsible table of suppressed downstream alerts.
  - Suppressed action items are hidden behind a toggle and link back to their root.
  - A "Guarded plan for this link" button prefills the remediation panel.
- **RAG evidence.** Playbooks and Copilot answers render `[S#]` as links that open the matching evidence: config stanza with line numbers, drift with green/red ± lines, NetBox topology, KB runbook, or past incident with its resolution.
  - Invented citations are struck through and flagged unverified.
  - Copilot `host Lnn` references are checked against the config that was sent.
- **Audit log panel** for admins (and dev mode with an audit store): filter by actor or action, verify the hash chain.

### Added — evidence-grounded RCA, streaming triage, RBAC and evaluation

- **Retrieval index** (`rag.py`): zero-dependency BM25 over SQLite (`AI_LOG_ANALYZER_RAG_DB`, default the state DB) with a network-aware tokenizer (interface-name canonicalization, IPs/ASNs as whole terms). Indexes config stanzas with original line numbers (Junos braces and `set`, IOS/NX-OS/EOS/FRR/FortiOS indentation), running-vs-golden drift hunks (`config_drift`), NetBox / site-manifest topology, every KB runbook, and the incident store (incremental sync; resolved incidents are precedents). Config bodies are secret-scrubbed at rest. CLI `rag index|search|stats|drift`; `GET /api/rag/search`, `/api/rag/stats`, `POST /api/rag/reindex`, `/api/rag/drift`.
- **Cited evidence in RCA and Copilot**: every playbook carries `deep_analysis.evidence` (S1..Sn: config, drift, topology, runbook, incident) even with the LLM off; LLM prompts get the evidence as fenced numbered sources and must cite `[S#]`; `deep_analysis.citations` reports valid and invented labels. Copilot numbers config lines (`L12|`) and validates `host Lnn` references against the configs it sent.
- **Incident resolution**: incidents have stable IDs (`INC-000042`); `POST /api/incidents/<id>/resolve` attaches the fix, which retrieval then cites as precedent.
- **Streaming triage worker** (`triage_worker.py`): tails the syslog spool from a persisted cursor, dedups relay echoes, classifies into a sliding window, runs entity pairing + topology-aware suppression, and opens or updates Jira / ServiceNow / webhook (or dry-run) tickets with the RCA playbook, cited evidence and, for interface faults, a guarded drain with its Ansible check-mode playbook. Per-incident cooldown (escalations and recoveries bypass it), no update without new events, self-healed flaps never ticket, global hourly rate limit with deferral, retries after failed delivery, and a lease so one worker per host processes the spool. `ai-log-analyzer triage-worker`, `/api/triage/stream/{status,start,stop,tick}`, `AI_LOG_ANALYZER_TRIAGE_WORKER=true`.
- **RBAC** (`rbac.py`): `viewer` < `operator` < `admin` from `AI_LOG_ANALYZER_{VIEWER,OPERATOR,ADMIN}_TOKENS` or `AI_LOG_ANALYZER_RBAC_FILE` (SHA-256 token hashes), constant-time comparison. Admin-only: `/api/run`, LLM provider/toggle, sources and rules configuration, triage worker control, index rebuild, audit log. The legacy `AI_LOG_ANALYZER_API_TOKEN` maps to admin, so existing deployments are unchanged. `GET /api/whoami`.
- **Audit trail** (`audit.py`, `audit_log` table): append-only (UPDATE/DELETE rejected by triggers) and SHA-256 hash-chained (`/api/audit/verify`). Records `/api/run`, configuration mutations, denied attempts, incident resolutions, triage tickets and every external (cloud) LLM call with the acting principal (sizes and counts, never prompt content; `AI_LOG_ANALYZER_AUDIT_LLM=all|off`). `GET /api/audit` with actor/action/since filters.
- **Golden-incident regression harness** (`judge.run_eval`, `ai-log-analyzer eval --golden [--min-golden 0.99]`): labeled EVPN underlay cascade, BGP route leak + flap, FortiGate SD-WAN/IPsec cascade and PAN-OS HA failover incidents (`data/eval/`), replayed offline with a deterministic stub LLM and scored on RCA accuracy, entity de-tokenization (no raw IPs/hostnames reach the cloud provider; tokens restored), guardrail compliance (injected destructive CLI never survives) and evidence/citation validity.

### Fixed

- Shared SQLite state DB could silently lose committed rows across forked workers: a connection still open at `fork()` (unreachable but not yet garbage-collected) was inherited, and when the child finalized it, closing the descriptor dropped the child's POSIX locks on the database, so sibling workers overwrote each other's WAL frames. Every connection is now closed before `fork()` (`os.register_at_fork`) and reopened lazily. Writes also retry `BEGIN IMMEDIATE` / `database is locked` instead of swallowing `OperationalError` (which dropped the insert).
- `VXLAN_TUNNEL_DOWN` / VTEP-down / NVE-peer-lost lines were classified as "VPN/IPsec tunnel failure"; they are now "VXLAN tunnel / VTEP down" (category `evpn`, EVPN cascade playbook).

### Added — durable ingest, multi-worker state, suppression, automation export

- **Shared SQLite WAL state** (`state_store.py`, `AI_LOG_ANALYZER_STATE_DB`): syslog spool, incident memory and LLM runtime toggles shared by every Gunicorn worker and kept across restarts. See `docs/OPERATIONS.md`.
- **Syslog listener rewrite** (`sources/syslog.py`): asyncio loop with concurrent non-blocking TCP, RFC 6587 octet-counting + LF framing, optional TLS / mutual TLS (RFC 5425), tuned `SO_RCVBUF`, sender IP/CIDR allow-list, oversize-frame and connection limits, `stats()`. Header-less lines are attributed to the sender IP (was the literal `syslog`); every event carries `attrs.sender_ip`. Durable spool; a worker that cannot bind the port reads the shared spool instead of splitting traffic.
- **Topology-aware suppression** (`suppression.py`, `AnalysisResult.suppression`): dependent alerts of a failed core/WAN router (inferred from the addresses peers lose, even when the router logs nothing), firewall HA pair, or SD-WAN / IPsec transport are grouped under one root; action items carry `suppressed_by` and rank below live roots; webhooks page roots only. Optional dependency map (`AI_LOG_ANALYZER_DEPENDENCIES`).
- **Ansible / Nornir export** (`remediation_export.py`): `cisco.ios`, `cisco.nxos`, `arista.eos`, `junipernetworks.junos` (commit confirmed + rollback), `fortinet.fortios`, `paloaltonetworks.panos` and FRR playbooks with a check-mode diff task, guarded apply → verify → persist, and rescue rollback; Nornir/NAPALM dry-run scripts. Re-screened by `SafetyGuardrail`. Exposed via `remediation --format ansible|nornir`, `POST /api/remediation {"export": ...}` and the MCP tool.

### Fixed

- `IncidentStore` JSONL: appends and cap rewrites hold an `fcntl` lock and re-read the file, so concurrent workers no longer interleave lines or drop records. `*.db` paths use the SQLite backend.
- UDP syslog no longer sets `SO_REUSEADDR` (two workers could bind the same port and split datagrams).
- CLI `remediation --vendor` accepts the FortiOS, PAN-OS and SD-WAN vendors.

### Added — multi-vendor schema, parsers and BGP intelligence

- **Canonical event schema.** `LogEvent` / `ClassifiedEvent` gain optional `vendor`, `event_type`, `interface`, `peer_ip`, `asn`, `vrf`, `vni`, `tunnel_id`, `action` (`vendor_action` on `ClassifiedEvent`), `state`, `normalized_utc_ts` and an `attrs` map. The five-field constructor is unchanged; `ClassifiedEvent.to_dict()` adds an `entities` key only when fields are known.
- **Parser plugin registry** (`ai_log_analyzer/parsers/`) replaces the first-regex-wins parser: FortiOS key=value (VPN/IKE, SD-WAN SLA, router BGP, HA, conserve mode, traffic/UTM), PAN-OS CSV (SYSTEM routing/vpn/ha/globalprotect, TRAFFIC, THREAT, GLOBALPROTECT), Cisco Catalyst SD-WAN (vEdge notifications + cEdge FTMD/OMPD/VDAEMON), and entity enrichment for Junos, EOS, IOS-XE, NX-OS, FRR, SONiC, Cumulus and SR Linux. Legacy base fields are byte-identical. Connector events are enriched lazily in the classifier. See `docs/PARSERS.md`.
- **Classifier + KB.** Rules and 5-phase playbooks (FortiOS / PAN-OS / SD-WAN CLI) for IKE Phase 1/2 and DPD failures, SD-WAN SLA violations, BFD / OMP / control-connection loss, firewall HA split-brain and failover, FortiGate conserve mode and session-table exhaustion, IPS hits, GlobalProtect auth failures; new `sdwan` and `firewall` categories.
- **BGP anomaly detection** (`bgp_anomaly.py`, `AnalysisResult.bgp_anomalies`): RFC 4271 / RFC 4486 NOTIFICATION decoding, RFC 8203 shutdown communication, planned vs unplanned, max-prefix warning vs exceeded with counts, origin / AS-path changes, per-peer flapping and fabric-wide route-flap storms. Hold-timer expiry and administrative Cease now get distinct playbooks.
- **Down → up state pairing** (`entity_state.py`): action items carry `state` (`active` / `flapping` / `recovered`) and `entity_states`; active outages rank above recovered ones of the same severity. `AnalysisResult.entity_states` summarizes every entity.
- **Cross-vendor entity correlation** (`correlate.correlate_entities`, `AnalysisResult.entity_correlation`): joins events on shared IPs, BGP /30-/31 point-to-point subnets, device interfaces and tunnels, and same-device timing; root = lowest layer, earliest event (e.g. FortiGate SD-WAN SLA miss → IPsec down → Junos KMD VPN down → BGP hold-timer on both ends).
- **Remediation vendors:** `fortinet_fortios` (revert mode — honest about the restart on revert), `paloalto_panos` (named snapshot + manual rollback; no native timer), `cisco_sdwan` (`config-transaction` + `commit confirmed`). QoS/CoPP templates are refused for these vendors. Guardrail blocks FortiOS/PAN-OS/SD-WAN factory-reset, wipe and restart commands.

### Changed

- Hold-timer, max-prefix, administrative Cease, protocol NOTIFICATION and origin/AS-path lines get specific descriptions instead of the generic "BGP peer down" bucket (same severity/category).
- Classifier literal gate is now per pattern (only patterns whose guaranteed literal occurs are tried, in table order): identical results, ~3.6× faster classification stage. End-to-end ingest is ~30 % slower than before this release on a 147k-line mixed corpus because every line now gets entity extraction, state pairing and correlation.

### Security

- **Central LLM gateway** (`llm.query()`). Every LLM call — analyzer, copilot, diff, judge, site_doc, site_optimize — now passes one boundary that re-applies secret/PII redaction, so no caller can forget it.
- **No silent cloud egress.** `ollama` / `local` no longer fall back to Claude or Grok unless `ALLOW_CLOUD_FALLBACK=true`; an explicitly selected cloud provider may fall back to local runtimes, not to a second cloud vendor.
- **Reversible, indexed entity tokens** (`sanitize_vault.py`). IPs, IPv6, MACs, ASNs and hinted hostnames become `<IP_1>`, `<IP6_1>`, `<MAC_1>`, `<ASN_1>`, `<HOST_1>` instead of one generic placeholder, so the model can tell BGP/EVPN peers apart. Answers are detokenized for the operator. One vault per analysis run keeps numbering consistent across playbooks and the executive summary. The vault is LRU/TTL-bounded.
- **New redaction rules** (`sanitize.py`): interface/neighbor `description`, SNMP `location` / `contact`, SNMPv3 auth/priv keys, and chassis serial numbers.
- **Prompt-injection fencing.** Raw log and config text is wrapped in `<untrusted_data>` blocks (embedded delimiters neutralized) and the gateway adds a data-handling rule to every system prompt.
- **SafetyGuardrail on model-generated CLI.** Deep-analysis phases and `preventive_config`, `optimize_config` patches/rollbacks, site `fix_per_device`, and site-optimize `config_changes` are screened; violations are replaced with a visible `# BLOCKED by SafetyGuardrail (...)` line and listed in `guardrail_blocked`. New rules: Junos stanza deletes, `clear bgp *` / bare `clear bgp neighbor`, `load override`, `request system reboot`, shell wipes; multi-command strings are checked per segment.

### Added

- Per-provider prompt budgets (`LLM_MAX_PROMPT_CHARS[_<PROVIDER>]`, visible head+tail truncation), optional `OLLAMA_NUM_CTX`, and retry with exponential backoff on HTTP 408/429/5xx/529 honouring `Retry-After` (`LLM_MAX_RETRIES`, `LLM_BACKOFF_BASE`, `LLM_BACKOFF_MAX`).
- `/api/llm/status` exposes `allow_cloud_fallback`, `tokenize_hostnames` and `last_call` metadata (provider, prompt size, redactions, entities tokenized, truncation — never content).

### Changed

- `llm.prepare_log_samples()` no longer masks addresses itself; the gateway tokenizes the whole prompt with one vault.

## [1.3.0] - 2026-10-16

### Added

- **Deep network analytics** (`analytics.py`). RFC 2439 exponential flap dampening with periodic-vs-bursty jitter, Tarjan articulation-point blast radius, and config-to-log drift correlation. Stdlib only.
- **ServiceNow table source** (`sources/servicenow.py`). Reads `em_alert`, `incident`, or `syslog`, normalizes display-value CI objects into syslog lines, and rejects loopback and metadata URLs before any request.
- **Change correlation and incident sync** (`servicenow_sync.py`). Scores recent change requests against findings and creates or updates one incident per deterministic `netlog-ai-` correlation id. Dry-run is the default.
- **CLI, API, and MCP surfaces.** `ai-log-analyzer analyze --deep-analytics`, `POST /api/analytics/deep`, `POST /api/itsm/servicenow/sync`, and MCP tools `netlog_deep_analytics`, `netlog_servicenow_correlate_changes`, `netlog_servicenow_sync_incident`.
- **Topology overlay.** Cytoscape classes for critical and latent SPOFs, flap storms, and correlated change badges, plus a dry-run work-notes preview.

## [1.2.0] - 2026-10-15

### Added

- **SolarWinds Orion + Observability SaaS connector** (`sources/solarwinds.py`, #54 plus audit upgrade). SWIS v3 mode POSTs parameterized SWQL (`{"query", "parameters"}` with `@since` / host filters — never string interpolation) to `/SolarWinds/InformationService/v3/Json/Query`. Active alerts join `Orion.AlertActive`, `Orion.AlertObjects`, and `Orion.AlertConfigurations` (`AlertActiveID`, `AlertObjectID`, `TriggeredDateTime`, `TriggeredMessage`, `ac.Severity`, `ac.Name`, `ao.EntityCaption`, `ao.RelatedNodeCaption`). Syslog is read from `Orion.OLM.LogEntry` with fallback to `Orion.SysLog`, both joined to `Orion.Nodes`; network events come from `Orion.Events`. SaaS mode uses Bearer `GET /v1/logs` and `GET /v1/alerts` with cursor or page pagination. Everything normalizes to `<timestamp> <hostname> <program>[<severity>]: <message>`.
- **`SolarWindsConfig.from_env()`** reads `SOLARWINDS_URL`, `SOLARWINDS_USERNAME`, `SOLARWINDS_PASSWORD`, `SOLARWINDS_TOKEN`, `SOLARWINDS_MODE` (`swis` or `saas`), and `SOLARWINDS_VERIFY_SSL`. `SourceManager.load_from_env()` also registers a `solarwinds` source from those vars.
- **Topology and telemetry helpers.** `build_site_manifest(site_name)` reads `Orion.Nodes` + `Orion.TopologyConnections` into the NetBox/EVPN manifest shape. `fetch_interface_telemetry(device, interface)` maps `Orion.NPM.Interfaces` `InErrorsToday` / `OutErrorsToday` / `InDiscardsToday` / `OutDiscardsToday` onto `InterfaceTelemetrySnapshot` (`SolarWindsInterfaceTelemetry` carries Orion `Status`, which the base snapshot type has no field for).
- **Explicit writeback.** `append_alert_note` invokes `Orion.AlertActive/AppendNote`; `acknowledge_alert` invokes `Orion.AlertActive/Acknowledge`. No automatic writes; credentials are never logged.
- **MCP SolarWinds tools** (`fetch_solarwinds_logs`, `fetch_solarwinds_alerts`, `push_solarwinds_alert_note`). The note push is an explicit tool call only.
- Wired through `sources/__init__`, the manager, CLI `--source` (kinds + `SOLARWINDS_*` env), `/api/sources`, `/api/analyze`, the web source selector (`index.html` + `app.js`), and CONNECTORS docs.

### Tests

- Mocked SolarWinds coverage: parameterized SWQL, alert join, OLM→`Orion.SysLog` fallback, `Orion.Events`, SaaS pagination, site manifest, NPM telemetry, writeback payloads, `from_env`, manager dispatch, MCP log/alert/note tools, and web `/api/sources`. Full suite: **613 passing**, ruff clean.

## [1.1.0] - 2026-10-14

### Added

- **Vendor-safe remediation & rollback guardrails** (`remediation.py`). Generates deterministic pre-checks, transactional configuration blocks with auto-revert timers (`commit confirmed` on Junos, `configure session ... commit timer` on Arista EOS, `checkpoint` on Cisco NX-OS, `configure terminal revert timer` on Cisco IOS-XE, and `vtysh` snapshot + auto-revert on FRR), post-checks, and explicit abort/rollback sequences. Strictly enforces destructive command blocklist and 1–30 minute timer limits via `SafetyGuardrail`.
- **Two-way Jira & ServiceNow ITSM integration** (`itsm.py`, `integrations/itsm.py`). Deterministic incident fingerprinting (`NETLOG-<SHA256>`) for idempotent ticket deduplication across CLOS fabrics. Updates open tickets with markdown RCA summaries and remediation cards or creates new incidents via `JiraITSMClient` and `ServiceNowITSMClient`.
- **Remediation & ITSM surfaces**. Exposes `/api/remediation` and `/api/itsm/enrich` REST API endpoints, `generate_remediation_plan` and `enrich_itsm_incident` MCP 2.x server tools, Web UI `#remediation-panel` controls, and CLI `ai-log-analyzer remediation` subcommand + `--remediation` flag for `ai-log-analyzer analyze`.

## [1.0.0] - 2026-10-13

### Added

- **Protocol-aware EVPN causality** (`evpn_causal.py`). `EVPNBipartiteCausalEngine` classifies syslog into L1–L5 (physical → LAG/MLAG → underlay → VTEP/NVE → EVPN overlay), picks the lowest-layer root cause, and suppresses higher-layer symptoms on the same or adjacent device inside a 120s window. Opt-in via `analyze(..., evpn_causal=True)`, `--evpn-causal`, or `AI_LOG_ANALYZER_EVPN_CAUSAL=1` — default off. Cytoscape elements (`device:LAYER` nodes, dashed overlay edges, pulsing root-cause style) are exposed for topology overlay.
- **Optical DOM/DDM and interface telemetry correlation** (`sources/telemetry.py`). `TelemetryCorrelator` and `PrometheusTelemetryBridge` evaluate interface optical budgets, FCS/CRC error deltas, and queue discards to separate physical fiber/transceiver degradation from QoS/CoPP microburst buffer drops or clean remote shutdowns.
- **MCP causality tool** (`analyze_evpn_causality`). `mcp_server/server.py` exposes site-level bipartite underlay/overlay causal analysis as an MCP tool for automated triage.
- **EVPN REST & Web UI overlay**. Exposes `/api/causal/evpn` endpoint and Cytoscape.js overlay rendering with L1-L5 dependency edges.

## [0.9.0] - 2026-10-13

### Added

- **Drain-style log deduplication** (`dedup.py`). `NetworkLogDeduplicator` masks IPv4/IPv6, MAC, interface, ASN, hex, PID, and number tokens, clusters identical templates, and emits compact `[DEDUP xN]` lines for LLM prompts. Opt-in via `analyze(..., dedup=True)`, `--dedup`, or `AI_LOG_ANALYZER_DEDUP=1` — default off so classification counts and the streaming memory bound stay unchanged.
- **Log-line vault anonymizer** (`sanitize_vault.py`). `SanitizeVault.anonymize()` masks IPv4, IPv6, MAC (colon/dash/Cisco-dotted), and ASN so EVPN Type-2 MAC/IP lines are fully redacted before `llm.py`. Distinct from the config sanitizer in `sanitize.py`.
- **NetBox site manifest & v4.x cable termination fallback** (`sources/netbox.py`, `build_site_manifest()`). Optional stdlib client builds devices + cable adjacency. Cable terminations whose `device` is `None` (FrontPort/RearPort patch panels, CircuitTermination) are skipped instead of raising `AttributeError`. When `NETBOX_URL` and `NETBOX_TOKEN` are set, analysis attaches device site/role/type from the NetBox REST API via stdlib `urllib`. Unset = no-op, no network. The token is never logged.
- **Ingestion hardening.** File/syslog ingest now replaces bad encodings, strips BOM and control characters, blanks out-of-range timestamps, and caps oversized lines (`AI_LOG_ANALYZER_MAX_LINE_BYTES`, default 64KiB) and files (`AI_LOG_ANALYZER_MAX_FILE_BYTES`, default unlimited for the CLI).

### Fixed

- **Syslog header prefixes.** `dedup._SYSLOG_HEADER_RE` now accepts optional PRI+version (`<134>` / `<134>1 `), Cisco sequence numbers (`004122: `), and a leading asterisk (`*Oct 13`), reconciled with the existing PRI strip from #51. Arista / Junos / FRR / Cisco prefixed lines cluster.
- **Sanitize vault IPv6/MAC.** EVPN Type-2 MAC/IP advertisements are masked alongside IPv4/ASN before any LLM prompt.

## [0.8.0] - 2026-10-10

### Added

- **Readable unknowns, shorter VXLAN labels, a local syslog listen button, and an LLM checkbox that stays off.** Unknown-pattern rows wrap and carry a one-line meaning. VXLAN edges show a count instead of every VNI. Live tail can open UDP 5514. Unchecking Use LLM is no longer overwritten by the status poll.
- **Shift brief on the Logs tab.** After an analysis, the UI shows the sanitized brief and the ServiceNow-shaped ticket fields. The ticket is still not posted. Timeline rows include the syslog sample so a commit is not only a category title.
- **Logs tab guards.** Run Analysis stays disabled until a lab container is selected. The topology map hides when you leave Site. The header version comes from the package, and the LLM chip stays off while the selected provider is unreachable.
- **Work shift incident handoff.** Every analysis handoff now includes a ServiceNow-shaped ticket (`short_description`, `urgency`, `configuration_item`, `work_notes`) that is not posted, and a one-page shift brief with the epicenter, the change window, and up to three read-only commands. IOS-XE, Aruba, and Meraki lines for an access point down, 802.1X failure, DHCP pool exhaustion, WAN failover, and a non-Meraki VPN down classify on their own. When the incident journal is on, the brief names a host and category seen at least twice in seven days.
- **Restore auto-detection parsing** (#19). `tfsm-fire` stays off the dependency list — that distribution is still gone from PyPI — and the `parse` extra now installs `textfsm` plus `ntc-templates`. `adapters/tfsm_auto.py` scores those templates in-process. `pip install netlog-ai[parse]` and `[all]` work again, and `tests/test_tfsm_auto.py` runs instead of skipping.

### Changed

- **MCP server requires SDK 2.x** (#17). `mcp_server/server.py` constructs `MCPServer` from `mcp.server.mcpserver` — FastMCP was removed in 2.0 with no shim. The `mcp` and `all` extras are `mcp>=2,<3` (the #16 `<2` hotfix is gone). `_build_server()` now reports "SDK not installed" vs "incompatible version" separately, and names the installed version via packaging metadata because 2.x does not set `mcp.__version__`. Dual 1.x/2.x support was rejected: both this project and mcp 2.0 require Python >=3.10, and a fallback import would hide the next API move the same way #16 was hidden.

### Fixed

- Keep low-severity config commits visible to the change-window correlator
  and causal timeline when a 300-event severity cap would otherwise drop
  them during a fabric-wide storm. The timeline display cap now pins a
  bounded set of config events so a late commit cannot vanish behind 24
  earlier flaps.
- Pin the earliest config event per hostname in the change-window reserve
  so later CLI-classified noise on another device cannot evict the
  causative commit. `change_window.devices` is chronological so the
  earliest commit host is named first, including when configs survive
  inside the severity top_k. The timeline floor that evicts oldest
  commits to surface a later storm keeps that earliest commit so the
  noisy host cannot steal the timeline either.
- Order change-window / timeline / config-reserve by parsed event time,
  not the raw timestamp string. Mixed `--frr` ISO, Junos RFC3164, and
  Loki nanosecond-epoch stamps do not sort lexicographically, so a later
  FRR or Loki host was named as `devices[0]`. RFC3164 year is taken from
  a sibling dated event. Leftover-cluster gaps use the same restamped
  time so a mixed-format storm is not split into one-event clusters.
  The yearless RFC3164 sentinel is a leap year so 29 Feb still parses.
  Aware ISO offsets convert to UTC before comparison so ``10:00+05:00``
  cannot sort after ``09:55Z``. RFC3164 restamp picks the nearest year
  to the dated sibling so a ``Dec 31`` Junos commit is not assigned
  January's calendar year and cannot lose ``devices[0]`` to a later
  January host. Wrap only at a year boundary (Nov/Dec next to Jan/Feb)
  so a June ISO sibling keeps December in the same year. Yearless-only
  Dec/Jan pairs pin the first RFC3164 stamp to ``now()`` and restamp
  the rest against that sibling, so mid-year ``now()`` cannot assign
  both the same calendar year. An int year passed to ``event_time``
  stays a literal calendar year.
- Floor later incident rows into a config-flooded timeline cap so a
  24-commit maintenance burst cannot hide the BGP storm that follows.
  Leftover earlier flaps do not count as already showing the outage when
  a commit exists in the window — including when that commit overflowed
  past a flap-filled cap or arrived after the storm, and including when
  leftover flaps themselves overflow the cap (the floor must pull the
  later storm, not more morning flaps or a later leftover-category
  burst of the same signature). The same floor now runs when there is
  no config commit at all — a 24-flap morning prefix must not hide an
  afternoon BGP storm on another device. A leftover-contiguous skip only
  consumes leftover-category overflow — including leftover flaps that
  resume after a commit or time gap immediately before the storm —
  so a leftover-headed burst cannot swallow the outage. A storm that
  starts within 60s of leftover flaps (flaps → commit → immediate
  BGP) is not swallowed. When leftover itself is already routing, a
  later high/critical routing cluster is kept as the storm — trailing
  leftover-signature flaps, leftover-host resume that heads the same
  60s cluster, other-category rows, and recovery do not steal the
  floor. Those leftover flaps can also
  be evicted when they occupy the cap and leave no commit slots to spare.
  After flooring, remaining early commits (or leftover flaps, when no
  commit sat in the prefix) are swapped for true late commits rather
  than evicting the storm.

## [0.7.0] - 2026-10-08

### Added

- **0.7.0 incident handoff.** `handoff.incident_handoff` builds a paste card from the
  health score, blast radius, change window, and top actions, then runs that
  card through the sanitize gate. The analysis payload includes it as `handoff`.
  Raw syslog stays out of the paste. Commercial NOC tools already post incident
  stories into Slack and ServiceNow; this is the local preview that strips
  secrets and public IPs before that paste.

## [0.6.0] - 2026-08-29

Causal console release.

### Added

- **xAI Grok LLM provider** (`LLM_PROVIDER=grok`, `XAI_API_KEY`) — OpenAI-compatible
  `/v1/chat/completions`, sanitize-first like every other backend. Joins the
  fallback chain after Ollama / DMR / Claude. Selecting Grok without a key is
  rejected the same way Claude is.
- **Causal console** (`causal.py`) — chronological incident timeline with
  cause links (link-down → BGP/OSPF/LAG, config-commit → critical), a
  blast-radius estimator naming the epicenter, and a change-window correlator
  that flags commits inside the same incident. Wired into `analyze()` so Flask,
  CLI, and MCP all see `timeline` / `blast` / `change_window` / `sanitize_diff`.
- **Sanitize-diff preview** — `POST /api/sanitize-diff` plus a UI panel that
  shows the redacted text and per-rule counts (what the LLM is allowed to see).
- **Custom-rule editor** in the Flask UI (runtime `POST /api/rules`, listed
  next to the built-in KB).
- **SONiC + Cumulus classifier patterns** — orchagent / syncd / SWSS / teamd,
  switchd / clagd / ifupdown2 / PTMD, NVUE/NCLU and ConfigDB commits. First-match
  specific tokens sit ahead of the generic `commit` / `link down` rules.
  Suite 369 → **423** tests.

### Changed

- GitHub Pages counters paint the final number immediately (the previous
  count-up animation could leave chips at 0 if mermaid's CDN module hung).
- Docs: 80 regex patterns, Grok in the provider chain, 0.6 roadmap section.

## [0.5.2] - 2026-08-23

Security and hardening release.

### Fixed

- Bind `/api/analyze` (`source=frr`) and the `/api/optimize` docker-exec fallback
  to the bundled-lab inventory. Caller-supplied container names outside
  `list_lab_containers()` are rejected (403, fail-closed on mixed lists). Site
  prefixes are POP-scoped (`de-fra-`, `uk-lon-`, `nl-ams-`, `us-nyc-`) so
  `dev-*` / `us-east-*` containers cannot ride a country-level allow-list.
- Secret-sanitize cross-run template memory before persistence and force its JSON
  file to owner-only permissions.
- Protect incident search endpoints (`/api/incidents/similar`) with the API token.
- Bound custom classification regexes to prevent ReDoS.
- Sanitize outbound webhook payloads.
- Redact credentials from bundled site configuration samples.
- Fix Unicode casefold bypass in the classifier literal gate.
- Bound executive-summary hostname anchors.
- Bound TextFSM demo template scan.

### Notes

- The MCP extra is already `mcp>=2,<3` on main (server code ported to
  `mcp.server.mcpserver.MCPServer`). Formal packaging/test lock-in remains in
  open PR #33 and will ship in a follow-up release.

## [0.5.1] - 2026-07-28

Packaging hotfix. **`pip install netlog-ai[all]` and `pip install netlog-ai[parse]`
were failing for every user of the published package**, and CI was red on Python
3.10 / 3.11 / 3.12.

### Fixed

- **Removed the withdrawn `tfsm-fire` dependency.** Upstream deleted the package from
  PyPI *and* deleted `github.com/scottpeterman/tfsm_fire`, some time between
  2026-07-13 (netlog-ai CI installed `tfsm_fire-0.1.0-py3-none-any.whl` cleanly that
  day) and 2026-07-28 (both 404). There is no surviving fork, mirror, renamed
  distribution, or Wayback snapshot — the dependency is simply unobtainable, so the
  extras that required it could not resolve:

  ```text
  ERROR: Could not find a version that satisfies the requirement tfsm-fire>=0.1.0; extra == "all"
  ERROR: No matching distribution found for tfsm-fire>=0.1.0; extra == "all"
  ```

  Repointing the extra at a `git+https://` URL was not an option — the repo is gone,
  and PyPI rejects PEP 508 direct references in uploaded metadata regardless.

- **Pinned the ruff rule selection**, fixing a *second*, independent CI break that the
  install failure was masking. `[tool.ruff.lint]` set only `ignore`, never `select`, so
  the repo inherited ruff's default rule set — while `dev` allows `ruff>=0.5`. ruff
  0.16.0 broadened those defaults, turning an unmodified `main` from "All checks passed"
  into **240 findings** with no code change (verified: ruff 0.15.21 passes on
  `origin/main`, ruff 0.16.0 does not). Lint now explicitly selects `E4, E7, E9, F` —
  ruff's historical defaults and the set this codebase was written against — so the
  config no longer drifts with the tool version.

- **Bounded the MCP SDK to `<2`**, fixing a *third* independent break. MCP SDK 2.0
  removed `mcp.server.fastmcp` (it is now `mcp.server.mcpserver`), which
  `mcp_server/server.py` imports; `mcp>=1.0` resolved to 2.0.0 and failed
  `tests/test_mcp_tools.py` on unmodified `main`. Porting to the 2.x API is a real
  migration and is tracked separately rather than bundled into a packaging hotfix.

All three had the same underlying cause — unpinned dependencies drifting under a repo
that had not run CI since 2026-07-13 — and each was masked by the one before it.

### Changed

- **`parse` extra removed.** `pip install netlog-ai[parse]` now warns that the extra
  doesn't exist and installs the base package, instead of hard-failing.
- **`all` extra reduced to `mcp>=1.0`** — it now installs everything it advertises.
- **`docs/TFSM_AUTO_PARSER.md`** documents manual installation of `tfsm-fire` plus the
  template DB for anyone who still has copies, and notes that the templates originate
  from the still-maintained
  [networktocode/ntc-templates](https://github.com/networktocode/ntc-templates).
- CI installs the base `[dev]` set and the full `[dev,all]` set as separate steps, so a
  broken base dependency can't hide behind the extras.

### Added

- `tests/test_packaging.py` — offline metadata guards: no PEP 508 direct references in
  any dependency list (they build fine locally but cannot be uploaded to PyPI), no
  `tfsm-fire` requirement, and `all` stays a superset of the other non-dev extras.

### Unchanged

- `adapters/tfsm_auto.py` and its public API are untouched. It has always been a strict
  fallback parser that no other feature depends on, and it already degraded to
  no-match — never raising — when the package or template DB was absent. Set
  `TFSM_DB_PATH` / `TFSM_DB_URL` and install your own copy of `tfsm-fire` to keep using
  it; `tests/test_tfsm_auto.py` skips at module level otherwise.

## [0.5.0] - 2026-07-13

Research-driven wave (competitive study of 2026 NOC tooling — SSE-first live
viewers, incident-history UX, Cisco/Nokia syslog references).

### Added

- **🔴 Live tail** — `GET /api/tail/<source_id>` streams classified events
  from any syslog listener source via Server-Sent Events (zero new deps, no
  polling, server-side `?min_severity=` filter, keepalive frames, query-token
  auth for EventSource). New Live Tail panel in the Logs tab with start/stop,
  source picker, and a rolling 200-event view. Backed by a new cursor-based
  `fetch_new()` on the syslog source (monotonic ingest counter — no
  duplicates, wraparound-safe).
- **↻ Incident memory** (`memory.py`) — with `AI_LOG_ANALYZER_INCIDENT_STORE`
  set, every run journals its action items locally (bounded JSONL); future
  runs annotate items with `recurrence` ("seen 3× before, last Jul 5, on
  spine-01") shown as a badge in the UI, and `/api/incidents/similar?q=`
  answers free-text "have we seen this before?" via token-overlap search.
- **🎬 Demo mode** — `ai-log-analyzer demo` runs a deterministic synthetic
  incident storyline (6 devices, 4 vendor dialects: flapping interface, BGP
  collapse, NX-OS service crash, PSU failure, SSH brute force, SR Linux
  churn, one never-seen shape) through the full pipeline and prints the
  result; `--serve` starts the UI with a UDP feeder so Live Tail streams the
  story in real time. Zero setup, zero LLM key needed.
- **Cisco IOS-XE / NX-OS / Nokia SR Linux classifier patterns** —
  `%LINK-3-UPDOWN`, `%LINEPROTO-5-UPDOWN`, `%ETHPORT-5-IF_DOWN`,
  `%SYSMGR-2-SERVICE_CRASHED`, `%VPC-2-*`, `%MODULE-2/%PLATFORM-2`,
  `%DUAL-5-NBRCHANGE` (EIGRP), `%HSRP-5-STATECHANGE`, `%ENVMON`,
  `%SEC_LOGIN-4/5`, `%SYS-5-CONFIG_I`, and SR Linux `bgp_mgr` session /
  oper-state transitions — mapped onto the existing canonical descriptions so
  stability flap-pairing, recovery filtering, and the KB all work unchanged.
- **Per-event confidence score** — every classified event now carries
  `confidence`: 1.0 custom rule, 0.9 KB pattern, 0.6 raw-severity promotion,
  0.3 unmatched snippet.

### Performance

- Literal-gate extraction now recovers guaranteed literals from alternations
  whose common prefix sre hoists into a short run (`%a|%b` → `%` + branch) —
  unguarded always-scanned patterns drop from 2 to **0**.

Suite 338 → 369 tests.

## [0.4.0] - 2026-07-13

### Added

- **Fabric stability engine** (`stability.py`) — per-device flap detection
  (down↔up oscillation of interfaces / BGP peers / OSPF neighbors / LAG
  members / VPN tunnels), event-rate burst detection against each device's
  own baseline, rising/stable/falling trend, and a deterministic 24h risk
  band. Surfaces as `stability` in `/api/analyze` + MCP and a **📶 Fabric
  Stability** panel in the UI (worst devices first, actionable
  recommendations). Streaming-safe: O(devices × entity classes) memory,
  minute-prefix bucketing with arrival-order fallback so unreliable syslog
  timestamps can't break it.
- **LLM-as-Judge playbook scoring** (`judge.py` + `ai-log-analyzer eval`) —
  scores generated playbooks 0–10 on actionability / safety / grounding /
  completeness with a deterministic heuristic core (empty playbooks can't
  ace safety "by absence"; disruptive commands without context are
  penalized; R1/SW2-style placeholder names hurt grounding). Optional
  `--use-llm` blends a real LLM judge via the configured provider, falling
  back silently. `eval` self-tests every rule-based KB playbook by default,
  scores a saved analyze result with `--file`, and `--min-score` makes it a
  CI quality gate.

- **Unknown-pattern template mining** (`patterns.py`) — every line the regex KB
  can't match is mined into templates with a dependency-free Drain-style
  streaming clusterer (variables masked as `<ip>/<mac>/<hex>/<if>/<n>/<ts>`,
  similar shapes merged into `<*>` wildcards, LRU-bounded memory). The
  analyzer surfaces the top templates — error-smelling shapes ranked first —
  as `unknown_patterns` in `/api/analyze`, the MCP `analyze_logs` tool, and a
  new **🔭 Unknown Patterns** panel in the UI. Novel failure modes no longer
  vanish as `info` noise.
- **Custom classification rules** — operators can extend/override the built-in
  KB: a JSON rules file loaded at startup (`AI_LOG_ANALYZER_CUSTOM_RULES`) and
  a runtime API (`GET/POST /api/rules`). Custom rules are checked before the
  built-in patterns, so a known-noise event can be demoted or a site-specific
  failure promoted.
- **Cross-run template persistence** — set `AI_LOG_ANALYZER_TEMPLATE_STORE`
  to a path and the miner remembers every template shape across runs
  (FIFO-bounded JSON store, atomic writes, corrupt-file tolerant). Templates
  never seen in *any* prior run are flagged `is_new` (🆕 in the UI panel,
  `new_template_count` in the API) — the classic AIOps early-warning signal.
- **Coverage wave for phases 0–12 leftovers** — `reports.py` (MD/CSV/HTML
  exporters), `runbook.py` (Ansible/netmiko generation + command extraction),
  `topology.py` (build/exports/finding overlay), and the previously untested
  web routes `/api/report`, `/api/runbook`, `/api/topology`, plus the
  validation paths of `/api/diff` and `/api/copilot`. Suite 294 → 325 tests.

### Security

- **Log lines now pass the sanitize gate before LLM calls.** `deep_analyze()`
  sent raw sample log lines (and severity-promoted raw descriptions) to the
  LLM unsanitized — configs were always scrubbed but logs were not,
  contradicting the sanitize-before-LLM guarantee. Both are now scrubbed, as
  is the executive-summary item list.
- **`/api/sources/<id>/test` and `/api/sources/<id>/fetch` now require the API
  token** — they were the only POST data routes missing the auth gate.
- **`Authorization: Bearer <token>` accepted** everywhere `X-API-Token` is
  (the README documented Bearer; the code only accepted the custom header).

### Fixed

- **MCP server finds bundled sites on pip installs** — `list_sites` /
  `analyze_site` resolved only the repo-root `sites/` symlink and returned
  empty from a `pip install netlog-ai[mcp]` wheel; now uses the same
  env-override → packaged-data → repo-root resolution as the web app.
- **`/api/optimize/site` no longer mislabels device platforms on mixed-vendor
  sites** — it stamped every device with the manifest-level vendor string
  (e.g. `multi (Nokia SRL + Arista cEOS + FRR)`); it now uses the shared
  loader that keeps per-device `platform`.
- **Syslog connector `fetch()` is idempotent** — it used to drain the ring
  buffer, so a correlate → triage sequence on the same source saw zero events
  on the second call. It now snapshots; the deque's `maxlen` bounds memory.
- **Default Ollama model corrected** to `qwen2.5-coder:latest` (was
  `gemma4:latest`, which doesn't exist, breaking the out-of-box default
  provider).
- Env-configured sources no longer leak `verify_tls`/`timeout_seconds` into
  `extra`; `.env.example` and README now document the real security env vars
  (`AI_LOG_ANALYZER_API_TOKEN`, `AI_LOG_ANALYZER_CORS_ORIGINS`,
  `ANALYZER_HOST`, `AI_LOG_ANALYZER_FILE_ROOTS`) and the `ollama` provider.

## [0.3.1] - 2026-06-10

- UI header version badge is now populated live from `/api/health` (the 0.3.0
  wheel shipped a hardcoded "v0.2" badge; the static value is only a fallback).

## [0.3.0] - 2026-06-10

First PyPI release: `pip install netlog-ai`. Headline features: cross-source correlation + per-device triage (12 MCP tools), alert webhooks, streaming analyze (flat memory at any log size), 2.3× faster classification, fully air-gapped UI, self-contained wheels.

### Tests

- **LLM transport + fallback-chain coverage** (llm.py 54% → 69%): provider
  fallback order, claude-only no-fallback contract, prompt-caching payload,
  per-provider error recording, `<think>`-block cleaning — all with a network
  tripwire so no test can ever hit the real (paid) Anthropic API. Suite
  278 → 294.

### Performance

- **Streaming analyze — flat memory at any input size.** `analyze()` now
  consumes any iterable in a single bounded pass (per-severity top-300 heaps,
  action-item groups bounded by the KB table, per-device counters). Measured
  on a 100MB syslog: **651MB → 40MB peak RSS** (16×), identical results.
  `classifier.iter_classify()` is the new lazy building block;
  `classify_events()` keeps its sorted/materialized contract. The web file
  route and the CLI both pass generators end-to-end; the web route gains a
  size guard (`AI_LOG_ANALYZER_MAX_FILE_MB`, default 200 — CPU must fit the
  HTTP worker timeout; the CLI streams multi-GB files without limit).

### Added

- **Alert webhooks** — analyses that find events at/above a severity threshold
  fire a webhook: Slack incoming-webhook or generic JSON POST
  (`AI_LOG_ANALYZER_WEBHOOK_URL` / `_MIN_SEVERITY` / `_FORMAT`). Wired into
  `POST /api/analyze` and per-source analysis; delivery is best-effort (5s
  timeout, failures logged, never breaks the analysis response).

### Repository

- **History rewritten** (2026-06-10): pre-pseudonymization identifiers scrubbed
  from all historical sample blobs, and 21MB of demo videos purged from history
  (now release assets on `media-2026-06`). Clone pack: 26MB → 3.4MB. Old clones
  must be re-cloned or hard-reset.

### Performance

- **Classifier literal gate: 2.3× faster classification** (1.2 → 2.7 MB/s on the
  sample corpus, identical results). Guaranteed literal keywords are extracted
  from each KB pattern's parse tree at import; lines containing none of them
  (the vast majority of real syslog) skip the ordered 75-regex loop entirely.
  Sound by construction — patterns with no provable literal stay always-checked —
  and self-maintaining as KB rules are added. Equivalence + invariants pinned by
  `tests/test_classifier_gate.py`.

### Distribution & data privacy (wave 3)

- **Wheels are now self-contained**: `samples/`, `sites/`, and the entire web UI
  ship as package data (`ai_log_analyzer/data/`, `web/static/`). Previously a
  pip-installed netlog-ai had **no UI and no demo data** (package-data was never
  configured); Docker images booted to an empty sites list. Top-level `samples/`
  and `sites/` remain as symlinks for checkout workflows;
  `AI_LOG_ANALYZER_SAMPLES_DIR` / `AI_LOG_ANALYZER_SITES_DIR` override.
- **Release pipeline**: pushing a `v*` tag builds sdist+wheel, smoke-tests that
  the wheel carries data + UI, publishes to PyPI via trusted publishing, and
  cuts a GitHub release (`.github/workflows/release.yml`).
- **Samples fully re-pseudonymized**: the RIR-assigned local ASN, seven real
  peer ASNs, transit/CDN/IXP provider names, a real circuit ID, and six real
  site codes were replaced with private-range ASNs and neutral identifiers —
  guarded by a regression test so they can't reappear.
- **Air-gapped UI**: cytoscape/elkjs/cytoscape-elk are vendored into
  `web/static/vendor/` (the topology tab previously needed 2.3MB from a CDN);
  a test asserts the UI loads no external scripts.

### Security

- **Closed the `analyze_site()` sanitize bypass** — site-wide cross-device analysis
  sent raw `config_text` to the LLM provider; it now routes every device config
  through `sanitize(mask_pii=True)` like the other LLM paths, locked in by a
  regression test (`tests/test_site_sanitize.py`).
- **Confined `POST /api/analyze {source:"file"}`** to allowlisted roots
  (home + `/var/log` + the checkout; override with `AI_LOG_ANALYZER_FILE_ROOTS`).
  Previously any reachable caller could read arbitrary files via the API.
- `GET /api/llm/status` no longer exposes `last_errors` (upstream error bodies) to
  anonymous callers when an API token is configured.
- CDN `<script>` tags now carry Subresource Integrity hashes.

### Changed

- **Anthropic prompt caching**: system prompts are sent with
  `cache_control: ephemeral` — repeat analyses bill cached input at ~10% price.
- Static text assets use `Cache-Control: no-cache` (ETag revalidation → 304s)
  instead of `no-store` re-downloading ~200KB per page view.
- Dropped the unused D3 bundle (280KB on every page load; `app.js` never used it).
- Version is reported from package metadata (fixed the `ai-log-analyzer` →
  `netlog-ai` distribution-name mismatch that pinned `/api/health` to a hardcoded
  fallback); `pyproject.toml` bumped to 0.2.0 to match.
- Added `CONTRIBUTING.md` (the README already linked it; the file didn't exist).
- `tests/test_sources.py` no longer depends on test execution order
  (registry registration is now a per-test fixture). Suite: 237 → 246 tests.

### Added — DCN AI Intelligence port (cross-source correlation + per-device triage)

Four capabilities harvested from the legacy DCN AI Intelligence tool and re-targeted
to netlog-ai's `LogEvent` / `SourceManager` model. Each is exposed three ways: a Python
library function, an **MCP tool**, and a **web GUI** surface in the **Device** tab.

- **Cross-source correlation** — `correlate.py` · MCP tool `correlate_sources` ·
  `POST /api/correlate` · Device-tab "🔗 Cross-Source Correlation".
  Classifies each source independently and groups by device: a host with actionable
  events in **≥2 sources is `confirmed`**, in **1 source is `suspected`**. Results are
  ranked worst-severity-first with per-source coverage. Pure, O(N) over events,
  FQDN→short-host normalization, never mutates input.
- **Per-device triage** — `device_triage.py` · MCP tool `analyze_device` ·
  `POST /api/triage` · Device-tab "🔬 Device Triage".
  Per-host verdict (HARDWARE / ROUTING / LAG / LICENSE / MEMORY / SECURITY / …), a
  0–100 health score, severity histogram, top-process breakdown, and **frequency-deduped
  error patterns** that normalize hex addresses, IPs, and PIDs (e.g. 120 near-identical
  BGP errors collapse to one pattern). The `sshd` verdict only fires on real error-grade
  events, so healthy login-only devices are not mislabelled.
- **Richer root-cause knowledge base** — `kb.py`.
  Merged the DCN `_AI_KB` content (root cause / risk / resolution steps / Junos + EOS CLI)
  additively into the existing phased entries, plus new `vpn`, `redundancy`, `fpc`, and
  `chassis` categories. Backward compatible — existing KB consumers and tests unaffected.
- **Expanded classifier patterns** — `classifier.py`.
  Backfilled the missing fleet-validated syslog pattern (`inetd` / `xinetd` / `ftpd` →
  `low` / `system`), first-match ordering preserved.

### Added — web GUI wiring

- `POST /api/correlate` and `POST /api/triage` thin-wrapper routes (token-gated when
  `AI_LOG_ANALYZER_API_TOKEN` is set; ok-envelope passthrough; `400` on bad
  `min_severity` / missing `hostname`).
- Device-tab UI for both features, reusing the existing side-section / card / severity
  components — confirmed/suspected badges, per-source coverage pips, verdict banner,
  health ring, severity histogram, and deduped-pattern list.

### Security

- Both new routes validate input at the boundary; correlation/triage never raise for a
  single failing source (errors captured under `skipped`). MCP tools wrap calls so a
  backend failure returns `{ok: false, error}` rather than crashing the session.

### Tests

- 45 new tests across `test_correlate.py`, `test_device_triage.py`, `test_kb_rca.py`,
  `test_mcp_tools.py`, and `test_web_correlate_triage.py`. Full suite: **237 passing**,
  `ruff` clean. Stress-tested: correlation over 1,200 devices in ~0.02 s, triage over
  10,000 events in ~0.008 s.

### Reference

- New capabilities and both MCP tools are documented in
  [`docs/PORTED_FROM_DCN_AI.md`](docs/PORTED_FROM_DCN_AI.md), with the connector / MCP /
  HTTP surface in [`docs/CONNECTORS.md`](docs/CONNECTORS.md).

## [0.1.0]

- Initial public release: multi-vendor network log analyzer with a pluggable LLM backend
  (local Docker Model Runner or Anthropic Claude), source connectors
  (Kibana, Splunk, Loki, LibreNMS, syslog), site-bundle analysis, topology inference from
  config, compliance scanning, and a built-in MCP server.
