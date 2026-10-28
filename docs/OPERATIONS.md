# Operations: durable ingest, multi-worker state, suppression, automation export, retrieval, triage, RBAC

## Shared state for multi-worker deployments

Set one SQLite database for every Gunicorn worker on the host:

```bash
AI_LOG_ANALYZER_STATE_DB=/var/lib/netlog-ai/state.db
```

It runs in WAL mode, so readers never block the writer and writers serialize
with a busy timeout. Connections are per thread and reopened after `fork()`.
The database holds:

| Table | Replaces | Effect |
|---|---|---|
| `syslog_spool` | in-memory ring buffer | syslog lines survive restarts; every worker reads the same stream |
| `incidents` | unlocked JSONL rewrite | recurrence badges and `/api/incidents/similar` are consistent across workers |
| `kv` (`llm` namespace) | per-process `_state` | `/api/llm/provider` and `/api/llm/toggle` apply to all workers within ~1 s (API keys are never stored) |

`AI_LOG_ANALYZER_INCIDENT_STORE` still works:

* A path ending in `.db`, `.sqlite` or `.sqlite3` uses the SQLite backend.
* Any other path uses JSONL, now protected by an `fcntl` lock on `<path>.lock`.
  The file is re-read before a cap rewrite, so concurrent workers neither tear
  lines nor drop each other's records. The lock is POSIX only; on Windows the
  JSONL writes stay unlocked.

## Syslog listener

| `extra` key / env | Default | Meaning |
|---|---|---|
| `proto` | `udp` | `udp`, `tcp`, or `tls` (RFC 5425; also implied by `tls_cert` with `tcp`) |
| `bind`, `port` | `127.0.0.1`, `5514` | listen address |
| `rcvbuf` / `AI_LOG_ANALYZER_SYSLOG_RCVBUF` | 4 MiB | `SO_RCVBUF`; the kernel may cap it at `net.core.rmem_max` |
| `allow` / `AI_LOG_ANALYZER_SYSLOG_ALLOW` | (all) | comma-separated sender IPs / CIDRs; others are dropped and counted |
| `tls_cert`, `tls_key`, `tls_ca` | — | server cert/key; `tls_ca` turns on mutual TLS |
| `max_frame` | 65536 | larger RFC 6587 frames are discarded without losing framing |
| `max_connections`, `idle_timeout` | 512, 300 s | TCP/TLS connection limits |
| `spool` / `AI_LOG_ANALYZER_SYSLOG_SPOOL` | `AI_LOG_ANALYZER_STATE_DB` | durable spool DB |
| `buffer_size` | 50 000 | lines kept per source (ring or spool rows) |
| `max_bytes` | 64 MiB | memory ring only: bytes retained before the oldest lines are evicted (`ring_evicted`) |
| `queue_max`, `queue_max_bytes` | 200 000, 128 MiB | spool writer queue: lines / bytes waiting for SQLite before new lines are dropped and counted (`queue_overflow`, `queue_overflow_bytes`, `spool_lines_lost`) |

* **Concurrency:** TCP and TLS run on one asyncio loop, so many senders are
  served at once and an idle or slow connection never blocks the others.
* **Framing:** each message may use RFC 6587 octet-counting (`LEN SP MSG`) or
  LF framing. Line breaks inside an octet-counted frame are folded to spaces.
* **Sender attribution:** a line without a hostname header is attributed to
  its sender IP instead of the literal `syslog`. Every event carries
  `attrs.sender_ip`, which suppression also uses to learn device addresses.
* **Workers:** UDP no longer sets `SO_REUSEADDR`; on Linux that option let a
  second worker bind the same port and take half the datagrams. With a spool
  configured, a worker whose bind fails becomes a *reader* of the shared spool
  (`stats()["role"] == "reader"`). Without a spool the bind error is raised as
  before.
* **Memory:** a line can be 64 KiB, so the ring and the writer queue are
  bounded in bytes as well as in lines. With a spool no line is kept in the
  ring (the spool is what `fetch` reads).
* **Health:** `SyslogListenerSource.stats()` reports received, spooled,
  rejected_sender, rejected_conn_limit, dropped_oversize,
  active_connections, ring_bytes, writer_queue_bytes and ring_evicted.

## Topology-aware suppression

`AnalysisResult.suppression` groups dependent alerts under their root. Root
kinds, strongest first:

* `platform`: firewall HA failover or split-brain (the HA peer is folded in),
  conserve mode, session-table exhaustion.
* `device_unreachable`: at least 2 devices lose sessions to addresses one
  device owns. Inferred even when the failed device logs nothing.
* `transport`: SD-WAN SLA, BFD, control connection, IPsec/IKE or link down.

Each suppressed action item carries `suppressed_by` and ranks below the live
roots of the same severity. Webhooks page the roots only and add a
`suppressed_alerts` count.

Address ownership comes from the logs (sender IP, FortiOS `locip`, Junos
`Local-ip`, SD-WAN system IP, the far end of a /30–/31 BGP session). It can
also come from an optional dependency map set in `AI_LOG_ANALYZER_DEPENDENCIES`
or passed as the analysis `site_manifest`:

```json
{"devices": {"core-01": {"ips": ["10.0.0.2", "10.0.0.4"], "children": ["leaf-01", "leaf-02"],
                         "ha_peer": "core-02", "role": "core"}}}
```

## Ansible / Nornir export

```bash
ai-log-analyzer remediation --device leaf1 --vendor arista_eos --interface Ethernet1 --format ansible > drain.yml
ansible-playbook -i inventory drain.yml --check --diff     # dry run, nothing applied
ansible-playbook -i inventory drain.yml --diff             # apply → verify → persist; rescue rolls back
```

The same export is available on `POST /api/remediation` with `"export": "ansible"|"nornir"`
and on the MCP tool `generate_remediation_plan(export=...)`.

| Vendor | Collection | Rollback in `rescue` |
|---|---|---|
| IOS-XE | `cisco.ios` | inverse change (drain); manual instructions for custom CLI |
| NX-OS | `cisco.nxos` | `checkpoint` before apply → `nxos_rollback` |
| EOS | `arista.eos` | inverse change (drain) |
| Junos | `junipernetworks.junos` (netconf) | native `commit confirmed N`; `rollback 1` on failure |
| FortiOS | `fortinet.fortios` (httpapi) | interface status back up (drain only) |
| PAN-OS | `paloaltonetworks.panos` | named config snapshot → load + commit (drain only) |
| FRR | `ansible.builtin` + `vtysh` | `frr.conf` backup restore + reload |
| Cisco SD-WAN | — | refused: change template-managed edges through vManage (`cisco.catalystwan`) |

Every export re-screens the change and its inverse through `SafetyGuardrail`.
The rollback runs only when the apply step actually changed the device.
Post-checks fail the play only if a command errors. Add `wait_for` conditions
for your success criteria before relying on the automatic rescue.

Check-mode and diff support depend on the collection version, so run the dry
run against a lab device first. The Nornir export uses `nornir_napalm`
(`napalm_configure(dry_run=True)` by default, `--apply` to commit) for IOS,
EOS, Junos and NX-OS.

## Retrieval index (RAG)

Every playbook and Copilot answer can cite evidence an engineer can open:

| Kind | Source | Citation |
|---|---|---|
| `config` | running config stanza, original line numbers | `leaf1 running-config L102-L118 \`router bgp 65001\`` |
| `drift` | running vs golden diff hunk | `leaf1 drift vs golden L115-L115 \`router bgp 65001\`` |
| `topology` | NetBox devices + cables, or a site `manifest.json` | `NetBox device leaf1 (role leaf, site DC1)` |
| `runbook` | curated KB playbooks | `KB runbook routing/bgp_hold_timer` |
| `incident` | incident store; resolutions are precedents | `INC-000042 (2026-10-01, resolved)` |

```bash
AI_LOG_ANALYZER_STATE_DB=/var/lib/netlog-ai/state.db \
AI_LOG_ANALYZER_GOLDEN_DIR=/etc/netlog-ai/golden \
ai-log-analyzer rag index --netbox          # KB + site configs + drift + NetBox + incidents
ai-log-analyzer rag search "neighbor 10.0.1.0 hold timer" --hosts leaf1
ai-log-analyzer rag drift running.cfg golden.cfg
```

* **Storage:** SQLite tables `rag_docs` / `rag_postings` in `AI_LOG_ANALYZER_RAG_DB`
  or the state DB. Ranking is BM25 computed locally; nothing leaves the host.
* **Golden configs:** `<golden_dir>/<site>/<host>.txt`, `<golden_dir>/<host>.txt`, or
  a `golden/` folder inside a site bundle. Banner lines that change on every
  commit (last-change stamps, "Building configuration") are ignored.
* **Secrets:** stanza bodies are passed through `sanitize()` before they are stored.
* **Incidents:** each analysis syncs new and changed incident-store records
  before it runs, so an item never cites itself. Record the fix with
  `POST /api/incidents/<id>/resolve {"resolution": "..."}` to turn an incident into
  a precedent.
* **In playbooks:** `deep_analysis.evidence` lists S1..Sn for the affected devices
  (configs and drift only for those devices). With the LLM on, the model gets
  the evidence as fenced numbered sources and must cite `[S#]`;
  `deep_analysis.citations.invalid` lists labels it invented.
* **Off switch:** `AI_LOG_ANALYZER_RAG=0`.

## Streaming triage worker

The worker turns the spool into tickets without anyone uploading logs:

```bash
AI_LOG_ANALYZER_STATE_DB=/var/lib/netlog-ai/state.db \
AI_LOG_ANALYZER_TRIAGE_SINKS=servicenow,webhook \
ai-log-analyzer triage-worker            # or AI_LOG_ANALYZER_TRIAGE_WORKER=true with the web app
```

| Setting | Default | Meaning |
|---|---|---|
| `AI_LOG_ANALYZER_TRIAGE_WINDOW_S` | 300 | sliding correlation window |
| `AI_LOG_ANALYZER_TRIAGE_POLL_S` | 15 | tick interval |
| `AI_LOG_ANALYZER_TRIAGE_MIN_SEVERITY` | high | lowest severity that opens a ticket |
| `AI_LOG_ANALYZER_TRIAGE_COOLDOWN_S` | 900 | per-incident quiet period after a send |
| `AI_LOG_ANALYZER_TRIAGE_MAX_TICKETS_PER_HOUR` | 30 | global send budget; excess is deferred |
| `AI_LOG_ANALYZER_TRIAGE_SINKS` | dry-run | `jira`, `servicenow`, `webhook`, `dry-run` |
| `AI_LOG_ANALYZER_TRIAGE_USE_LLM` | false | LLM playbooks (KB playbooks otherwise) |

Per tick: new spool rows (oldest first, from a cursor stored in the state DB)
→ parse → drop exact duplicates within 5 s → classify → window → entity
pairing, topology-aware suppression and grouping → one incident per root and
per remaining unsuppressed group at or above the minimum severity.

* **Ticket identity** is site + device + layer, so an incident keeps one ticket
  when it gains dependents or a second interface.
* **Cooldown:** within the cooldown new events are held. A severity escalation
  or a state change (for example, all entities recovered) bypasses it. After
  the cooldown an update is sent only if events arrived since the last send.
* **Self-healed** groups (down then up inside the window) never open a ticket.
* **Rate limit:** sends beyond the hourly budget are deferred to later ticks;
  failed deliveries are retried on the next tick.
* **One active worker:** a lease in the state DB elects the worker that
  processes the spool; the others report `standby`.
* **Payload:** the RCA card, the playbook's commands per phase, cited
  evidence, sample events, related alerts and, for interface faults with a
  known vendor, a guarded drain plan plus its Ansible playbook (run with
  `--check --diff` first). Nothing is executed on devices.

## RBAC and audit trail

| Role | Can |
|---|---|
| `viewer` | incident search, live tail, triage status, retrieval search, full `/api/llm/status` |
| `operator` | viewer + analyze, correlate, triage, copilot, remediation plans, ITSM enrichment, resolve incidents, drift |
| `admin` | operator + `/api/run`, LLM provider / toggle, sources and rules, triage worker control, index rebuild, audit log |

```bash
AI_LOG_ANALYZER_OPERATOR_TOKENS="alice:$(openssl rand -hex 24)"
AI_LOG_ANALYZER_RBAC_FILE=/etc/netlog-ai/rbac.json
# {"users": [{"name": "noc-wall", "role": "viewer", "token_sha256": "<sha256 of the token>"}]}
```

* Send the token as `Authorization: Bearer <token>` or `X-API-Token`; the SSE live
  tail also accepts `?token=`.
* `AI_LOG_ANALYZER_API_TOKEN` keeps working as the `admin` role.
* With no principal configured the API stays in dev mode (open, localhost bind).

The audit log lives in the state DB (or `AI_LOG_ANALYZER_AUDIT_DB`):

* **Append-only:** triggers reject UPDATE and DELETE.
* **Tamper-evident:** every row stores the SHA-256 of the previous row and itself,
  so `GET /api/audit/verify` finds an edit made outside SQLite.
* **Recorded:** `/api/run` (host and command), LLM provider/toggle changes,
  source and rule changes, ITSM writes, incident resolutions, triage worker
  control and tickets, denied attempts (`authz.denied`), and every cloud LLM
  call (provider, prompt size, redaction count, never content).
  Set `AI_LOG_ANALYZER_AUDIT_LLM=all` to include local providers.
* **Query:** `GET /api/audit?actor=alice&action=llm.*&since=<epoch>&limit=100`.

## Golden-incident evaluation

```bash
ai-log-analyzer eval --golden --min-golden 0.99   # CI gate
```

Replays the labeled incidents in `src/ai_log_analyzer/data/eval/` (EVPN
underlay cascade, BGP route leak + flap, FortiGate SD-WAN/IPsec cascade,
PAN-OS HA failover) offline. The LLM is a deterministic stub, so the run
measures the pipeline around the model:

| Dimension | Passes when |
|---|---|
| `rca` | the labeled root is the top live item; required alerts found, false positives absent; dependents suppressed under the expected root kind; expected states and BGP anomaly classes reported |
| `detokenize` | no raw IP or affected hostname reaches the (cloud) provider prompt, and echoed tokens are restored in the playbook |
| `guardrail` | the destructive CLI the stub injects (zeroize, reload, clear bgp *, factory reset, private-data reset, write erase) never reaches a playbook |
| `evidence` | the expected config / drift evidence is attached and every `[S#]` citation resolves |

Add a case by dropping a JSON file with `logs`, optional `configs` / `golden` /
`site`, and an `expect` block into that directory (or pass `--cases DIR`).

## Dashboard (V2)

* **Sign in:** with RBAC on, click the 👤 chip next to the brand and paste a token.
  * The token stays in this browser tab (`sessionStorage`) and is sent as `Authorization: Bearer` to `/api/*`, or as `?token=` for the live tail.
  * A viewer sees dashboards; operator and admin unlock their routes.
  * The 📜 Audit log button appears for admins.
* **Status bar** (`GET /api/status/overview`, polled every 10 s; it never probes LLM providers):

| Chip | Shows | Green when |
|---|---|---|
| Spool | rows in the SQLite WAL spool, newest line age, listener counters | newest line < 5 min old |
| Triage | worker role (`active` / `standby` / `off`) and ticket count | this process holds the lease |
| Egress | 🔒 *Local only · no cloud fallback*, ☁ *Cloud fallback enabled*, ☁ *Cloud: provider* | local only |
| Vault | entities tokenized and secrets redacted on the last LLM call | last call succeeded |

* **Incident cards:** one per suppression root (platform, device unreachable, transport) and per cross-vendor cluster that no root explains.
  * Each card shows the shared peer IPs, ASNs, tunnels, VRFs, /30–/31 subnets and interfaces.
  * The suppressed downstream alerts are behind an expandable section.
  * In Action Items, suppressed rows are hidden by default; their "↳ suppressed by ROOT-…" chip jumps to the card.
* **Remediation:** pick device, vendor, action and interface, or use "Guarded plan for this link" on a card. Switch between Vendor CLI, Ansible (YAML, with the `check_mode: true` dry-run task) and Nornir, and download the file.
* **Guardrail:** any `# BLOCKED by SafetyGuardrail` line is badged ⛔ GUARDRAIL, and its ▶ Run button is disabled.
* **Evidence:** `[S#]` in a playbook's root cause or a Copilot answer opens the cited item.
  * Drift items show the running (+) and golden (−) lines.
  * Labels the model invented are struck through and flagged unverified.
