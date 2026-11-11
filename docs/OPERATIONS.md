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

## Setup wizard (`netlog-ai init`)

A fresh install needs a handful of settings, not the ~90 variables in
`docs/ENVIRONMENT.md`. The wizard asks for the essentials — state DB
location, server bind, syslog source(s), LLM provider, RAG embeddings,
backup retention — and writes a working `.env` file:

```bash
netlog-ai init                 # interactive, Enter keeps the default
netlog-ai init --non-interactive --port 6060 --llm-provider openai --cloud-api-key "$OPENAI_API_KEY"
```

* **Interactive:** every question shows its default in brackets; Enter
  keeps it, so the wizard is skippable question by question. Bad input
  (a port out of range, a malformed URL, an invalid CIDR) is rejected
  with a message and re-prompted. Cloud API keys and the API token are
  read hidden (never echoed) and are optional — without a key the
  provider simply reports unavailable in `/api/llm/status` and the
  server still starts.
* **Non-interactive / scripted:** `--non-interactive` takes every value
  from flags (`--state-db`, `--host`, `--port`, `--llm-provider`,
  `--ollama-url`, `--ollama-model`, `--cloud-api-key`,
  `--allow-cloud-fallback`, `--syslog/--no-syslog`, `--syslog-bind`,
  `--syslog-port`, `--syslog-allow`, `--snmp/--no-snmp`,
  `--snmp-bind`, `--snmp-port`, `--snmp-community`,
  `--embeddings/--no-embeddings`, `--embedding-model`,
  `--hybrid-alpha`, `--triage/--no-triage`, `--backup-keep`,
  `--api-token`) or from the environment when a flag is absent, so an
  existing `.env` can be replayed. Invalid values exit 2 and write
  nothing.
* **Non-destructive:** an existing file is never overwritten silently —
  interactive mode asks, `--non-interactive` refuses unless `--force`
  is given. A file holding a secret (cloud key, API token) is chmodded
  `0600`.
* **What it writes:** only variables the app already reads (see
  `docs/ENVIRONMENT.md`) — `ANALYZER_HOST`/`ANALYZER_PORT`,
  `AI_LOG_ANALYZER_STATE_DB`, a `NETLOG_SOURCE_syslog_*` block (and a
  `NETLOG_SOURCE_traps_*` block when SNMP is enabled), `LLM_PROVIDER`
  (+ `OLLAMA_URL`/`OLLAMA_MODEL` or the provider's key variable),
  `AI_LOG_ANALYZER_EMBEDDINGS`/`AI_LOG_ANALYZER_EMBEDDING_MODEL`/
  `AI_LOG_ANALYZER_RAG_HYBRID_ALPHA`, `AI_LOG_ANALYZER_TRIAGE_WORKER`
  when enabled, `AI_LOG_ANALYZER_API_TOKEN` when set.
* **Next steps:** the wizard prints the exact commands to start the
  server and check it — `netlog-ai serve`, then
  `curl http://<host>:<port>/api/health` (expect HTTP 200) — plus
  `netlog-ai doctor`, the nightly backup cron line
  (`0 3 * * * netlog-ai backup --keep N`), the Prometheus scrape for
  `/api/metrics`, and (for Ollama + embeddings) `ollama pull
  nomic-embed-text` + `netlog-ai rag index`.
* **Where the file is read from:** the server auto-loads `<project>/.env`
  (the repo checkout root) and `~/.env`. The default output is `./.env`,
  so run the wizard and the server from the same directory in a
  checkout; with a pip install, load the file explicitly first:
  `set -a; source /path/to/.env; set +a`.

## Backup & restore

The state database is the whole incident history — back it up nightly:

```bash
# Daily snapshot, keep the newest 7 copies (default destination: <db dir>/backups)
0 3 * * * netlog-ai backup --keep 7
# Explicit destination (or AI_LOG_ANALYZER_BACKUP_DIR):
0 3 * * * netlog-ai backup --dest /var/backups/netlog-ai --keep 14
```

`netlog-ai backup` takes a consistent snapshot with the SQLite online
backup API, so it runs while the workers are alive, verifies the copy
with `PRAGMA integrity_check`, and rotates old copies. A backup is a
plain SQLite file named `<db>-YYYYMMDD-HHMMSS.db`.

Restore replaces the database — **stop the web workers and the triage
worker first**, or a live writer keeps writing to the replaced file:

```bash
systemctl stop netlog-ai        # or however the workers run
netlog-ai restore /var/lib/netlog-ai/backups/state-20261110-030000.db --force
systemctl start netlog-ai
```

`--force` is required when a database already exists at the target; the
replaced database is checkpointed first and kept as a
`.pre-restore-<timestamp>` safety copy next to it. Without `--force`,
restore refuses to overwrite and exits 1. Verify after a restore with
`netlog-ai doctor` and by opening the dashboard.

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
* **Health:** `SyslogListenerSource.stats()` reports received, spooled,
  rejected_sender, rejected_conn_limit, dropped_oversize and
  active_connections.

## SNMP trap receiver **(new in 2.3.0)**

Listens for SNMP traps on UDP (default `0.0.0.0:162`) and feeds them into
the **same pipeline as syslog** — no parallel path. Each trap is parsed
(stdlib BER decoder in `src/ai_log_analyzer/sources/snmp_proto.py`) and
rendered as one syslog-like line, e.g.
`2026-11-11T13:00:00Z 10.0.0.5 snmpd: SNMPv2c trap linkDown
(1.3.6.1.6.3.1.1.5.3) sysUpTime=12345 ifIndex.2=2
ifDescr.2=GigabitEthernet0/1`, then written to the shared durable spool by
the same `SpoolSink` the syslog listener uses. From there the classifier,
the streaming triage worker, Live Tail, the dashboard spool view and
`/api/metrics` all see traps exactly like syslog lines: the spool source
is the source id, `fetch`/`fetch_new` work the same way, and drop counters
feed the same backpressure feed (audit action `snmp_backpressure`).

| `extra` key / env | Default | Meaning |
|---|---|---|
| `bind`, `port` | `0.0.0.0`, `162` | listen address. Port 162 is privileged: run as root, grant `CAP_NET_BIND_SERVICE`, or listen on an unprivileged port and redirect 162 to it |
| `community` / `AI_LOG_ANALYZER_SNMP_COMMUNITY` | `public` | accepted SNMPv2c/v1 community strings, comma-separated; anything else is rejected and counted (`rejected_auth`) |
| `v3_users` / `AI_LOG_ANALYZER_SNMP_V3_USERS` | — | USM users, one per `;`: `name:auth_proto:auth_pass`; `name` alone means noAuthNoPriv. `auth_proto` is `md5`, `sha`/`sha1`, `sha224`, `sha256`, `sha384` or `sha512` |
| `allow` / `AI_LOG_ANALYZER_SNMP_ALLOW` | (all) | comma-separated sender IPs / CIDRs; others are dropped and counted |
| `rcvbuf` / `AI_LOG_ANALYZER_SNMP_RCVBUF` | 4 MiB | `SO_RCVBUF`; the kernel may cap it at `net.core.rmem_max` |
| `spool` / `AI_LOG_ANALYZER_SNMP_SPOOL` | `AI_LOG_ANALYZER_STATE_DB` | durable spool DB |
| `buffer_size` | 50 000 | lines kept per source (ring or spool rows) |

* **Versions:** SNMPv1 trap PDUs (generic traps map to
  `1.3.6.1.6.3.1.1.5.(generic+1)`, enterprise-specific to
  `<enterprise>.0.<specific>`), SNMPv2c, and SNMPv3/USM `noAuthNoPriv` and
  `authNoPriv` (RFC 3414 key localisation, HMAC verified over the whole
  message). **Not supported: `authPriv`** (encrypted traps) — they are
  rejected explicitly and counted (`dropped_unsupported`), so a device
  configured for privacy shows up in the counters instead of vanishing
  silently. Configure such a device for `authNoPriv` or v2c.
* **Enable it** (environment; the web UI's Sources tab accepts the same
  fields via `POST /api/sources`):
  ```sh
  NETLOG_SOURCE_traps_TYPE=snmp
  NETLOG_SOURCE_traps_URL=udp://0.0.0.0:162
  NETLOG_SOURCE_traps_BIND=0.0.0.0
  NETLOG_SOURCE_traps_PORT=162
  NETLOG_SOURCE_traps_COMMUNITY=public
  # NETLOG_SOURCE_traps_V3_USERS=trapuser:sha256:change-me
  ```
* **Test it** from a device or a workstation with `snmptrap` (net-snmp):
  ```sh
  snmptrap -v 2c -c public 127.0.0.1:162 "" 1.3.6.1.6.3.1.1.5.3 \
    1.3.6.1.2.1.2.2.1.1.2 i 2 1.3.6.1.2.1.2.2.1.2.2 s "GigabitEthernet0/1"
  ```
  then check the spool (`/api/status/overview` shows the `traps` source
  depth; Live Tail in the Logs tab lists `snmp` sources alongside `syslog`).
* **Health:** `SnmpTrapSource.stats()` reports `received`, `traps`,
  `rejected_auth`, `parse_errors`, `dropped_unsupported`, `udp_drops` and
  the spool counters; `/api/metrics` exposes them as
  `netlog_ingested_datagrams_total{source="traps"}` and
  `netlog_dropped_datagrams_total{source="traps",reason="..."}`. A second
  worker whose bind fails with EADDRINUSE becomes a *reader* of the shared
  spool, exactly like the syslog listener.

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
* **Semantic (hybrid) search (new in 2.3.0):** when Ollama serves an embedding
  model, reindexing also stores one vector per document (SQLite table
  `rag_embeddings`, float32 blobs, local only) and a search blends the BM25
  score with cosine similarity — min-max normalised per signal, weight
  `AI_LOG_ANALYZER_RAG_HYBRID_ALPHA` (default `0.5`; `1.0` is keyword-only).
  This is what lets a natural-language question ("why does BGP drop after an
  upgrade?") retrieve a stanza that shares no words with the query. Setup:
  ```bash
  ollama pull nomic-embed-text          # one-time, ~274 MB
  ai-log-analyzer rag index             # (re)builds the index and embeds it
  ai-log-analyzer rag search "why does bgp drop after an upgrade" --json
  ```
  `/api/rag/search` reports `"mode": "hybrid" | "keyword"` and an `embeddings`
  block; `/api/rag/stats` reports `embedded_docs` vs `documents`. Vectors are
  (re)embedded on reindex and on `ai-log-analyzer rag embed` (e.g. after Ollama
  was started later); changing `AI_LOG_ANALYZER_EMBEDDING_MODEL` drops the old
  vectors and re-embeds. **Without Ollama the ranking is exactly the BM25
  ranking as before** — the embedding call is best-effort and a missing,
  unreachable or model-less Ollama only ever means keyword-only search, never
  an error. Env vars: `AI_LOG_ANALYZER_EMBEDDINGS` (`auto` default, `0`/`off`
  disables vectors), `AI_LOG_ANALYZER_EMBEDDING_URL` (defaults to `OLLAMA_URL`,
  else `http://localhost:11434`), `AI_LOG_ANALYZER_EMBEDDING_MODEL` (default
  `nomic-embed-text`), `AI_LOG_ANALYZER_EMBEDDING_TIMEOUT` (default `30` s),
  `AI_LOG_ANALYZER_RAG_EMBED_BATCH` (default `32`), `AI_LOG_ANALYZER_RAG_HYBRID_ALPHA`.
  Note the vector scan is a full pass over the stored vectors per search —
  fine for a config/KB corpus of a few thousand documents, not designed for a
  million-document index.
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

* Send the token as `Authorization: Bearer <token>` or `X-API-Token`, including for the
  SSE live tail. Tokens are never accepted in the URL (`?token=`), which access logs record.
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
  * The token stays in this browser tab (`sessionStorage`) and is sent as `Authorization: Bearer` to `/api/*`, the live tail included.
  * A viewer sees dashboards; operator and admin unlock their routes.
  * The 📜 Audit log button appears for admins.
* **Status bar** (`GET /api/status/overview`, polled every 10 s; it never probes LLM providers):

| Chip | Shows | Green when |
|---|---|---|
| Spool | rows in the SQLite WAL spool, newest line age, listener counters | newest line < 5 min old |
| Triage | worker role (`active` / `standby` / `off`) and ticket count | this process holds the lease |
| Egress | 🔒 *Local only · no cloud fallback*, ☁ *Cloud fallback enabled*, ☁ *Cloud: provider* | local only |
| Vault | entities tokenized and secrets redacted on the last LLM call | last call succeeded |

* **Prometheus metrics** (`GET /api/metrics`, `viewer` role; same Bearer token as the other `/api/*` routes): spool depth (`netlog_spool_rows`), dropped datagrams (`netlog_dropped_datagrams_total`), ingest counters (`netlog_ingested_datagrams_total`, `netlog_events_per_second`), LLM calls/latency (`netlog_llm_calls_total`, `netlog_llm_call_seconds_total`) and analysis runs (`netlog_analysis_runs_total`, `netlog_analysis_seconds_total`). A scrape never writes to the state DB and never probes an LLM provider. Example scrape config:

  ```yaml
  scrape_configs:
    - job_name: netlog-ai
      static_configs:
        - targets: ['127.0.0.1:6060']
      metrics_path: /api/metrics
      # With RBAC on, add: authorization: {credentials: "<viewer-token>"}
  ```

* **Grafana dashboard** (`grafana/netlog-ai.json`, details in `grafana/README.md`):
  ingest rate (EPS), spool depth, dropped datagrams, LLM latency/errors,
  analysis time, uptime and build info — all from the scrape above (the
  dashboard expects `job="netlog-ai"`). Import: Grafana → Dashboards →
  New → Import → paste/upload the JSON → pick the Prometheus datasource
  when asked (`${DS_PROMETHEUS}`). Panels with no data yet (e.g. no LLM
  calls since process start) stay empty rather than erroring. Thresholds
  are in the panels (spool warn 25k / crit 45k rows, drops red above 0,
  LLM error rate warn 5% / crit 20%, analysis warn 10 s / crit 60 s);
  alert rules belong in Grafana Alerting, not in the dashboard JSON —
  three suggested expressions are in `grafana/README.md`.

* **Incident cards:** one per suppression root (platform, device unreachable, transport) and per cross-vendor cluster that no root explains.
  * Each card shows the shared peer IPs, ASNs, tunnels, VRFs, /30–/31 subnets and interfaces.
  * The suppressed downstream alerts are behind an expandable section.
  * In Action Items, suppressed rows are hidden by default; their "↳ suppressed by ROOT-…" chip jumps to the card.
* **Remediation:** pick device, vendor, action and interface, or use "Guarded plan for this link" on a card. Switch between Vendor CLI, Ansible (YAML, with the `check_mode: true` dry-run task) and Nornir, and download the file.
* **Guardrail:** any `# BLOCKED by SafetyGuardrail` line is badged ⛔ GUARDRAIL, and its ▶ Run button is disabled.
* **Evidence:** `[S#]` in a playbook's root cause or a Copilot answer opens the cited item.
  * Drift items show the running (+) and golden (−) lines.
  * Labels the model invented are struck through and flagged unverified.
