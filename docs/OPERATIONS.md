# Operations: durable ingest, multi-worker state, suppression, automation export

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
