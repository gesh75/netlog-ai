# Environment variables

Every environment variable netlog-ai reads. `tests/test_docs_env.py` fails when a
variable read in `src/` is missing from this page, so it cannot silently drift.
A commented, copy-pasteable version lives in [`.env.example`](../.env.example).

Nothing is required: with no configuration the tool runs against the bundled demo data
and a local Ollama on `localhost:11434`.

**Boolean values** accept `1/true/yes/on` (case-insensitive) unless a row says otherwise.
**Secrets** (tokens, passwords, API keys) are never logged or echoed by the app; keep them in
the process environment or a `.env` file with owner-only permissions, never in git.

## `.env` loading

At import time the package loads, in priority order (a variable already set in the real
environment always wins; `.env` never overrides it):

1. `<project>/.env`
2. `~/.env`
3. `../DCN_Network_Tool/.env`
4. `../DCN_AI_Intelligence/.env`

Because `~/.env` and sibling-project files are read, a stray file there can change behavior.
Set `AI_LOG_ANALYZER_DEBUG=1` to print which files were loaded.

Items marked **(new in 2.2.0)** are introduced by this release's hardening work; see the
CHANGELOG for the exact semantics shipped.

## Server and security

| Variable | Default | Purpose / notes |
| --- | --- | --- |
| `ANALYZER_PORT` | `6060` | TCP port for the built-in web server (`netlog-ai serve` / `web.app:main`). |
| `ANALYZER_HOST` | `127.0.0.1` | Bind address. **Security:** `0.0.0.0` exposes the API to the network; do that only with authentication configured (a warning is printed otherwise). |
| `AI_LOG_ANALYZER_API_TOKEN` | unset | Legacy shared token, treated as role `admin`. When set, API routes require it as `X-API-Token: <token>` or `Authorization: Bearer <token>`. **Security:** with no token and no RBAC tokens, all routes are unauthenticated. |
| `AI_LOG_ANALYZER_VIEWER_TOKENS` | unset | RBAC: comma-separated `name:token` pairs with role `viewer` (read-only). A bare token gets a generated name. Setting any RBAC token turns auth on. |
| `AI_LOG_ANALYZER_OPERATOR_TOKENS` | unset | Same format, role `operator` (viewer plus running analyses, ITSM enrichment and incident resolution). |
| `AI_LOG_ANALYZER_ADMIN_TOKENS` | unset | Same format, role `admin` (everything, including provider, rules, source and triage-worker control). |
| `AI_LOG_ANALYZER_RBAC_FILE` | unset | JSON file `{"users": [{"name", "role", "token_sha256"}]}`. Prefer `token_sha256` so the file holds no usable secret. |
| `AI_LOG_ANALYZER_REQUIRE_AUTH` | `false` (`1` in the Docker image) | **(new in 2.2.0)** When set, `create_app()` raises at startup unless an API token or RBAC principal is configured, so a gunicorn deployment can never start open. |
| `AI_LOG_ANALYZER_ALLOW_NOAUTH` | `false` | **(new in 2.2.0)** `python -m` / `main()` refuses to bind a non-loopback address without a token unless this is `1`. Demos and isolated labs only. |
| `AI_LOG_ANALYZER_ITSM_ALLOW_PRIVATE` | `false` | **(new in 2.2.0)** Lets the ServiceNow sync reach a private-range instance URL. Read from the server environment only; request bodies cannot set it. |
| `AI_LOG_ANALYZER_ALLOWED_HOSTS` | `localhost,127.0.0.1,[::1]` plus `ANALYZER_HOST` | **(new in 2.2.0)** Comma-separated `Host` header allow-list (DNS-rebinding defense). Enforced only while authentication is off; a bad Host gets 400. `*` disables the check. |
| `AI_LOG_ANALYZER_MAX_SSE` | `8` | **(new in 2.2.0)** Maximum concurrent server-sent-event streams (`/api/tail`); further clients get 503. |
| `AI_LOG_ANALYZER_MAX_CONTENT_LENGTH` | `16777216` (16 MiB) | **(new in 2.2.0)** Maximum request body size; larger requests get a JSON 413. |
| `AI_LOG_ANALYZER_CORS_ORIGINS` | `http://localhost:6060,http://127.0.0.1:6060` | Comma-separated CORS allow-list for `/api/*`. Never use `*` together with authentication. |
| `AI_LOG_ANALYZER_FILE_ROOTS` | `/var/log` plus `AI_LOG_ANALYZER_DATA_DIR` | Colon-separated directories that `POST /api/analyze {"source":"file"}` may read. Dotfiles, dot-directories and credential/state filenames are denied under every root. **Security:** keep it as narrow as you can; `$HOME` and the repo checkout are no longer included by default. |
| `AI_LOG_ANALYZER_MAX_FILE_MB` | `200` | Web-route cap for single-file analysis (MB). Use the CLI for larger files. |
| `AI_LOG_ANALYZER_SAMPLES_DIR` | packaged `data/samples` | Override the demo samples directory. |
| `AI_LOG_ANALYZER_SITES_DIR` | packaged `data/sites` | Override the site manifests / golden-config directory (web app, CLI and MCP server). |
| `AI_LOG_ANALYZER_DATA_DIR` | unset | **(new in 2.2.0)** One extra directory, besides `/var/log`, from which file analysis may read (for example the container's `/data` volume). |
| `AI_LOG_ANALYZER_PSEUDONYM_KEY` | random per process | **(new in 2.2.0)** HMAC key for PUB-/user- pseudonym tokens. Each gunicorn worker generates its own random key, so tokens differ per worker and after a restart; set a long random value for stable tokens. **Security:** treat as a secret; anyone holding it can regenerate the tokens. |
| `NETLOG_ALLOW_INSECURE_HTTP` | `false` | **(new in 2.2.0)** Allow plain `http://` for the ITSM and ServiceNow integrations (they require `https://` otherwise, except for private test hosts). **Security:** sends credentials in clear text. |
| `NETLOG_ALLOW_PRIVATE_OUTBOUND` | `false` | **(new in 2.2.0)** Lets network connectors (Kibana, Splunk, Loki, LibreNMS, ServiceNow, SolarWinds) reach private, loopback and non-resolving hosts. A URL set by the operator through `NETLOG_SOURCE_<id>_URL` / `SOLARWINDS_URL` is already trusted; this is for sources added at runtime. NetBox keeps private addresses allowed because `NETBOX_URL` is operator-set. |
| `AI_LOG_ANALYZER_DEBUG` | unset | Any non-empty value prints which `.env` files were loaded. |

## LLM gateway

Sanitization always runs before any provider call; these settings only choose where sanitized
text goes. Operator-mutable runtime toggles (provider, enabled, cloud fallback, hostname
tokenization) are shared across workers through the state DB, API keys never are.

| Variable | Default | Purpose / notes |
| --- | --- | --- |
| `LLM_PROVIDER` | `ollama` | `ollama`, `local` (Docker Model Runner), `claude`, `claude-only`, `grok`. |
| `LLM_ENABLED` | `true` | Master switch for LLM calls (`true`/`false` only). |
| `LLM_TIMEOUT` | `120` | Per-request timeout in seconds. |
| `LLM_TOTAL_TIMEOUT_S` | `180` | **(new in 2.2.0)** Overall wall-clock budget for one gateway call across providers, retries and backoff; per-request timeouts shrink to what is left. `0` = unlimited. |
| `LLM_BREAKER_THRESHOLD` | `3` | **(new in 2.2.0)** Consecutive failures after which a provider's circuit opens and it is skipped. `0` disables the breaker. |
| `LLM_BREAKER_COOLDOWN_S` | `60` | **(new in 2.2.0)** Seconds an open circuit stays open before one trial call is allowed. State is per process. |
| `LLM_LOCAL_HOSTS` | empty | **(new in 2.2.0)** Comma-separated hostnames to treat as local for the egress policy. An `OLLAMA_URL` / `MODEL_RUNNER_URL` on any other off-host name reports mode `remote-host`. |
| `LLM_MODEL` | `ai/qwen3:latest` | Model for the local Docker Model Runner. |
| `MODEL_RUNNER_URL` | `http://localhost:12434` | Docker Model Runner base URL. |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama native API base URL. |
| `OLLAMA_MODEL` | `qwen2.5-coder:latest` | Ollama model. |
| `OLLAMA_NUM_CTX` | `0` (server default) | Ollama context window in tokens. Ollama silently truncates at its own window, so set it to match `LLM_MAX_PROMPT_CHARS_OLLAMA` (about 4 chars per token). |
| `ANTHROPIC_API_KEY` | unset | Anthropic API key. **Secret.** |
| `ANTHROPIC_MODEL` | `claude-haiku-4-5-20251001` | Anthropic model. |
| `XAI_API_KEY` | unset | xAI Grok API key. **Secret.** |
| `XAI_MODEL` | `grok-4` | xAI model. |
| `XAI_URL` | `https://api.x.ai/v1` | xAI OpenAI-compatible endpoint. |
| `ALLOW_CLOUD_FALLBACK` | `false` | Whether a local provider may fall back to a cloud API (and claude and grok may fall back to each other). Takes precedence over `LLM_ALLOW_CLOUD_FALLBACK`. **Security (data egress):** leave `false` unless sanitized text may leave the site. |
| `LLM_ALLOW_CLOUD_FALLBACK` | `false` | Same setting under the `LLM_` prefix; used when `ALLOW_CLOUD_FALLBACK` is unset. |
| `LLM_TOKENIZE_HOSTNAMES` | `auto` | Hostname pseudonyms (`<HOST_n>`): `auto` (cloud providers only), `always`, `never`. |
| `LLM_MAX_PROMPT_CHARS` | per provider | Global prompt budget in characters (`0` = unlimited). Built-in defaults: ollama/local 48000, claude 600000, grok 400000. |
| `LLM_MAX_PROMPT_CHARS_<PROVIDER>` | falls back to `LLM_MAX_PROMPT_CHARS` | Per-provider override, e.g. `LLM_MAX_PROMPT_CHARS_OLLAMA`, `_LOCAL`, `_CLAUDE`, `_GROK`. |
| `LLM_MAX_RETRIES` | `2` | Retries on HTTP 408/429/5xx with exponential backoff. |
| `LLM_BACKOFF_BASE` | `1.0` | Backoff base in seconds. |
| `LLM_BACKOFF_MAX` | `20.0` | Backoff cap in seconds. |
| `AI_LOG_ANALYZER_AUDIT_LLM` | `cloud` | Which provider calls are audited (sizes and counts only, never content): `cloud`, `all`, `off`. |
| `AI_LOG_ANALYZER_VAULT_MAX_ENTRIES` | `4096` | Bound on the process-wide reversible entity vault. |
| `AI_LOG_ANALYZER_VAULT_TTL_SECONDS` | `3600` | Vault entry lifetime in seconds (`0` = no expiry). |

## State, storage and retrieval

| Variable | Default | Purpose / notes |
| --- | --- | --- |
| `AI_LOG_ANALYZER_STATE_DB` | unset | Shared SQLite (WAL) file for the syslog spool, incident memory, audit log, retrieval index and runtime toggles. Required for multi-worker deployments and the streaming triage worker. |
| `AI_LOG_ANALYZER_SQLITE_SYNC` | SQLite default | **(new in 2.2.0)** SQLite `synchronous` level (`OFF`, `NORMAL`, `FULL`) for the state DB; trade durability against write speed. |
| `AI_LOG_ANALYZER_SYSLOG_SPOOL` | the state DB | Separate syslog spool DB. |
| `AI_LOG_ANALYZER_INCIDENT_STORE` | unset | Incident journal: a `*.jsonl` path, or a `*.db`/`*.sqlite` path. Falls back to the state DB. Local only, bounded. |
| `AI_LOG_ANALYZER_AUDIT_DB` | the state DB | Audit log database. Auditing is on when this or the state DB is set. |
| `AI_LOG_ANALYZER_RAG_DB` | the state DB | Retrieval (BM25) index database. |
| `AI_LOG_ANALYZER_RAG` | enabled | Set to `0`, `false`, `off` or `no` to disable evidence retrieval. |
| `AI_LOG_ANALYZER_RAG_REFRESH_SECONDS` | `30` | **(new in 2.2.0)** How often a search re-checks site config files for changes and re-indexes them. `0` = check on every search; negative = never. |
| `AI_LOG_ANALYZER_GOLDEN_DIR` | unset | Golden configs for drift detection: `<site>/<host>.txt` or `<host>.txt`. |
| `AI_LOG_ANALYZER_TEMPLATE_STORE` | unset | JSON file remembering mined log templates across runs, to flag never-seen patterns. Written owner-only. |
| `AI_LOG_ANALYZER_CUSTOM_RULES` | unset | JSON list of custom classification rules loaded at startup; they override the built-in knowledge base. |
| `AI_LOG_ANALYZER_DEPENDENCIES` | unset | JSON dependency map for topology-aware suppression. |

## Analysis tuning

| Variable | Default | Purpose / notes |
| --- | --- | --- |
| `AI_LOG_ANALYZER_DEDUP` | off | Collapse near-identical lines before classification. |
| `AI_LOG_ANALYZER_DEDUP_MAX_CLUSTERS` | `20000` | **(new in 2.2.0)** Upper bound on distinct dedup clusters kept per run; further shapes fall into one overflow cluster so memory stays bounded. |
| `AI_LOG_ANALYZER_EVPN_CAUSAL` | off | Enable the protocol-aware EVPN causal overlay by default. |
| `AI_LOG_ANALYZER_MAX_LINE_BYTES` | `65536` | Longer log lines are truncated before parsing (protects against pathological input). |
| `AI_LOG_ANALYZER_MAX_FILE_BYTES` | `0` (unlimited) | Cap on the bytes read from one file by the ingest layer. |
| `AI_LOG_ANALYZER_FLAP_THRESHOLD` | `3` | State transitions within the window that count as a flap. |
| `AI_LOG_ANALYZER_FLAP_WINDOW_S` | `600` | Flap detection window in seconds. |

## Streaming triage worker and webhooks

| Variable | Default | Purpose / notes |
| --- | --- | --- |
| `AI_LOG_ANALYZER_TRIAGE_WORKER` | `false` | Start the streaming triage worker inside the web app (needs the state DB). |
| `AI_LOG_ANALYZER_TRIAGE_SINKS` | `dry-run` | Comma list of `jira`, `servicenow`, `webhook`, `dry-run`. **Security:** defaults to dry-run so nothing external happens by accident. |
| `AI_LOG_ANALYZER_TRIAGE_MIN_SEVERITY` | `high` | Minimum severity that opens a ticket. |
| `AI_LOG_ANALYZER_TRIAGE_WINDOW_S` | `300` | Correlation window in seconds. |
| `AI_LOG_ANALYZER_TRIAGE_POLL_S` | `15` | Spool poll interval in seconds. |
| `AI_LOG_ANALYZER_TRIAGE_TICK_BUDGET_S` | `10` | **(new in 2.2.0)** Time budget for one triage tick. A tick keeps draining full batches from the spool until it is empty or this budget is spent, then re-polls immediately. |
| `AI_LOG_ANALYZER_TRIAGE_RETENTION_DAYS` | `30` | **(new in 2.2.0)** Age after which non-active triage ticket records are pruned. |
| `AI_LOG_ANALYZER_TRIAGE_COOLDOWN_S` | `900` | Per-incident ticket cooldown in seconds. |
| `AI_LOG_ANALYZER_TRIAGE_MAX_TICKETS_PER_HOUR` | `30` | Hard cap on tickets per hour. |
| `AI_LOG_ANALYZER_TRIAGE_MAX_PER_SENDER_PER_HOUR` | `0` (half the hourly cap, at least 2) | Most tickets per hour that incidents from one syslog sender address may use, so one source cannot spend the whole budget. Set it to the hourly cap if every device reaches the listener through one collector. |
| `AI_LOG_ANALYZER_TRIAGE_MAX_PER_DEVICE_PER_HOUR` | `0` (a fifth of the hourly cap, at least 2) | Most tickets per hour one device may use. |
| `AI_LOG_ANALYZER_TRIAGE_MAX_PENDING_PER_SENDER` | `100` | Most deferred incidents one sender may keep parked; further ones are dropped and counted (`dropped`). `0` = no limit. |
| `AI_LOG_ANALYZER_TRIAGE_SITE` | `default` | Site label stamped on triage incidents. |
| `AI_LOG_ANALYZER_TRIAGE_USE_LLM` | `false` | Allow the LLM in triage (sanitized first). |
| `AI_LOG_ANALYZER_TRIAGE_SOURCES` | unset | Comma list of registered source ids to include; empty means all. |
| `AI_LOG_ANALYZER_WEBHOOK_URL` | unset | Alert webhook target (required by the `webhook` sink). **Security:** server-side request to an operator-supplied URL; use `https://`. |
| `AI_LOG_ANALYZER_WEBHOOK_MIN_SEVERITY` | `high` | `critical`, `high`, `medium` or `low`. |
| `AI_LOG_ANALYZER_WEBHOOK_FORMAT` | `generic` | `generic` or `slack`. |

## Log sources

| Variable | Default | Purpose / notes |
| --- | --- | --- |
| `NETLOG_SOURCE_<id>_<KEY>` | unset | Defines a log source. A source needs `TYPE` and `URL`. Other keys: `API_TOKEN`, `USERNAME`, `PASSWORD`, `COOKIES` (`k=v;k=v`), `AUTH_METHODS` (default `api_token,basic,cookie`), `VERIFY_TLS` (default `true`; only the literal `false` disables), `TIMEOUT_SECONDS` (default `30`), plus type-specific keys (for example `INDEX_PATTERN`, `PORT`, `BIND`, `ALLOW`, `SPOOL`, `RCVBUF`, `MODE`). See [CONNECTORS.md](CONNECTORS.md). **Security:** the URL is fetched server-side; point it only at systems you operate. |
| `AI_LOG_ANALYZER_SYSLOG_ALLOW` | unset (allow all) | Syslog sender allow-list (IPs or CIDRs). **Security:** set this on any listener reachable from untrusted networks. |
| `AI_LOG_ANALYZER_SYSLOG_RCVBUF` | `4194304` | UDP socket receive buffer in bytes. |
| `NETLOG_DEMO_SYSLOG_PORT` | `5514` | UDP port for the `demo` command's built-in syslog listener (loopback only). |
| `SOLARWINDS_URL` | unset | SolarWinds Orion SWIS or Observability endpoint; presence enables the native source. |
| `SOLARWINDS_USERNAME` | unset | Basic-auth user. |
| `SOLARWINDS_PASSWORD` | unset | Basic-auth password. **Secret.** |
| `SOLARWINDS_TOKEN` | unset | Bearer token (preferred over user/password). **Secret.** |
| `SOLARWINDS_MODE` | `swis` | `swis` or `saas`. |
| `SOLARWINDS_VERIFY_SSL` | `true` | Verify TLS certificates. Disabling it permits man-in-the-middle attacks. |

## ITSM, NetBox and device tooling

| Variable | Default | Purpose / notes |
| --- | --- | --- |
| `JIRA_URL` | unset | Jira base URL. |
| `JIRA_BASE_URL` | unset | Alias for `JIRA_URL` (used when `JIRA_URL` is unset by the web app and MCP server). |
| `JIRA_EMAIL` | unset | Jira account email. |
| `JIRA_API_TOKEN` | unset | Jira API token. **Secret.** |
| `JIRA_PROJECT_KEY` | `NET` | Project that receives tickets. |
| `SERVICENOW_URL` | unset | ServiceNow instance URL. |
| `SNOW_URL` | unset | Alias for `SERVICENOW_URL`. |
| `SERVICENOW_USER` | unset | ServiceNow user. |
| `SNOW_USER` | unset | Alias for `SERVICENOW_USER`. |
| `SERVICENOW_PASSWORD` | unset | ServiceNow password. **Secret.** |
| `SNOW_PASSWORD` | unset | Alias for `SERVICENOW_PASSWORD`. **Secret.** |
| `SERVICENOW_TOKEN` | unset | ServiceNow bearer token (instead of user/password). **Secret.** |
| `NETBOX_URL` | unset | NetBox base URL. Enrichment is enabled only when both `NETBOX_URL` and `NETBOX_TOKEN` are set. |
| `NETBOX_TOKEN` | unset | NetBox API token (read-only token recommended). **Secret.** |
| `DCN_TOOL_URL` | `http://localhost:5757` | Base URL of the network tool the FRR/device adapter calls. **Security:** server-side request; keep it on loopback or a trusted management network. |
| `DOCKER_EXEC_FALLBACK` | `true` | When the tool API is unreachable, the FRR adapter falls back to `docker exec` against lab containers. **Security:** this runs commands through the local Docker daemon (equivalent to host-level privilege). Set `false` on any shared or production host. |
| `NET_USER` | `admin` | Username embedded as an environment lookup in generated runbook scripts (read by the generated script, not by netlog-ai itself). |
| `NET_PASS` | unset | Device password read by generated runbook scripts. **Secret.** Never hardcode it into the generated file. |

## MCP server

| Variable | Default | Purpose / notes |
| --- | --- | --- |
| `NETLOG_MCP_TRANSPORT` | `stdio` | `stdio`, `streamable-http` or `sse`. **Security:** the HTTP transports expose the tools over the network and need `Authorization: Bearer <NETLOG_MCP_TOKEN>`; the server refuses a non-loopback bind without a token. |
| `NETLOG_MCP_HOST` | `127.0.0.1` | **(new in 2.2.0)** Bind address for the HTTP transports. |
| `NETLOG_MCP_PORT` | `8000` | **(new in 2.2.0)** Port for the HTTP transports. |
| `NETLOG_MCP_TOKEN` | unset | **(new in 2.2.0)** Bearer token required by the HTTP transports (compared in constant time). On loopback with no token the server starts with a warning. **Secret.** |
| `NETLOG_MCP_ALLOW_WRITE` | `false` | **(new in 2.2.0)** Enables the MCP tools that change external systems: `add_source`, live `enrich_itsm_incident`, `push_solarwinds_alert_note` and live `netlog_servicenow_sync_incident`. Dry-run and preview paths stay available. |
