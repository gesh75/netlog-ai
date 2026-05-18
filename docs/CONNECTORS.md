# Connectors and MCP server

netlog-ai ships with a pluggable connector layer (`src/ai_log_analyzer/sources/`)
that lets it pull events from any common log source, plus an **MCP server**
that exposes the analyzer as agent-callable tools.

The same engine that processes `--file` and pasted text now also drives:

| Connector  | Type           | Auth methods                          | Notes |
|------------|----------------|---------------------------------------|-------|
| `kibana`   | Elasticsearch  | `api_token` · `basic` · `cookie`      | Same engine as the closed-source ~2.4M-events/day version |
| `splunk`   | Splunk REST    | `api_token` · `basic`                 | Uses `oneshot` search — no job polling |
| `loki`     | Grafana Loki   | `api_token` · `basic` · `cookie`      | LogQL via `query_range` |
| `syslog`   | UDP/TCP listener | n/a                                 | Zero-config, perfect for laptop demos |
| `librenms` | LibreNMS REST  | `api_token`                           | Eventlog via `/api/v0/logs/eventlog` |
| `netbox`   | (planned)      | `api_token`                           | Device enrichment only — see roadmap |

Every connector implements the same Python `Protocol` (`LogSource`) so the
classifier, dedup, ranking, and LLM layers don't change — adding a new source
is one new file in `sources/`.

---

## Quick start — local syslog listener (no cloud required)

Point any device's syslog destination at your laptop's IP on UDP **5514** and
analyze in real time.

```bash
# 1. Start netlog-ai
netlog-ai serve

# 2. Register the syslog listener
curl -X POST http://127.0.0.1:6060/api/sources \
  -H 'Content-Type: application/json' \
  -d '{
        "id":   "local-syslog",
        "type": "syslog",
        "url":  "udp://127.0.0.1",
        "extra": {"port":"5514","proto":"udp","bind":"0.0.0.0"}
      }'

# 3. Send a test event
logger --server 127.0.0.1 --port 5514 --udp \
  "bgp peer 10.0.0.1 down (hold timer expired)"

# 4. Pull + analyze
curl -X POST http://127.0.0.1:6060/api/sources/local-syslog/analyze \
  -d '{"since_seconds":3600,"limit":1000,"use_llm":false}' \
  -H 'Content-Type: application/json'
```

---

## Configuring sources via environment variables

For production deployments, set `NETLOG_SOURCE_<id>_<FIELD>` env vars and they
are auto-registered on startup:

```bash
# Kibana / Elasticsearch
export NETLOG_SOURCE_kibana_TYPE=kibana
export NETLOG_SOURCE_kibana_URL=https://es.example.com:9200
export NETLOG_SOURCE_kibana_API_TOKEN=eyJhbGciOi...
export NETLOG_SOURCE_kibana_INDEX_PATTERN=network_devices-*

# Splunk
export NETLOG_SOURCE_splunk_TYPE=splunk
export NETLOG_SOURCE_splunk_URL=https://splunk.example.com:8089
export NETLOG_SOURCE_splunk_API_TOKEN=...
export NETLOG_SOURCE_splunk_SEARCH='search index=network sourcetype=junos'

# Loki
export NETLOG_SOURCE_loki_TYPE=loki
export NETLOG_SOURCE_loki_URL=https://loki.example.com:3100
export NETLOG_SOURCE_loki_API_TOKEN=...
export NETLOG_SOURCE_loki_QUERY='{job=~"network"}'

# LibreNMS
export NETLOG_SOURCE_librenms_TYPE=librenms
export NETLOG_SOURCE_librenms_URL=https://librenms.example.com
export NETLOG_SOURCE_librenms_API_TOKEN=...
```

---

## HTTP API

| Method | Path                                  | Description |
|--------|---------------------------------------|-------------|
| GET    | `/api/sources`                        | List registered sources + known connector kinds |
| POST   | `/api/sources`                        | Register a new source (auth-required) |
| DELETE | `/api/sources/<id>`                   | Remove a source (auth-required) |
| POST   | `/api/sources/<id>/test`              | Healthcheck a source |
| POST   | `/api/sources/<id>/fetch`             | Pull raw events `{since_seconds, limit, host_filter}` |
| POST   | `/api/sources/<id>/analyze`           | Pull + run full analyzer pipeline (auth-required) |

---

## MCP server

netlog-ai exposes its core capabilities as a **Model Context Protocol** server,
so Claude Code, Cursor, Continue, and any other MCP-compatible client can
query it directly.

### Install + run

```bash
pip install 'netlog-ai[mcp]'
netlog-ai mcp                       # stdio transport (default)
netlog-ai mcp --transport streamable-http
```

### Tools exposed

| Tool                    | Purpose |
|-------------------------|---------|
| `list_connector_kinds`  | Enumerate built-in connector types |
| `list_sources`          | Show registered live sources |
| `add_source`            | Register a new connector at runtime |
| `test_source`           | Healthcheck a registered source |
| `fetch_logs`            | Pull raw events from a source |
| `search_logs`           | Pull events matching a regex pattern |
| `analyze_logs`          | Full analyzer pipeline (classify + dedup + rank + optional LLM) |
| `get_top_offenders`     | Return the N noisiest hostnames |
| `list_sites`            | Enumerate bundled site directories |
| `analyze_site`          | Run site-wide cross-device analysis |

### Hook into Claude Code

Add to `~/.claude/mcp_servers.json` (or use `claude mcp add`):

```json
{
  "mcpServers": {
    "netlog-ai": {
      "command": "netlog-ai",
      "args": ["mcp"],
      "env": {
        "NETLOG_SOURCE_kibana_TYPE": "kibana",
        "NETLOG_SOURCE_kibana_URL": "https://es.example.com:9200",
        "NETLOG_SOURCE_kibana_API_TOKEN": "..."
      }
    }
  }
}
```

Then in Claude Code: *"Use netlog-ai to fetch the noisiest 5 devices from
kibana in the last hour and explain what's wrong with each."*

---

## Writing a new connector

Implement the `LogSource` Protocol and self-register:

```python
# src/ai_log_analyzer/sources/my_source.py
from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.sources.base import LogSource, SourceConfig, registry


class MyCustomSource:
    kind = "mycustom"

    def __init__(self, config: SourceConfig) -> None:
        self.config = config
        self.name = config.id

    @classmethod
    def from_config(cls, cfg: SourceConfig) -> "MyCustomSource":
        return cls(cfg)

    def healthcheck(self) -> bool:
        return True

    def fetch(self, *, since_seconds: int = 3600,
              limit: int = 10000, host_filter: str = ""):
        # Talk to your custom API / DB / queue / etc.
        for raw in some_iter(since_seconds, limit):
            yield LogEvent(
                timestamp=raw["ts"],
                hostname=raw.get("host", ""),
                appname=raw.get("app", "mycustom"),
                severity_raw=raw.get("sev", "info"),
                message=raw["msg"],
            )

    def close(self) -> None:
        pass


registry.register("mycustom", MyCustomSource.from_config)
```

Then add it to `sources/__init__.py` so it's loaded on import. Done.

---

## Design philosophy

- **Smart, not heavy.** Connectors are plain Python — no Kafka, no Redis, no
  external runtime. The whole layer is < 1500 lines.
- **Sanitize before LLM.** All connectors emit raw events; the sanitizer step
  in the analyzer (passwords, SSH keys, public IPs) still runs before any
  outbound call.
- **Graceful auth fallback.** Declarative `auth_methods` tuple, proven against
  Datadog / ServiceNow / Splunk / Kibana patterns.
- **Single contract.** Every source emits `LogEvent`; the rest of the
  pipeline (classifier, dedup, ranking, LLM, reports) doesn't know which
  source produced the event.
