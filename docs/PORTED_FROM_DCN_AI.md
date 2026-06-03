# Port from DCN AI Intelligence Center — 2026-06-02

Four capabilities backfilled from the closed-source **DCN AI Intelligence Center**
(`04_Scripts_Tools/DCN_AI_Intelligence`) into netlog-ai. The goal was to bring the
same cross-source correlation and per-device triage patterns that operate against
real Kibana/LibreNMS feeds into the open-source, lab-portable tool.

Both correlation and triage are now reachable **two ways**: as the agent-facing MCP
tools documented below (`correlate_sources`, `analyze_device`) and as first-class
**Web GUI** surfaces in the Device tab of the SPA — see [Web GUI surface](#web-gui-surface).

---

## 1. Multi-source correlation (`correlate_sources`)

**What changed:** `src/ai_log_analyzer/correlate.py` (pre-existing) is now callable
from the MCP layer via `correlate_from_manager()`. The function classifies events from
every registered source, then tags each device as:

- **confirmed** — actionable events (severity ≥ `min_severity`) appear in **two or
  more** independent sources (e.g. Kibana *and* LibreNMS both report the same host).
- **suspected** — only one source has seen the device.

The double-source requirement eliminates single-source noise (a syslog burst that
didn't trigger a LibreNMS alert is unlikely to be a real incident).

## 2. Richer root-cause KB (`kb.py`)

**What changed:** every existing KB entry (`BGP_DOWN`, `OSPF_ADJ`, `INT_DOWN`,
`LAG_DOWN`, `ASIC_PARITY`, `LICENSE`, `AUTH_FAIL`, `KERNEL_PANIC`) gained a
structured `rca` sub-dict with:

- `root_cause` — plain-English diagnosis, numbered cause list
- `risk` — traffic-impact sentence
- `resolution_steps` — ordered checklist (5–8 items)
- `cli_junos` / `cli_eos` — copy-pastable command sets for both vendors
- `timeline` — P1/P2 priority with a time-to-act statement

Two entirely new KB categories were added from the DCN AI KB:

| Category key | Match pattern | Covers |
|---|---|---|
| `vpn` / `tunnel_down` | `ike\|ipsec\|vpn\|tunnel` | IKE Phase 1/2 failure, NAT-T, cert expiry, UDP 500/4500 |
| `redundancy` / `failover` | `vrrp\|hsrp\|failover\|master.*change` | VRRP/HSRP state change, split-brain, tracked-object events |

Both entries include the full 5-phase playbook (Diagnose → Mitigate → Remediate →
Verify → Optimize), `preventive_config` snippets, and `monitoring` alert guidance.

The `hardware` KB sub-tree also gained two entries (`fpc`, `chassis`) alongside the
existing `asic_parity` entry:

| Sub-key | Match | Covers |
|---|---|---|
| `fpc` | `fpc.*(?:offline\|crash\|error\|halt\|restart)\|line.?card` | FPC/line-card offline, memory exhaustion, JTAC evidence collection |
| `chassis` | `chassis.*alarm\|power.*fail\|fan.*fail\|psu\|temperature` | PSU failure, fan failure, thermal thresholds |

## 3. Expanded classifier patterns (`classifier.py`)

**What changed:** one pattern added to `_KB_PATTERNS` (low-severity, `system`
category):

```python
(r"inetd|xinetd|ftpd", "low", "system", "inetd service activity"),
```

The entry is positioned *after* all higher-severity patterns (BGP, OSPF, interface,
hardware) so the first-match-wins rule still lets a message that contains both an
`ftpd` token and a `bgp.*down` token be classified by the routing pattern. Three new
unit tests (`test_classifier.py`) verify the match, the parametrized `xinetd`/`ftpd`
variants, and the first-match-wins invariant.

## 4. Per-device triage (`analyze_device`)

**What changed:** `src/ai_log_analyzer/device_triage.py` (pre-existing) is now
callable from the MCP layer via `triage_from_manager()`. For a named hostname the
function returns:

- **severity histogram** across all registered sources
- **process breakdown** — top appnames generating events
- **frequency-deduped error patterns** — distinct message signatures sorted by count
- **verdict** — the dominant KB category (e.g. `HARDWARE`, `ROUTING`, `LAG`)
- **health score** — 0–100 integer; lower is worse

---

## New MCP tools

Two tools were added to `src/ai_log_analyzer/mcp_server/server.py`.

### `correlate_sources`

Cross-source device correlation. Classifies each source's events independently,
then marks devices `confirmed` or `suspected` based on how many sources saw them.

**Signature:**

```
correlate_sources(
    source_ids: list[str] | None = None,   # default: all registered sources
    since_seconds: int = 3600,
    limit: int = 5000,
    min_severity: str = "medium",
) -> dict
```

**Usage example** (Claude Code / MCP client):

> "Use netlog-ai to correlate all sources for the last 2 hours and show me
> every confirmed device."

```python
# Equivalent tool call
correlate_sources(since_seconds=7200, min_severity="medium")
# Returns:
# {
#   "ok": true,
#   "confirmed": [{"hostname": "fra4-rt-01", "sources": ["kibana", "librenms"], ...}],
#   "suspected": [{"hostname": "lhr3-sw-02", "sources": ["kibana"], ...}],
# }
```

Filter to a specific pair of sources:

```python
correlate_sources(source_ids=["kibana", "librenms"], since_seconds=3600)
```

### `analyze_device`

Per-device deep triage. Pulls one hostname's events from all (or specified) sources,
builds a severity histogram, process breakdown, error pattern list, and returns a
verdict + health score.

**Signature:**

```
analyze_device(
    hostname: str,
    source_ids: list[str] | None = None,   # default: all registered sources
    since_seconds: int = 86400,
    limit: int = 5000,
) -> dict
```

**Usage example:**

> "Run a deep triage on fra4-rt-01 across all sources for the last 24 hours."

```python
analyze_device(hostname="fra4-rt-01", since_seconds=86400)
# Returns:
# {
#   "hostname": "fra4-rt-01",
#   "verdict": "ROUTING",
#   "health_score": 42,
#   "severity_histogram": {"high": 3, "medium": 11, "low": 74},
#   "top_processes": [{"appname": "rpd", "count": 14}, ...],
#   "error_patterns": [{"pattern": "bgp peer .* down", "count": 3}, ...],
# }
```

Scope to a single source:

```python
analyze_device(hostname="fra4-rt-01", source_ids=["kibana"])
```

---

## Files changed

| File | Change |
|---|---|
| `src/ai_log_analyzer/classifier.py` | +1 pattern (`inetd\|xinetd\|ftpd`) |
| `src/ai_log_analyzer/kb.py` | Richer `rca` blocks on all existing entries; new `_VPN_DOWN`, `_REDUNDANCY`, `_FPC_ERR`, `_CHASSIS_ENV` entries; `hardware` sub-tree extended; `vpn` and `redundancy` keys added to `KB` dict |
| `src/ai_log_analyzer/mcp_server/server.py` | +2 tools: `correlate_sources`, `analyze_device` |
| `src/ai_log_analyzer/web/app.py` | +2 routes: `POST /api/correlate`, `POST /api/triage` (thin wrappers over `correlate_from_manager` / `triage_from_manager`) |
| `src/ai_log_analyzer/web/static/index.html` | Device-tab controls + result panels for the Correlate / Triage GUI |
| `src/ai_log_analyzer/web/static/app.js` | Handlers + renderers for the correlation table and triage panel |
| `tests/test_classifier.py` | +3 unit tests for the new inetd pattern |
| `tests/test_web_correlate_triage.py` | Route-wrapper tests for `/api/correlate` and `/api/triage` |

---

## Web GUI surface

The correlation and triage capabilities are no longer MCP-only — both now have a
front-end home in the **Device tab** of the SPA, alongside *Optimize Device*:

- **🔗 Correlate Sources** (`POST /api/correlate`, wrapping `correlate_from_manager`) —
  a sidebar control (min-severity + time window) renders a sortable, severity-coded
  table of devices, each tagged **CONFIRMED** (≥ 2 sources) or **SUSPECTED** (1), with
  per-source coverage pips and a per-row *Triage* button.
- **🔬 Triage Device** (`POST /api/triage`, wrapping `triage_from_manager`) — a hostname
  input opens a result panel with a status-colored verdict banner, a 0–100 health-score
  ring, a severity histogram, a top-process table, and the deduped error patterns.

These are the GUI front-ends of the same `correlate_sources` / `analyze_device` tools
above; the routes are pure thin wrappers and add no business logic.
