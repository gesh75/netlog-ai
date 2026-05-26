# Auto-Detection Parser (tfsm_fire integration)

netlog-ai integrates [scottpeterman/tfsm_fire](https://github.com/scottpeterman/tfsm_fire)
as an **opt-in fallback parser** for arbitrary CLI output where the platform and command
aren't known up-front.

## Why

Our hand-written FRR / syslog parsers handle the lab cleanly, but break down for:

- Multi-vendor `show` output pasted into the analyzer without context
- MCP tool calls where the LLM hands us raw text without telling us the vendor
- Heterogeneous device inventory where you don't know which template applies

`tfsm_fire` solves this by scoring every TextFSM template in a SQLite DB (~700 templates
from ntc-templates) against the input, then returning the one with the highest score on a
0–100 scale. We use it **only as a fallback** — primary regex paths stay fast.

## Installation

```bash
pip install -e ".[parse]"   # adds tfsm-fire + textfsm
```

The template DB (~576 KB SQLite) is **not** bundled in the pip package. It's auto-downloaded
from the upstream GitHub repo to `~/.cache/netlog-ai/tfsm_templates.db` on first use.

Override the path with the `TFSM_DB_PATH` env var if you want to vendor it elsewhere
(e.g. for an air-gapped environment):

```bash
export TFSM_DB_PATH=/opt/netlog-ai/tfsm_templates.db
```

## Quick start

```python
from ai_log_analyzer.adapters.tfsm_auto import auto_parse

raw = """
Device ID           Local Intf     Hold-time  Capability      Port ID
switch1             Gi0/1          120        R               Gi1/0/1
switch2             Gi0/2          120        R               Gi1/0/2
"""

result = auto_parse(raw, filter_hint="lldp_neighbor", min_score=40.0)
if result.matched:
    print(f"template={result.template} score={result.score:.1f}")
    for record in result.records:
        print(record)
```

Output:

```text
template=juniper_junos_show_lldp_neighbors score=76.7
{'LOCAL_INTERFACE': 'Gi0/1', 'NEIGHBOR_NAME': 'switch1', ...}
{'LOCAL_INTERFACE': 'Gi0/2', 'NEIGHBOR_NAME': 'switch2', ...}
```

## API

### `auto_parse(output, filter_hint=None, min_score=0.0) -> ParseResult`

| Param         | Type                | Purpose                                                      |
|---------------|---------------------|--------------------------------------------------------------|
| `output`      | `str`               | Raw CLI output to parse                                      |
| `filter_hint` | `Optional[str]`     | Narrow templates by name substring (e.g. `"bgp"`, `"version"`) — much faster |
| `min_score`   | `float`             | Reject matches below this score (recommended: `40.0`)        |

Returns a frozen `ParseResult`:

```python
@dataclass(frozen=True)
class ParseResult:
    template: Optional[str]              # matched cli_command, e.g. "cisco_ios_show_version"
    score: float                         # 0-100 quality score
    records: list[dict]                  # parsed rows (empty if no match)
    candidates: list[tuple[str, float, int]]  # all non-zero (template, score, record_count)

    @property
    def matched(self) -> bool: ...
```

The function **never raises** — every failure mode (missing dep, empty input, no match,
DB download failure) returns an unmatched `ParseResult`.

### `parse_output(result, filter_hint=None, min_score=40.0) -> list[dict]`

Convenience helper in `adapters.network_tool` that takes a `CommandResult` and returns
parsed records directly:

```python
from ai_log_analyzer.adapters.network_tool import run_command, parse_output

cmd = run_command("de-fra-core-01", "vtysh -c 'show ip bgp summary'")
records = parse_output(cmd, filter_hint="bgp_summary")
```

### `is_available() -> bool`

Cheap probe — use it to gate UI affordances when the `parse` extra isn't installed.

## Scoring guide

| Score    | Interpretation                              |
|----------|---------------------------------------------|
| 80–100   | High confidence — safe to use programmatically |
| 50–79    | Likely correct — review records before automating |
| 40–49    | Borderline — consider as a hint, not a fact |
| 0–39     | Low confidence — usually a false positive    |

The scorer rewards: record count, field richness, population rate, and consistency across
records. See `tfire.tfsm_fire._calculate_template_score` upstream for the math.

## Filter hints by use case

| Hint           | What it matches                                 |
|----------------|-------------------------------------------------|
| `"version"`    | `show version` (all vendors)                    |
| `"bgp_summary"`| `show ip bgp summary` and variants              |
| `"lldp"`       | LLDP neighbor tables                            |
| `"interface"`  | `show interface(s)` outputs                     |
| `"route"`      | Routing table dumps                             |
| `"vlan"`       | VLAN tables                                     |

Always pass a hint when you can — full scans iterate 700+ templates and are noticeably
slower than filtered ones.

## Why we use it as a fallback only

1. **Regex is faster** for parsers we control end-to-end (FRR docker logs, RFC 3164 syslog).
2. **TextFSM templates can mismatch** — a Cisco LLDP output may score highest against a
   Juniper template (both use similar column layouts). For known-vendor flows we want
   deterministic parsers, not best-guess.
3. **The template DB is a network dependency** — relying on it for hot paths would create
   a cold-start latency spike on the first parse of every process.

The right mental model: tfsm_fire is the *parser of last resort* when nothing else applies.

## Lessons learned during integration

- The pip package installs as the Python module `tfire`, not `tfsm_fire`. The upstream
  README's `from tfsm_fire import TextFSMAutoEngine` example is wrong — use
  `from tfire.tfsm_fire import TextFSMAutoEngine`.
- The 576 KB SQLite template DB ships **only** in the GitHub repo, not the wheel.
- The engine is thread-safe (one SQLite connection per thread via `threading.local`), so
  a module-level singleton is safe.
- Per-template parse failures are swallowed inside `find_best_template` — exceptions
  bubble up only on SQLite / DB-level errors.

## References

- Upstream repo: https://github.com/scottpeterman/tfsm_fire
- Template source: https://github.com/networktocode/ntc-templates
- Our adapter: [`src/ai_log_analyzer/adapters/tfsm_auto.py`](../src/ai_log_analyzer/adapters/tfsm_auto.py)
- Tests: [`tests/test_tfsm_auto.py`](../tests/test_tfsm_auto.py)
