# Auto-Detection Parser (tfsm_fire integration)

> ## ⚠️ Upstream status: withdrawn (July 2026)
>
> `tfsm-fire` has been **removed from PyPI** and `github.com/scottpeterman/tfsm_fire` has
> been **deleted**. Both return 404. There is no surviving fork, mirror, renamed
> distribution, or Wayback snapshot, and the template-DB raw URL is dead too.
>
> It was installable as recently as **2026-07-13** (netlog-ai CI installed
> `tfsm_fire-0.1.0-py3-none-any.whl` that day), so pre-existing environments may still
> have it cached. But it can no longer be obtained from anywhere.
>
> **What changed in netlog-ai v0.5.1:** the `parse` extra was removed and `all` reduced
> to `mcp` only. Keeping the dependency made `pip install netlog-ai[parse]` and
> `pip install netlog-ai[all]` hard-fail for every user, and broke CI on all Python
> versions. A `git+https://` direct reference was not an option: the repo is gone, and
> PyPI rejects direct references in uploaded metadata regardless.
>
> **What did not change:** `adapters/tfsm_auto.py` and its API are untouched. The adapter
> is a strict fallback that nothing else depends on, and it degrades to no-match when the
> package or DB is absent. If you have a copy of both, everything below still works —
> see [Installation](#installation).

netlog-ai integrates `tfsm_fire` as an **opt-in fallback parser** for arbitrary CLI output
where the platform and command aren't known up-front.

## Why

Our hand-written FRR / syslog parsers handle the lab cleanly, but break down for:

- Multi-vendor `show` output pasted into the analyzer without context
- MCP tool calls where the LLM hands us raw text without telling us the vendor
- Heterogeneous device inventory where you don't know which template applies

`tfsm_fire` solves this by scoring every TextFSM template in a SQLite DB (~700 templates
from ntc-templates) against the input, then returning the one with the highest score on a
0–100 scale. We use it **only as a fallback** — primary regex paths stay fast.

## Installation

There is no longer an extra for this — `pip install netlog-ai[parse]` was removed in
v0.5.1 because the dependency is unobtainable (see the banner above). Both pieces must
now be supplied manually.

**1. The package.** You need a copy of `tfsm-fire` 0.1.0 (imports as `tfire`, depends on
`textfsm>=1.1.3`). If you have one in an existing environment, an old wheel, or a private
index:

```bash
pip install textfsm
pip install /path/to/tfsm_fire-0.1.0-py3-none-any.whl   # or: pip install -e /path/to/checkout
```

**2. The template DB** (~576 KB SQLite). This was never bundled in the pip package — it
lived only in the upstream GitHub repo, which is gone. The auto-download will fail, so
point the adapter at your own copy:

```bash
export TFSM_DB_PATH=/opt/netlog-ai/tfsm_templates.db     # local copy, or
export TFSM_DB_URL=https://your-mirror.example/tfsm_templates.db
```

The templates came from [networktocode/ntc-templates](https://github.com/networktocode/ntc-templates),
which is still actively maintained — a compatible DB can be rebuilt from that source if
you no longer have the original.

If either piece is missing, `is_available()` returns `False`, `auto_parse()` returns an
unmatched `ParseResult`, and `tests/test_tfsm_auto.py` skips at module level. Nothing
raises and no other feature is affected.

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

Cheap probe — use it to gate UI affordances when `tfsm-fire` isn't installed.

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

- Upstream repo: `https://github.com/scottpeterman/tfsm_fire` — **deleted, 404 as of 2026-07-28**
- Template source: https://github.com/networktocode/ntc-templates (still maintained)
- Our adapter: [`src/ai_log_analyzer/adapters/tfsm_auto.py`](../src/ai_log_analyzer/adapters/tfsm_auto.py)
- Tests: [`tests/test_tfsm_auto.py`](../tests/test_tfsm_auto.py)
