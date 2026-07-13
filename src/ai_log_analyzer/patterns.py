"""Streaming template miner for *unclassified* log events (Drain-lite).

Every event the regex KB can't match is silently classified `info`/`other`
and vanishes from the action list — yet "a message shape we've never seen
before" is one of the strongest early-warning signals in network operations
(new error paths show up as new templates before they show up as outages).

This module mines those unmatched lines into templates with zero external
dependencies, so the analyzer can surface a ranked "unknown patterns" panel
next to the KB-classified action items:

  1. **Mask** variable parts (IPs, MACs, hex, numbers, interface names) so
     `bgp peer 10.0.0.1 reset` and `bgp peer 10.0.0.9 reset` share a shape.
  2. **Cluster** masked token streams with a fixed-depth parse tree keyed by
     (token count, first token) and a similarity threshold — the same idea
     as the Drain algorithm, trimmed to what syslog needs.
  3. **Merge** diverging tokens into `<*>` wildcards as a cluster grows.

Memory is bounded by `max_clusters` (LRU eviction), so it is safe inside
analyze()'s single streaming pass at any input size.
"""
from __future__ import annotations

import re
from collections import OrderedDict
from dataclasses import dataclass, field

# Masking rules applied before tokenization, most specific first.
# Every mask becomes a fixed token so it can't split template shapes.
_MASKS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?(?::\d+)?\b"), "<ip>"),
    (re.compile(r"\b(?:[0-9a-f]{2}[:.-]){5}[0-9a-f]{2}\b", re.I), "<mac>"),
    (re.compile(r"\b(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}\b", re.I), "<mac>"),
    (re.compile(r"\b[0-9a-f]{2}(?::[0-9a-f]{2}){3,}\b", re.I), "<hex>"),
    (re.compile(r"\b0x[0-9a-f]+\b", re.I), "<hex>"),
    # interface names: ge-0/0/1.0, xe-1/2/3, et-0/0/0, Ethernet49/1, eth1, ae0.100
    (re.compile(r"\b(?:[gxem]t?e|et|ae|irb|lo|vlan|fxp|em|mge)-?\d+(?:[/.:]\d+)*\b", re.I), "<if>"),
    (re.compile(r"\b(?:hundredgige|fortygige|twentyfivegige|tengige|gigabitethernet|fastethernet|ethernet|port-channel|tunnel|loopback|management)\d+(?:[/.:]\d+)*\b", re.I), "<if>"),
    # ISO / syslog timestamps embedded mid-message
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[t ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:z|[+-]\d{2}:?\d{2})?\b", re.I), "<ts>"),
    (re.compile(r"\b\d{2}:\d{2}:\d{2}(?:\.\d+)?\b"), "<ts>"),
    # any remaining integers / decimals (counters, PIDs, ports, durations)
    (re.compile(r"(?<![\w.])\d+(?:\.\d+)?(?![\w.])"), "<n>"),
]

_WILDCARD = "<*>"


def mask_message(message: str) -> str:
    """Replace variable fields (IPs, MACs, hex, numbers, interfaces) with tokens."""
    out = message
    for pattern, token in _MASKS:
        out = pattern.sub(token, out)
    return out


def _similarity(a: list[str], b: list[str]) -> float:
    """Positional token similarity of two equal-length token lists (0..1)."""
    if not a:
        return 1.0
    same = sum(1 for x, y in zip(a, b) if x == y or x == _WILDCARD or y == _WILDCARD)
    return same / len(a)


@dataclass
class TemplateCluster:
    """One mined template with its live statistics."""
    cluster_id: int
    tokens: list[str]
    group_key: tuple[int, str] = (0, "")
    count: int = 0
    hosts: set[str] = field(default_factory=set)
    sample: str = ""              # first raw (masked) example, for the UI
    severity_hint: str = "info"   # promoted if the shape smells like an error

    @property
    def template(self) -> str:
        return " ".join(self.tokens)

    def to_dict(self) -> dict:
        return {
            "template": self.template,
            "count": self.count,
            "hosts": sorted(self.hosts)[:10],
            "host_count": len(self.hosts),
            "sample": self.sample,
            "severity_hint": self.severity_hint,
        }


# Words that mark an unknown template as probably-bad even though no KB rule
# matched it. Deliberately conservative: presence promotes the hint only.
_ERRORISH_RE = re.compile(
    r"\b(?:error|err|fail|failed|failure|crit|critical|fatal|panic|deny|denied|"
    r"drop|dropped|timeout|unreachable|refused|invalid|corrupt|exceed|exceeded|"
    r"mismatch|abort|aborted|lost|expired|violation)\b",
    re.IGNORECASE,
)


class TemplateMiner:
    """Fixed-depth streaming template miner (Drain-lite), bounded memory.

    Clusters are grouped by (token_count, first_token); within a group a new
    line joins the most similar cluster above `sim_threshold`, merging
    diverging positions into `<*>`, otherwise it starts a new cluster.
    """

    def __init__(self, sim_threshold: float = 0.55, max_clusters: int = 512,
                 max_tokens: int = 40) -> None:
        self.sim_threshold = sim_threshold
        self.max_clusters = max_clusters
        self.max_tokens = max_tokens
        self._clusters: OrderedDict[int, TemplateCluster] = OrderedDict()
        self._groups: dict[tuple[int, str], list[int]] = {}
        self._next_id = 1

    def add(self, message: str, hostname: str = "") -> TemplateCluster:
        """Feed one raw message; returns the cluster it joined or created."""
        masked = mask_message(message.strip())
        tokens = masked.split()
        if len(tokens) > self.max_tokens:
            tokens = tokens[: self.max_tokens]
        # Group key: length + first token — wildcard first tokens bucket together.
        first = tokens[0] if tokens else ""
        if first.startswith("<"):
            first = _WILDCARD
        key = (len(tokens), first)

        best: TemplateCluster | None = None
        best_sim = 0.0
        for cid in self._groups.get(key, ()):
            cluster = self._clusters.get(cid)
            if cluster is None:
                continue
            sim = _similarity(cluster.tokens, tokens)
            if sim > best_sim:
                best, best_sim = cluster, sim

        if best is not None and best_sim >= self.sim_threshold:
            # Merge diverging positions into wildcards.
            best.tokens = [
                t if t == u else _WILDCARD for t, u in zip(best.tokens, tokens)
            ]
            cluster = best
        else:
            cluster = TemplateCluster(
                cluster_id=self._next_id, tokens=tokens, group_key=key,
                sample=masked[:200],
            )
            self._next_id += 1
            self._clusters[cluster.cluster_id] = cluster
            self._groups.setdefault(key, []).append(cluster.cluster_id)
            self._evict_if_needed()

        cluster.count += 1
        if hostname:
            cluster.hosts.add(hostname)
        if cluster.severity_hint == "info" and _ERRORISH_RE.search(masked):
            cluster.severity_hint = "warning"
        # LRU touch
        self._clusters.move_to_end(cluster.cluster_id)
        return cluster

    def _evict_if_needed(self) -> None:
        while len(self._clusters) > self.max_clusters:
            old_id, old = self._clusters.popitem(last=False)
            ids = self._groups.get(old.group_key)
            if ids and old_id in ids:
                ids.remove(old_id)

    @property
    def cluster_count(self) -> int:
        return len(self._clusters)

    def top(self, n: int = 10, errorish_first: bool = True) -> list[TemplateCluster]:
        """Highest-signal clusters: error-smelling shapes first, then by volume."""
        clusters = list(self._clusters.values())
        if errorish_first:
            clusters.sort(key=lambda c: (c.severity_hint == "info", -c.count))
        else:
            clusters.sort(key=lambda c: -c.count)
        return clusters[:n]

    def to_dict(self, top_n: int = 10) -> dict:
        """JSON-ready summary for AnalysisResult / API / MCP."""
        top = self.top(top_n)
        return {
            "total_unclassified": sum(c.count for c in self._clusters.values()),
            "template_count": self.cluster_count,
            "top_templates": [c.to_dict() for c in top],
        }
