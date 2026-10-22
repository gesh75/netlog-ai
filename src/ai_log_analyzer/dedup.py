"""Drain-style template miner for network syslog bursts.

Masks variable tokens (IPv4/IPv6, MAC, interfaces, ASN, hex, PID, numbers),
clusters identical templates, and emits a compact representation suitable
for classification and LLM prompts.

Opt-in: `analyze(..., dedup=True)` or `AI_LOG_ANALYZER_DEDUP=1`. Default off
so existing streaming/classification behaviour is unchanged.
"""
from __future__ import annotations

import hashlib
import os
import re
from collections import Counter, OrderedDict
from collections.abc import Iterable, Iterator
from contextvars import ContextVar, Token
from dataclasses import dataclass, field

# Optional `<PRI>` / RFC5424 version prefix so standard syslog still clusters.
# Belt-and-suspenders: _SYSLOG_HEADER_RE also accepts the same prefix so a
# caller that skips this strip (Cisco sequence + PRI, raw RFC5424) still parses.
_PRI_PREFIX_RE = re.compile(r"^<\d+>(?:\d+\s+)?")

# Optional PRI+version, Cisco sequence (`004122: `), leading asterisk (`*Oct`),
# then BSD or ISO8601 timestamp, host, body.
_SYSLOG_HEADER_RE = re.compile(
    r"^(?:<\d+>(?:\d+\s+)?)?(?:\d+:\s+)?\*?"
    r"(?P<ts>"
    r"(?:[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"|"
    r"\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r")\s+"
    r"(?P<host>[A-Za-z0-9_.-]+)\s+"
    r"(?P<body>.*)$"
)

# Colon-MAC is a 6-group IPv6 lookalike; skip those so the MAC pass records them.
_MAC_COLON_RE = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")

_IPV6_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}(?:/\d{1,3})?\b"
)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
_MAC_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b"
    r"|"
    r"\b(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}\b",
    re.IGNORECASE,
)
_INTF_RE = re.compile(
    r"\b(?:"
    r"TenGigabitEthernet|GigabitEthernet|FastEthernet|FortyGigE|HundredGigE|"
    r"Port-Channel|Management|Loopback|Ethernet|Vxlan|Vlan|"
    r"eth|swp|po|ae|vlan|"
    r"xe-|et-|ge-|"
    r"irb\.|lo0\."
    r")\d+(?:[/.:]\d+)*\b",
    re.IGNORECASE,
)
_ASN_RE = re.compile(r"AS\s*\d+", re.IGNORECASE)
_HEX_RE = re.compile(r"0x[0-9a-fA-F]+")
_PID_RE = re.compile(r"\[\d+\]")
_NUM_RE = re.compile(r"\b\d+\b")

# Ordered: IPV6, IPV4, MAC, INTF, ASN, HEX, PID, NUM.
_TOKEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("IPV6", _IPV6_RE),
    ("IPV4", _IPV4_RE),
    ("MAC", _MAC_RE),
    ("INTF", _INTF_RE),
    ("ASN", _ASN_RE),
    ("HEX", _HEX_RE),
    ("PID", _PID_RE),
    ("NUM", _NUM_RE),
)

_NEWLINE_RE = re.compile(r"\r\n|\r|\n")


def _iter_text_lines(text: str) -> Iterator[str]:
    pos, n = 0, len(text)
    while pos < n:
        m = _NEWLINE_RE.search(text, pos)
        if m is None:
            yield text[pos:]
            return
        yield text[pos:m.start()]
        pos = m.end()


_VAR_DISPLAY_ORDER: tuple[str, ...] = ("INTF", "IPV4", "IPV6", "ASN", "MAC")
_COUNTED_KINDS: frozenset[str] = frozenset(_VAR_DISPLAY_ORDER)

# Bounds so one hostile or just huge input cannot grow the miner without limit.
_MAX_HOSTS_PER_CLUSTER = 1000
_MAX_VALUES_PER_KIND = 500
_DEFAULT_MAX_CLUSTERS = 20_000

_DEDUP_CTX: ContextVar[bool | None] = ContextVar("ai_log_analyzer_dedup", default=None)

_TRUTHY = frozenset({"1", "true", "yes", "on"})


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in _TRUTHY


def is_dedup_enabled() -> bool:
    """True when analyze() opted in or AI_LOG_ANALYZER_DEDUP is set."""
    override = _DEDUP_CTX.get()
    if override is not None:
        return override
    return _env_flag("AI_LOG_ANALYZER_DEDUP")


def set_dedup_enabled(enabled: bool | None) -> Token[bool | None]:
    """Bind the per-analyze() dedup flag. Returns a reset token."""
    return _DEDUP_CTX.set(enabled)


def reset_dedup_enabled(token: Token[bool | None]) -> None:
    _DEDUP_CTX.reset(token)


@dataclass
class LogCluster:
    cluster_id: str
    template: str
    count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    hosts: set[str] = field(default_factory=set)
    sample_raw: str = ""
    variable_counts: dict[str, Counter[str]] = field(default_factory=dict)
    hosts_truncated: bool = False   # more hosts than _MAX_HOSTS_PER_CLUSTER were seen

    def to_compact_line(self, max_vars: int = 4) -> str:
        """One LLM-ready line. Singletons pass through unchanged."""
        if self.count == 1:
            return self.sample_raw
        if self.first_seen and self.last_seen and self.first_seen != self.last_seen:
            window = f"window={self.first_seen}..{self.last_seen}"
        else:
            window = f"at={self.first_seen or 'unknown'}"
        hosts = self._format_hosts()
        prefix = f"[DEDUP x{self.count} | {window} hosts={hosts}] {self.template}"
        extras = self._format_vars(max_vars)
        return f"{prefix} | {extras}" if extras else prefix

    def _format_hosts(self) -> str:
        ordered = sorted(self.hosts)
        if not ordered:
            return "-"
        shown = ordered[:3]
        extra = len(ordered) - 3
        text = ",".join(shown)
        if extra > 0 or self.hosts_truncated:
            text += f"(+{max(extra, 0)}{'+' if self.hosts_truncated else ''}_more)"
        return text

    def _format_vars(self, max_vars: int) -> str:
        parts: list[str] = []
        for kind in _VAR_DISPLAY_ORDER:
            counter = self.variable_counts.get(kind)
            if not counter:
                continue
            items = ", ".join(
                f"{val}({cnt})" for val, cnt in counter.most_common(max_vars)
            )
            parts.append(f"{kind}=[{items}]")
        return " ".join(parts)


@dataclass
class DedupResult:
    clusters: list[LogCluster]
    total_lines: int
    unique_templates: int
    raw_chars: int
    compressed_chars: int

    @property
    def line_reduction_ratio(self) -> float:
        if self.total_lines <= 0:
            return 0.0
        return max(0.0, 1.0 - (self.unique_templates / self.total_lines))

    @property
    def char_reduction_ratio(self) -> float:
        if self.raw_chars <= 0:
            return 0.0
        return max(0.0, 1.0 - (self.compressed_chars / self.raw_chars))

    def format_for_llm(self) -> str:
        """Join compact cluster lines for an LLM prompt."""
        return "\n".join(c.to_compact_line() for c in self.clusters)


class NetworkLogDeduplicator:
    """Cluster syslog lines that share a masked template."""

    def __init__(self, preserve_singletons: bool = True, max_clusters: int | None = None) -> None:
        self.preserve_singletons = preserve_singletons
        if max_clusters is None:
            try:
                max_clusters = int(os.environ.get("AI_LOG_ANALYZER_DEDUP_MAX_CLUSTERS", "") or _DEFAULT_MAX_CLUSTERS)
            except ValueError:
                max_clusters = _DEFAULT_MAX_CLUSTERS
        self.max_clusters = max(1, max_clusters)

    def _parse_header(self, line: str) -> tuple[str, str, str]:
        stripped = _PRI_PREFIX_RE.sub("", line, count=1)
        match = _SYSLOG_HEADER_RE.match(stripped) or _SYSLOG_HEADER_RE.match(line)
        if not match:
            return "", "", line
        ts = match.group("ts") or ""
        host = match.group("host") or ""
        body = match.group("body") or ""
        return ts, host, body

    def _extract_template_and_vars(self, body: str) -> tuple[str, dict[str, list[str]]]:
        collected: dict[str, list[str]] = {kind: [] for kind, _ in _TOKEN_PATTERNS}
        out = body
        for kind, pattern in _TOKEN_PATTERNS:
            out = self._apply_pattern(out, kind, pattern, collected)
        return out, collected

    @staticmethod
    def _apply_pattern(
        text: str,
        kind: str,
        pattern: re.Pattern[str],
        collected: dict[str, list[str]],
    ) -> str:
        def _replace(match: re.Match[str]) -> str:
            value = match.group(0)
            if kind == "IPV6" and _MAC_COLON_RE.fullmatch(value):
                return value
            if kind == "PID":
                return "[<PID>]"
            collected[kind].append(value)
            return f"<{kind}>"

        return pattern.sub(_replace, text)

    def deduplicate(self, logs: str | Iterable[str]) -> DedupResult:
        lines: Iterable[str]
        if isinstance(logs, str):
            lines = _iter_text_lines(logs)   # lazy: no second copy of a large text as a list of lines
        else:
            lines = logs

        clusters: OrderedDict[str, LogCluster] = OrderedDict()
        total_lines = 0
        raw_chars = 0

        for raw in lines:
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", errors="replace")
            line = raw.rstrip("\r\n")
            if not line.strip():
                continue
            total_lines += 1
            raw_chars += len(line)

            ts, host, body = self._parse_header(line)
            template, variables = self._extract_template_and_vars(body)
            cluster_id = hashlib.sha1(template.encode("utf-8")).hexdigest()[:10]

            cluster = clusters.get(cluster_id)
            if cluster is None and len(clusters) >= self.max_clusters:
                # Too many distinct templates: fold the rest into one overflow cluster.
                cluster_id = "overflow"
                cluster = clusters.get(cluster_id)
                if cluster is None:
                    cluster = clusters[cluster_id] = LogCluster(
                        cluster_id=cluster_id, template="<more distinct templates than the cluster limit>",
                        first_seen=ts, last_seen=ts, sample_raw=line,
                        variable_counts={kind: Counter() for kind in _COUNTED_KINDS})
            if cluster is None:
                cluster = LogCluster(
                    cluster_id=cluster_id,
                    template=template,
                    count=0,
                    first_seen=ts,
                    last_seen=ts,
                    hosts=set(),
                    sample_raw=line,
                    variable_counts={kind: Counter() for kind in _COUNTED_KINDS},
                )
                clusters[cluster_id] = cluster
            cluster.count += 1
            if ts:
                if not cluster.first_seen:
                    cluster.first_seen = ts
                cluster.last_seen = ts
            if host:
                if host in cluster.hosts or len(cluster.hosts) < _MAX_HOSTS_PER_CLUSTER:
                    cluster.hosts.add(host)
                else:
                    cluster.hosts_truncated = True
            for kind, values in variables.items():
                bucket = cluster.variable_counts.get(kind)
                if bucket is not None:
                    for value in values:
                        if value in bucket or len(bucket) < _MAX_VALUES_PER_KIND:
                            bucket[value] += 1

        kept = [
            c for c in clusters.values()
            if self.preserve_singletons or c.count > 1
        ]
        result = DedupResult(
            clusters=kept,
            total_lines=total_lines,
            unique_templates=len(clusters),
            raw_chars=raw_chars,
            compressed_chars=0,
        )
        result.compressed_chars = len(result.format_for_llm())
        return result


def deduplicate_logs(
    logs: str | Iterable[str],
    *,
    preserve_singletons: bool = True,
) -> DedupResult:
    """Convenience wrapper around NetworkLogDeduplicator().deduplicate()."""
    return NetworkLogDeduplicator(preserve_singletons=preserve_singletons).deduplicate(logs)
