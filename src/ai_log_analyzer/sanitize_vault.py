"""Reversible entity vault — pseudonymize log/config entities before any LLM call.

``sanitize.py`` removes secrets (irreversibly). This module replaces the
*identifiers* the model needs to reason about — IPv4/IPv6 addresses, MACs,
ASNs and (optionally) hostnames — with deterministic, indexed tokens:

    10.0.0.1 → <IP_1>      10.0.0.2 → <IP_2>      AS65001 → AS<ASN_1>
    aa:bb:cc:dd:ee:ff → <MAC_1>                    leaf1 → <HOST_1>

The same entity always maps to the same token inside one vault, and two
different entities never share a token, so the model can still tell peer A
from peer B in a BGP/EVPN topology. ``detokenize()`` maps the model's answer
back to real values for the operator.

Numbering is per vault instance: the LLM gateway opens one vault per request
(or per incident via ``llm.entity_hints``), so numbering is deterministic for
a given prompt. The vault is bounded (LRU + optional TTL) so a long-lived
instance cannot grow without limit or keep raw addresses forever.
"""
from __future__ import annotations

import ipaddress
import os
import re
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable

# Colon-MAC is a 6-group IPv6 lookalike; leave it for the MAC pass.
_MAC_COLON_RE = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")

_IPV6_RE = re.compile(
    r"(?<![:\w<])(?P<addr>"
    r"(?:[0-9a-fA-F]{1,4}:){6}[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|:(?::[0-9a-fA-F]{1,4}){1,7}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}"
    r")(?P<plen>/\d{1,3})?(?![:\w])"
)
# Raw IPv4, or a ``PUB-xxxxxxxx`` token left by sanitize.py's public-IP pass
# (resolved back to the raw address when sanitize still remembers it).
_IPV4_RE = re.compile(
    r"\b(?P<addr>(?:\d{1,3}\.){3}\d{1,3}|PUB-[0-9a-f]{8})(?P<plen>/\d{1,2})?\b"
)
_MAC_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b"
    r"|"
    r"\b(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}\b",
)
# Only the digits are tokenized so `remote-as <ASN_1>` stays valid CLI after
# detokenize. "AS" is case-sensitive — "same as 3 peers" is not an ASN.
_ASN_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bAS ?(?P<asn>\d{1,10})\b"),
    re.compile(r"(?i)\b(?:remote|peer|local|neighbor)[- ]as\s+(?P<asn>\d{1,10})\b"),
    re.compile(r"(?i)\b(?:router\s+bgp|autonomous-system)\s+(?P<asn>\d{1,10})\b"),
)
_TOKEN_RE = re.compile(r"<(?P<kind>IP6|IP|MAC|ASN|HOST)_(?P<idx>\d+)>")

_DEFAULT_MAX_ENTRIES = 4096


def _int_env(name: str, default: int) -> int:
    try:
        return max(0, int(os.environ.get(name, "") or default))
    except ValueError:
        return default


class SanitizeVault:
    """Bounded, reversible entity → token map.

    ``max_entries`` caps the forward map (least-recently-used entries are
    evicted first); ``ttl_seconds`` expires entries not seen recently. Index
    counters never rewind, so an evicted entity that reappears gets a fresh
    token rather than colliding with a token the model may still be quoting.
    """

    def __init__(
        self,
        max_entries: int = _DEFAULT_MAX_ENTRIES,
        ttl_seconds: float | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.max_entries = max(1, int(max_entries))
        self.ttl_seconds = ttl_seconds
        self._clock = clock
        self._lock = threading.Lock()
        # (kind, normalized key) → (token, display value, last-seen)
        self._forward: OrderedDict[tuple[str, str], tuple[str, str, float]] = OrderedDict()
        self._reverse: dict[str, str] = {}
        self._counters: dict[str, int] = {}

    # ── public API ──────────────────────────────────────────────────────────
    def tokenize(self, text: str, hosts: Iterable[str] = ()) -> str:
        """Replace hosts (if given), IPv6, IPv4, MAC and ASN tokens."""
        if not text:
            return text
        with self._lock:
            self._expire()
            out = self._tokenize_hosts(text, hosts)
            out = _IPV6_RE.sub(self._ipv6, out)
            out = _IPV4_RE.sub(self._ipv4, out)
            out = _MAC_RE.sub(self._mac, out)
            for pattern in _ASN_RES:
                out = pattern.sub(self._asn, out)
            return out

    # Back-compat name used by llm.prepare_log_samples callers and tests.
    anonymize = tokenize

    def detokenize(self, text: str) -> str:
        """Map tokens this vault issued back to their real values.

        Unknown tokens (never issued, or already evicted) are left untouched
        so a hallucinated ``<IP_99>`` stays visibly fake.
        """
        if not text:
            return text
        with self._lock:
            return _TOKEN_RE.sub(lambda m: self._reverse.get(m.group(0), m.group(0)), text)

    @property
    def mapping(self) -> dict[str, str]:
        """Display value → token (snapshot)."""
        with self._lock:
            return {display: token for token, display, _ in self._forward.values()}

    def __len__(self) -> int:
        return len(self._forward)

    def clear(self) -> None:
        with self._lock:
            self._forward.clear()
            self._reverse.clear()

    # ── internals ───────────────────────────────────────────────────────────
    def _token_for(self, kind: str, key: str, display: str) -> str:
        now = self._clock()
        entry = self._forward.get((kind, key))
        if entry is not None:
            token = entry[0]
            self._forward[(kind, key)] = (token, entry[1], now)
            self._forward.move_to_end((kind, key))
            return token
        self._counters[kind] = self._counters.get(kind, 0) + 1
        token = f"<{kind}_{self._counters[kind]}>"
        self._forward[(kind, key)] = (token, display, now)
        self._reverse[token] = display
        while len(self._forward) > self.max_entries:
            self._evict_oldest()
        return token

    def _evict_oldest(self) -> None:
        _, (token, _, _) = self._forward.popitem(last=False)
        self._reverse.pop(token, None)

    def _expire(self) -> None:
        if not self.ttl_seconds:
            return
        cutoff = self._clock() - self.ttl_seconds
        while self._forward:
            _, (_, _, seen) = next(iter(self._forward.items()))
            if seen >= cutoff:
                break
            self._evict_oldest()

    def _tokenize_hosts(self, text: str, hosts: Iterable[str]) -> str:
        names = sorted({h.strip() for h in hosts if h and len(h.strip()) >= 2},
                       key=len, reverse=True)
        if not names:
            return text
        pattern = re.compile(
            r"(?<![\w-])(?:" + "|".join(re.escape(n) for n in names) + r")(?![\w-])",
            re.IGNORECASE,
        )
        canonical = {n.lower(): n for n in names}

        def _replace(m: re.Match[str]) -> str:
            raw = m.group(0)
            return self._token_for("HOST", raw.lower(), canonical.get(raw.lower(), raw))

        return pattern.sub(_replace, text)

    def _ipv6(self, m: re.Match[str]) -> str:
        addr = m.group("addr")
        if _MAC_COLON_RE.fullmatch(addr):
            return m.group(0)
        try:
            key = ipaddress.IPv6Address(addr).compressed
        except ValueError:
            return m.group(0)
        return self._token_for("IP6", key, addr) + (m.group("plen") or "")

    def _ipv4(self, m: re.Match[str]) -> str:
        addr = m.group("addr")
        if addr.startswith("PUB-"):
            from ai_log_analyzer.sanitize import resolve_public_token
            addr = resolve_public_token(addr) or addr
            key = addr
        else:
            try:
                key = str(ipaddress.IPv4Address(addr))
            except ValueError:
                return m.group(0)
        return self._token_for("IP", key, addr) + (m.group("plen") or "")

    def _mac(self, m: re.Match[str]) -> str:
        raw = m.group(0)
        key = re.sub(r"[^0-9a-f]", "", raw.lower())
        return self._token_for("MAC", key, raw)

    def _asn(self, m: re.Match[str]) -> str:
        asn = m.group("asn")
        start, end = m.span("asn")
        base = m.start()
        whole = m.group(0)
        token = self._token_for("ASN", str(int(asn)), asn)
        return whole[: start - base] + token + whole[end - base:]


# Process-wide vault for the legacy module-level ``anonymize()`` helper.
# Bounded so it cannot leak memory over the life of a long-running server.
_DEFAULT_VAULT = SanitizeVault(
    max_entries=_int_env("AI_LOG_ANALYZER_VAULT_MAX_ENTRIES", _DEFAULT_MAX_ENTRIES),
    ttl_seconds=_int_env("AI_LOG_ANALYZER_VAULT_TTL_SECONDS", 3600) or None,
)


def anonymize(text: str) -> str:
    """Tokenize with the process-wide (bounded) vault."""
    return _DEFAULT_VAULT.tokenize(text)


def detokenize(text: str) -> str:
    """Reverse ``anonymize()`` using the process-wide vault."""
    return _DEFAULT_VAULT.detokenize(text)
