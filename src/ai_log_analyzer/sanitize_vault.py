"""Log-line vault anonymizer — mask addresses before any LLM call.

``sanitize.py`` is the *config* sanitizer (secrets, public IPv4). This module
is the *syslog* vault: every IPv4, IPv6, MAC, and ASN in a log line is replaced
so EVPN Type-2 MAC/IP advertisements cannot leak into ``llm.py``.

Stable mapping: the same raw token always becomes the same placeholder inside
one ``SanitizeVault`` instance, so a burst still clusters.
"""
from __future__ import annotations

import re

# Colon-MAC is a 6-group IPv6 lookalike; leave it for the MAC pass.
_MAC_COLON_RE = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")

_IPV6_RE = re.compile(
    r"(?<![:\w])(?:"
    r"(?:[0-9a-fA-F]{1,4}:){6}[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|:(?::[0-9a-fA-F]{1,4}){1,7}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}"
    r")(?:/\d{1,3})?(?![:\w])"
)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
_MAC_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b"
    r"|"
    r"\b(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}\b",
    re.IGNORECASE,
)
_ASN_RE = re.compile(r"\bAS\s*\d+\b", re.IGNORECASE)

_KIND_PLACEHOLDER = {
    "IPV6": "<IPV6>",
    "IPV4": "<IPV4>",
    "MAC": "<MAC>",
    "ASN": "<ASN>",
}


class SanitizeVault:
    """Stateful anonymizer. Mapping is per-instance so tests stay isolated."""

    def __init__(self) -> None:
        self.mapping: dict[str, str] = {}

    def anonymize(self, text: str) -> str:
        """Mask IPv6, IPv4, MAC (colon/dash/Cisco-dotted), and ASN tokens."""
        if not text:
            return text
        out = self._apply(text, _IPV6_RE, "IPV6")
        out = self._apply(out, _IPV4_RE, "IPV4")
        out = self._apply(out, _MAC_RE, "MAC")
        out = self._apply(out, _ASN_RE, "ASN")
        return out

    def _apply(self, text: str, pattern: re.Pattern[str], kind: str) -> str:
        placeholder = _KIND_PLACEHOLDER[kind]

        def _replace(match: re.Match[str]) -> str:
            value = match.group(0)
            if kind == "IPV6" and _MAC_COLON_RE.fullmatch(value):
                return value
            if value not in self.mapping:
                self.mapping[value] = placeholder
            return self.mapping[value]

        return pattern.sub(_replace, text)


_DEFAULT_VAULT = SanitizeVault()


def anonymize(text: str) -> str:
    """Anonymize with the process-wide vault (stable tokens across calls)."""
    return _DEFAULT_VAULT.anonymize(text)
