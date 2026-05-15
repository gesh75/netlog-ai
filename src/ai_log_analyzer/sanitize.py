"""Config sanitizer — strip secrets + PII before sending real configs to any LLM.

Two layers:

  SECRETS (always on):
    - Pre-shared keys / encrypted passwords ($1$, $7$, $9$, $6$)
    - SNMP community strings
    - BGP/OSPF/IS-IS authentication keys
    - RADIUS/TACACS shared secrets
    - SSH host keys
    - Certificate / private-key blobs

  PII (opt-in via mask_pii=True):
    - Usernames (Junos `user NAME { ... }` / EOS `username NAME ...`)
    - Public IPv4 addresses (kept private RFC1918 / link-local / loopback)
    - SSH key comments (often contain emails / employee IDs)

Returns (sanitized_text, redaction_count). For per-rule breakdown use sanitize_report().

NOTE: defense-in-depth net. Review output for any NEW vendor format before
sending to a cloud LLM the first time.
"""
from __future__ import annotations

import ipaddress
import re

# Each rule: (description, pattern, replacement). $1 preserves the key/keyword.
_RULES: list[tuple[str, re.Pattern[str], str]] = [
    # ── Junos style ──────────────────────────────────────────────────────
    ("junos-encrypted-password",
     re.compile(r'(encrypted-password|authentication-key|secret|pre-shared-key|password|shared-secret)\s+"\$[0-9]\$[^"]+"',
                re.IGNORECASE),
     r'\1 "<REDACTED>"'),
    ("junos-quoted-encrypted",
     re.compile(r'"\$[0-9]\$[^"]+"'),
     '"<REDACTED>"'),
    # Only match SNMP community context, NOT Junos policy-options BGP communities.
    # SNMP community in Junos: `community NAME { authorization ...; clients ...; }`
    # SNMP-style in EOS:       `snmp-server community NAME ro`
    # BGP community (skip):     `community NAME members 1:1234;`  ← these are just labels
    ("junos-snmp-community",
     re.compile(r'\b(community)\s+(\S+)\s*\{(\s*(?:authorization|clients))',
                re.IGNORECASE),
     r'\1 <REDACTED>{\3'),
    ("junos-snmp-community-quoted",
     re.compile(r'\b(community)\s+"([^"]+)"\s*\{(\s*(?:authorization|clients))',
                re.IGNORECASE),
     r'\1 "<REDACTED>"{\3'),
    ("junos-authentication-key",
     re.compile(r'(authentication-key|hello-authentication-key)\s+"[^"]+"',
                re.IGNORECASE),
     r'\1 "<REDACTED>"'),
    # ── Arista EOS / IOS style ───────────────────────────────────────────
    ("eos-secret-7",
     re.compile(r'\b(secret|password|key)\s+7\s+\S+',
                re.IGNORECASE),
     r'\1 7 <REDACTED>'),
    ("eos-secret-5",
     re.compile(r'\b(secret|password)\s+5\s+\$1\$\S+',
                re.IGNORECASE),
     r'\1 5 <REDACTED>'),
    ("eos-snmp-community",
     re.compile(r'\b(snmp-server\s+community)\s+(\S+)',
                re.IGNORECASE),
     r'\1 <REDACTED>'),
    ("eos-radius-key",
     re.compile(r'\b(radius-server\s+host\s+\S+\s+key)\s+(?:7\s+)?\S+',
                re.IGNORECASE),
     r'\1 <REDACTED>'),
    ("eos-tacacs-key",
     re.compile(r'\b(tacacs-server\s+host\s+\S+\s+key)\s+(?:7\s+)?\S+',
                re.IGNORECASE),
     r'\1 <REDACTED>'),
    ("eos-bgp-password",
     re.compile(r'\b(neighbor\s+\S+\s+password)\s+(?:7\s+)?\S+',
                re.IGNORECASE),
     r'\1 <REDACTED>'),
    # ── Generic encrypted blobs ──────────────────────────────────────────
    ("openssh-host-key",
     re.compile(r'(?:ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp\d+)\s+[A-Za-z0-9+/=]{40,}',
                re.IGNORECASE),
     '<REDACTED-SSH-KEY>'),
    ("private-key-block",
     re.compile(r'-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+PRIVATE KEY-----',
                re.MULTILINE),
     '-----BEGIN PRIVATE KEY-----\n<REDACTED-PRIVATE-KEY>\n-----END PRIVATE KEY-----'),
    ("certificate-block",
     re.compile(r'-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----',
                re.MULTILINE),
     '-----BEGIN CERTIFICATE-----\n<REDACTED-CERTIFICATE>\n-----END CERTIFICATE-----'),
]


def _hash_token(text: str, salt: str = "ai-log-analyzer") -> str:
    """Stable short token for replacing identifiers — same input → same token."""
    import hashlib
    h = hashlib.sha256(f"{salt}:{text}".encode()).hexdigest()[:8]
    return h


def _redact_user(match: re.Match) -> str:
    keyword = match.group(1)
    name = match.group(2)
    tail = match.group(3) if match.lastindex and match.lastindex >= 3 else ""
    return f"{keyword} user-{_hash_token(name.lower(), salt='username')}{tail}"


# ── PII rules (opt-in via mask_pii=True) ─────────────────────────────────────
# Each entry is either (name, pattern, replacement_string) OR (name, pattern, callable).
_PII_RULES: list = [
    # Junos user blocks:   user username.lastname { ... uid 2001; class super-user; }
    ("junos-user-block",
     re.compile(r'\b(user)\s+([a-z][\w.\-]{1,40})(\s*\{)',
                re.IGNORECASE),
     _redact_user),
    # EOS / IOS: username name privilege 15 ...   |  username name secret ...
    ("eos-username",
     re.compile(r'\b(username)\s+([a-z][\w.\-]{1,40})(\b)',
                re.IGNORECASE),
     _redact_user),
    # SSH key comments — typically contain emails or employee IDs at end of pubkey.
    # CRITICAL: bound the match to the same line — otherwise the regex eats
    # multiple lines of config that follow.
    ("ssh-comment-after-redaction",
     re.compile(r'(<REDACTED-SSH-KEY>)[ \t]+[^\n"\';]*'),
     r'\1'),
    # `full-name "First Last"` (Junos)
    ("junos-full-name",
     re.compile(r'\b(full-name)\s+"[^"]+"',
                re.IGNORECASE),
     r'\1 "<REDACTED-NAME>"'),
]


def _mask_public_ipv4(text: str, mapping: dict[str, str] | None = None) -> tuple[str, int]:
    """Replace every public IPv4 with a stable pseudonymous token, keeping
    private/loopback/link-local intact so topology readability is preserved.

    Returns (sanitized_text, replacements_in_this_text) — the count is
    occurrences actually rewritten in *this* text, not the cumulative
    unique-IP count across the shared mapping.
    """
    mapping = mapping if mapping is not None else {}
    replacements = 0

    def replace_one(m: re.Match) -> str:
        nonlocal replacements
        ip_text = m.group(0)
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError:
            return ip_text
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            return ip_text
        if ip_text not in mapping:
            mapping[ip_text] = f"PUB-{_hash_token(ip_text)}"
        replacements += 1
        return mapping[ip_text]

    ipv4_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    out = ipv4_re.sub(replace_one, text)
    return out, replacements


def sanitize(text: str, mask_pii: bool = False) -> tuple[str, int]:
    """Redact secrets (and optionally PII) from a config blob.

    Returns (sanitized_text, total_redactions).
    """
    out = text
    total = 0
    for _name, pat, repl in _RULES:
        out, n = pat.subn(repl, out)
        total += n
    if mask_pii:
        for _name, pat, repl in _PII_RULES:
            out, n = pat.subn(repl, out)
            total += n
        out, n = _mask_public_ipv4(out)
        total += n
    return out, total


def sanitize_report(text: str, mask_pii: bool = False) -> dict:
    """Per-rule breakdown — useful for debugging false positives."""
    out = text
    breakdown: dict[str, int] = {}
    for name, pat, repl in _RULES:
        out, n = pat.subn(repl, out)
        if n:
            breakdown[name] = n
    if mask_pii:
        for name, pat, repl in _PII_RULES:
            out, n = pat.subn(repl, out)
            if n:
                breakdown[name] = n
        # IPs (shared mapping so multiple files map the same IP to the same token)
        out, n = _mask_public_ipv4(out)
        if n:
            breakdown["public-ipv4"] = n
    return {"sanitized": out, "total": sum(breakdown.values()), "by_rule": breakdown}


def sanitize_many(files: dict[str, str], mask_pii: bool = True) -> dict[str, dict]:
    """Sanitize multiple files with a SHARED IP mapping — same public IP gets
    the same token across all files. Required so site-bundle analyses preserve
    cross-device topology relationships.

    Args:
        files: {filename: raw_text}
    Returns:
        {filename: {sanitized, total, by_rule}}
    """
    ip_mapping: dict[str, str] = {}
    results: dict[str, dict] = {}
    for fname, raw in files.items():
        out = raw
        breakdown: dict[str, int] = {}
        for name, pat, repl in _RULES:
            out, n = pat.subn(repl, out)
            if n:
                breakdown[name] = n
        if mask_pii:
            for name, pat, repl in _PII_RULES:
                out, n = pat.subn(repl, out)
                if n:
                    breakdown[name] = n
            out, n_ip = _mask_public_ipv4(out, mapping=ip_mapping)
            if n_ip:
                breakdown["public-ipv4"] = n_ip
        results[fname] = {
            "sanitized": out,
            "total": sum(breakdown.values()),
            "by_rule": breakdown,
        }
    return results
