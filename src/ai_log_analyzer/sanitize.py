"""Config sanitizer — strip secrets + PII before sending real configs to any LLM.

Two layers:

  SECRETS (always on):
    - Pre-shared keys / encrypted passwords ($1$, $7$, $9$, $6$)
    - SNMP community strings
    - BGP/OSPF/IS-IS authentication keys
    - RADIUS/TACACS shared secrets
    - SSH host keys
    - Certificate / private-key blobs (PEM, PGP armor, truncated blocks)
    - Generic credentials: ``password=``/``token=``/``api_key=`` pairs, HTTP
      ``Authorization`` headers, URL userinfo, cloud/API token prefixes

  PII (opt-in via mask_pii=True):
    - Usernames (Junos `user NAME { ... }` / EOS `username NAME ...`)
    - Public IPv4 addresses (kept private RFC1918 / link-local / loopback)
    - SSH key comments (often contain emails / employee IDs)

Returns (sanitized_text, redaction_count). For per-rule breakdown use sanitize_report().

NOTE: defense-in-depth net. Review output for any NEW vendor format before
sending to a cloud LLM the first time.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import threading
from collections import OrderedDict
from typing import Any

# A secret token: the whole non-space run, never an existing <REDACTED> (and
# never a token that is only followed by one), so re-sanitizing is a no-op.
# Every quantifier is bounded or single-level — no nested unbounded groups.
_TYPE = r"(?:[0-9]|sha512|sha256)"
_TOK = r'(?!"?<REDACTED)[^\s;]+(?![^\s;])(?![ \t]+(?:[^\s<]+[ \t]+){0,3}<REDACTED)'
_QTOK = r'(?:"(?!<REDACTED>")[^"\n]*"|' + _TOK + ")"
_R = r"\1 <REDACTED>"
_CRED_NAMES = (r"api[_-]?key|secret[_-]?(?:access[_-]?)?key|client[_-]?secret|token|passwd|password"
               r"|passphrase|private[_-]?key|secret|psk|passkey|pwd|auth[_-]?key|snmp[_-]?community"
               r"|community[_-]?string")
# A digest name after a key id (`message-digest-key 7 md5 K`, `ntp authentication-key 7 sha1 K`) and the
# word that may sit between it and the key: an encryption type (digit, IOS-XR clear/encrypted, Aruba
# plaintext/ciphertext). A key id is never the secret, so a rule for `key 7 ...` must not treat it as one.
_ALG = r"(?:md5|sha-?[0-9]{0,3}|(?:hmac|cmac)-[a-z0-9-]{3,20})"
_KTYPE = r"(?:[0-9]|clear|encrypted|plaintext|ciphertext)"
# Words that follow `password:` / `pre-shared-key` in log prose ("pre-shared-key mismatch"), not secrets.
_NOT_SECRET = (r"(?:required|incorrect|invalid|expired|missing|failed|mismatch(?:ed)?|none|null|true|false"
               r"|unset)(?![^\s\"'&;,])")
# FortiOS `set <field> [ENC] <value>` and PAN-OS / NVUE `set <path> <field> <value>` secret fields.
_SET_FIELDS = (r"password|passwd|passphrase|psksecret(?:-remote)?|ppk-secret|secret|key|auth-pwd|priv-pwd"
               r"|auth-password|priv-password|authentication-key|key-string|md5-key|api-key|bind-password"
               r"|shared-secret")
_PATH_FIELDS = (r"secret|password|passphrase|passkey|bind-password|shared-secret|snmp-community-string"
                r"|pre-shared-key[ \t]+key|auth-password|priv-password|md5-key")
# XML elements (PAN-OS and others) whose text is a secret.
_XML_SECRETS = (r"secret|password|passwd|passphrase|bind-password|shared-secret|snmp-community-string|phash"
                r"|authpwd|privpwd|auth-password|priv-password|private-key|psk")


def _kw(prefix: str, *, typed: bool = False, eol: bool = False, quoted: bool = False) -> re.Pattern[str]:
    """`<prefix> [type] <secret>` on one line: group 1 is everything but the secret.

    ``typed`` allows an encryption-type digit/word (``0``, ``7``, ``sha512``) after the
    prefix, which is kept; ``eol`` requires the secret to end the line (keeps prose such as
    "enable password for ..." intact); ``quoted`` also accepts a ``"quoted value"``.
    """
    group = prefix + (rf"(?:[ \t]+{_TYPE})?" if typed else "")
    tail = r"(?=[ \t\r]*$)" if eol else ""
    flags = re.IGNORECASE | (re.MULTILINE if eol else 0)
    return re.compile(rf"({group})[ \t]+{_QTOK if quoted else _TOK}{tail}", flags)


# Each rule: (description, pattern, replacement). $1 preserves the key/keyword.
# Order matters: a general rule must never consume the keyword another rule anchors on, so the
# statement-specific rules (FortiOS/PAN-OS/NVUE fields, key ids) run before the generic ones.
_RULES: list[tuple[str, Any, Any]] = [
    # ── Junos style ──────────────────────────────────────────────────────
    ("junos-encrypted-password",
     re.compile(r'(encrypted-password|authentication-key|secret|pre-shared-key|password|shared-secret)'
                r'[ \t]+"\$[0-9]\$[^"\n]+"', re.IGNORECASE),
     r'\1 "<REDACTED>"'),
    ("junos-quoted-encrypted",
     re.compile(r'"\$[0-9]\$[^"\n]+"'),
     '"<REDACTED>"'),
    # Only match SNMP community context, NOT Junos policy-options BGP communities.
    # SNMP community in Junos: `community NAME { authorization ...; clients ...; }`
    # SNMP-style in EOS:       `snmp-server community NAME ro`
    # BGP community (skip):     `community NAME members 1:1234;`  ← these are just labels
    ("junos-snmp-community",
     re.compile(r'\b(community)\s+(?!"?<REDACTED)(\S+)\s*\{(\s*(?:authorization|clients))',
                re.IGNORECASE),
     r'\1 <REDACTED>{\3'),
    ("junos-snmp-community-quoted",
     re.compile(r'\b(community)\s+"([^"]+)"\s*\{(\s*(?:authorization|clients))',
                re.IGNORECASE),
     r'\1 "<REDACTED>"{\3'),
    ("junos-authentication-key",
     re.compile(r'(authentication-key|hello-authentication-key)[ \t]+"(?!<REDACTED>")[^"\n]+"',
                re.IGNORECASE),
     r'\1 "<REDACTED>"'),
    # ── Statement-style secrets: FortiOS `set password ENC <blob>`, PAN-OS / NVUE `set <path> secret <v>`,
    # PAN-OS `-AQ==` blobs and XML elements. Before the key-id rules so `set authentication-key ENC <blob>`
    # is not read as the OSPF `authentication-key <type> <key>`.
    ("set-secret-field",
     re.compile(rf"(?m)^([ \t]*set[ \t]+(?:{_SET_FIELDS})(?:[ \t]+ENC)?)[ \t]+{_QTOK}", re.IGNORECASE), _R),
    ("set-path-secret",
     re.compile(rf'(?m)^([ \t]*set[ \t]+[^\n"]{{0,300}}?[ \t](?:{_PATH_FIELDS}))[ \t]+{_QTOK}',
                re.IGNORECASE), _R),
    ("xml-secret-element",
     re.compile(rf"(<({_XML_SECRETS})>)[ \t\r\n]*[^<\s][^<]*(</\2>)", re.IGNORECASE), r"\1<REDACTED>\3"),
    ("xml-pre-shared-key",
     re.compile(r"(<pre-shared-key>[ \t\r\n]*<key>)[ \t\r\n]*[^<\s][^<]*(</key>)", re.IGNORECASE),
     r"\1<REDACTED>\2"),
    # PAN-OS encrypts stored secrets as `-AQ==<base64>`; one anywhere is a secret.
    ("panos-encrypted-blob",
     re.compile(r"(?<![A-Za-z0-9+/=_-])-AQ==[A-Za-z0-9+/=]{6,}"), "<REDACTED-HASH>"),
    # ── Key ids vs keys ──────────────────────────────────────────────────
    # The number after `message-digest-key` / `ntp authentication-key` is an id (7 is common), so these
    # run before the type-7 rule below, which would otherwise take `key 7` and redact the digest word.
    ("ospf-isis-keys",
     _kw(rf"(?<!ntp[ ])\bauthentication-key(?:[ \t]+(?:[0-9]|ENC))?"
         rf"|\bmessage-digest-key[ \t]+\d{{1,10}}[ \t]+{_ALG}(?:[ \t]+{_KTYPE})?", quoted=True), _R),
    ("ntp-authentication-key",
     _kw(rf"\bntp[ \t]+authentication-key[ \t]+\d{{1,10}}[ \t]+{_ALG}(?:[ \t]+{_KTYPE})?"), _R),
    # ── Arista EOS / IOS style ───────────────────────────────────────────
    ("eos-secret-7",
     re.compile(rf'\b(secret|password|key)[ \t]+7[ \t]+(?!<REDACTED)(?!{_ALG}(?![^\s;]))\S+',
                re.IGNORECASE),
     r'\1 7 <REDACTED>'),
    ("eos-secret-5",
     re.compile(r'\b(secret|password)[ \t]+5[ \t]+\$1\$\S+',
                re.IGNORECASE),
     r'\1 5 <REDACTED>'),
    ("eos-snmp-community",
     re.compile(r'\b(snmp-server[ \t]+community)[ \t]+(?!<REDACTED)(\S+)',
                re.IGNORECASE),
     r'\1 <REDACTED>'),
    # `key 0 X` / `password 0 X`: the digit is the encryption TYPE, not the secret,
    # so it stays and the token after it is redacted.
    ("eos-radius-key",
     _kw(r"\b(?:radius-server[ \t]+key|radius-server[ \t]+host[ \t]+\S{1,64}[ \t]+(?:[^\n]{0,100}?[ \t])?key)"
         r"(?:[ \t]+(?:[0-9]|plaintext|ciphertext))?"), _R),
    ("eos-tacacs-key",
     _kw(r"\b(?:tacacs-server[ \t]+key|tacacs-server[ \t]+host[ \t]+\S{1,64}[ \t]+(?:[^\n]{0,100}?[ \t])?key)"
         r"(?:[ \t]+(?:[0-9]|plaintext|ciphertext))?"), _R),
    ("eos-bgp-password", _kw(r"\bneighbor[ \t]+\S{1,64}[ \t]+password(?:[ \t]+[0-9])?"), _R),
    # SNMPv3 USM keys — EOS/IOS `snmp-server user U G v3 auth sha KEY priv aes KEY`, NX-OS
    # `auth sha-256 0xKEY priv aes-128 0xKEY` / `priv 0xKEY` and Junos `authentication-password "..."`.
    ("snmpv3-auth-priv-key",
     re.compile(rf'\b(auth[ \t]+(?:md5|sha(?:-?\d+)?)|priv[ \t]+(?:des|3des|aes(?:-?\d+)?)(?:[ \t]+\d+)?)'
                rf'[ \t]+{_TOK}', re.IGNORECASE),
     r'\1 <REDACTED>'),
    # `priv` with no cipher name (NX-OS) is a key only on a `snmp-server user` line: in `snmp-server group
    # G v3 priv read V` it is the security level.
    ("snmpv3-user-priv-key",
     re.compile(r'\b(snmp-server[ \t]+user[ \t]+[^\n]{0,200}?[ \t]priv)[ \t]+'
                rf'(?!(?:des|3des|aes(?:-?\d+)?)(?![^\s;])){_TOK}', re.IGNORECASE),
     r'\1 <REDACTED>'),
    ("junos-snmpv3-password",
     re.compile(r'\b(authentication-password|privacy-password)[ \t]+(?!"?<REDACTED)(?:"[^"\n]*"|\S+)',
                re.IGNORECASE),
     r'\1 "<REDACTED>"'),
    # ── Generic encrypted blobs ──────────────────────────────────────────
    ("openssh-host-key",
     re.compile(r'(?:ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp\d+)\s+[A-Za-z0-9+/=]{40,}',
                re.IGNORECASE),
     '<REDACTED-SSH-KEY>'),
    # Bodies scan with `[\s\S]*?` + a swallow-to-end fallback (a truncated block still
    # hides everything after its header) so a pile of BEGIN lines stays linear.
    ("private-key-block",
     re.compile(r'-----BEGIN (?:[A-Z0-9]+ ){0,4}PRIVATE KEY(?: BLOCK)?-----(?!\s*<REDACTED-PRIVATE-KEY>)'
                r'(?:[\s\S]*?-----END (?:[A-Z0-9]+ ){0,4}PRIVATE KEY(?: BLOCK)?-----|[\s\S]*\Z)'),
     '-----BEGIN PRIVATE KEY-----\n<REDACTED-PRIVATE-KEY>\n-----END PRIVATE KEY-----'),
    ("certificate-block",
     re.compile(r'-----BEGIN CERTIFICATE-----(?!\s*<REDACTED-CERTIFICATE>)[^-]*-----END CERTIFICATE-----'),
     '-----BEGIN CERTIFICATE-----\n<REDACTED-CERTIFICATE>\n-----END CERTIFICATE-----'),
    # ── Credentials in other formats ─────────────────────────────────────
    # Typed Cisco-style secrets: the digit/word after the keyword is the
    # encryption TYPE and stays; the token after it is the secret.
    ("enable-password",
     _kw(r"\benable[ \t]+(?:password|secret)(?:[ \t]+level[ \t]+\d{1,2})?",
         typed=True, eol=True), _R),
    ("username-secret",
     _kw(r"\busername[ \t]+\S{1,64}[^\n]{0,120}?[ \t](?:secret|password)", typed=True), _R),
    ("typed-password-secret",
     re.compile(rf"\b((?:password|secret)[ \t]+[05-9])[ \t]+{_TOK}", re.IGNORECASE), _R),
    ("line-password",
     re.compile(rf"(?m)^([ \t]*(?:password|secret)(?:[ \t]+{_TYPE})?)[ \t]+{_TOK}(?=[ \t\r]*$)",
                re.IGNORECASE), _R),
    ("crypto-isakmp-key", _kw(r"\bcrypto[ \t]+isakmp[ \t]+key(?:[ \t]+[0-9])?"), _R),
    ("ikev2-pre-shared-key",
     _kw(r"\bpre-shared-key[ \t]+(?:(?:local|remote)(?:[ \t]+[0-9])?"
         r"|address[ \t]+\S{1,64}[ \t]+key(?:[ \t]+[0-9])?)"), _R),
    # Keyring `pre-shared-key [0|6] <secret>`, ASA `ikev1|ikev2 ... pre-shared-key <secret>` and IKEv2
    # profile `pre-share key <secret>`: the secret ends the line (keeps "pre-shared-key mismatch on ..."),
    # and the Junos / PAN-OS / `local|remote|address` forms keep their own rules.
    ("pre-shared-key-bare",
     re.compile(rf"(?m)\b((?:pre-shared-key(?![ \t]+(?:local|remote|address|ascii-text|hexadecimal|key)"
                rf"(?![^\s;]))|pre-share[ \t]+key)(?:[ \t]+[0-9])?)[ \t]+(?!{_NOT_SECRET}){_TOK}"
                r"(?=[ \t\r]*$)", re.IGNORECASE), _R),
    ("nhrp-authentication", _kw(r"\b(?:ip|ipv6)[ \t]+nhrp[ \t]+authentication", eol=True), _R),
    ("key-string", _kw(r"\bkey-string(?:[ \t]+[0-9])?"), _R),
    ("snmp-server-host-community",
     re.compile(r"\b(snmp-server[ \t]+host[ \t]+\S{1,64}(?:[ \t]+vrf[ \t]+\S{1,32})?(?:[ \t]+(?:traps|informs))?"
                r"(?:[ \t]+version[ \t]+(?:1|2c|3(?:[ \t]+(?:auth|noauth|priv))?))?)"
                rf"[ \t]+(?!(?:vrf|traps|informs|version)[ \t]){_TOK}", re.IGNORECASE), _R),
    # Junos: quoted or bare values; output is always quoted.
    ("junos-secret-values",
     re.compile(rf"\b(pre-shared-key[ \t]+(?:ascii-text|hexadecimal)|encrypted-password"
                rf"|plain-text-password(?:-value)?|simple-password|md5[ \t]+\d{{1,3}}[ \t]+key)[ \t]+{_QTOK}",
                re.IGNORECASE), r'\1 "<REDACTED>"'),
    # ── Wireless, Nokia SR Linux, AAA blocks, IS-IS / RIP / FHRP / MSDP, SNMP communities ───────────
    # WPA pre-shared keys: IOS-XE `security wpa psk set-key ascii|hex [type] KEY`, AireOS `... akm psk
    # set-key ascii <type> KEY <wlan-id>`, autonomous AP `wpa-psk ascii [type] KEY`.
    ("wpa-psk",
     _kw(r"\b(?:psk[ \t]+set-key|wpa-psk)[ \t]+(?:ascii|hex)(?:[ \t]+[0-9])?", quoted=True), _R),
    ("srl-secret-key", _kw(r"(?<![\w-])secret-key", quoted=True), _R),
    ("srl-community-entry",
     re.compile(rf"((?<![\w-])community-entry[ \t]+\S{{1,64}}(?:[ \t]*\{{)?[ \t\r\n]{{0,40}}"
                rf"(?<![\w-])community)[ \t]+{_QTOK}", re.IGNORECASE), _R),
    # ── Tokens, headers, URLs, key=value pairs ───────────────────────────
    ("http-authorization",
     re.compile(r"""\b(authorization["']?[ \t]*[:=][ \t]*["']?(?:(?:bearer|basic|token|negotiate)[ \t]+)?)"""
                r"""(?!"?<REDACTED)[^\s"',;]+(?![^\s"',;])(?![ \t]+(?:[^\s<]+[ \t]+){0,3}<REDACTED)""",
                re.IGNORECASE), r"\1<REDACTED>"),
    ("bearer-token",
     re.compile(r"\b(bearer)[ \t]+[A-Za-z0-9._~+/=-]{16,}", re.IGNORECASE), r"\1 <REDACTED>"),
    ("url-userinfo",
     re.compile(r"""\b([a-z][a-z0-9+.-]{1,20}://[^\s/:@"'<>]{0,128}:)[^\s/"'<>]{1,256}@""", re.IGNORECASE),
     r"\1<REDACTED>@"),
    ("url-token-userinfo",
     re.compile(r"\b(https?://)[A-Za-z0-9_-]{20,256}@", re.IGNORECASE), r"\1<REDACTED>@"),
    ("credential-pair",
     re.compile(rf"""(?<![A-Za-z0-9])((?:{_CRED_NAMES})["']?[ \t]*=[ \t]*)(?!["']?<REDACTED)"""
                r"""(?:"[^"\n]*"|'[^'\n]*'|[^\s"'&;,]+)""", re.IGNORECASE),
     r"\1<REDACTED>"),
    ("credential-json",
     re.compile(r'(?<![A-Za-z0-9])("(?:' + _CRED_NAMES + r')"[ \t]*:[ \t]*)"(?!<REDACTED>")[^"\n]*"',
                re.IGNORECASE),
     r'\1"<REDACTED>"'),
    # `name: value` (YAML, HTTP headers, `k: v` logs, prefixed JSON keys); a quoted value keeps its quotes.
    ("credential-colon",
     re.compile(rf"""(?<![A-Za-z0-9])((?:{_CRED_NAMES})["']?[ \t]*:[ \t]*)"""
                rf"""(?!["']?<REDACTED)(?!{_NOT_SECRET})(?:(")[^"\n]*"|(')[^'\n]*'|[^\s"'&;,]+)""",
                re.IGNORECASE),
     lambda m: f"{m.group(1)}{m.group(2) or m.group(3) or ''}<REDACTED>{m.group(2) or m.group(3) or ''}"),
    ("cloud-api-token",
     re.compile(r"\b(?:(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|AIPA)[A-Z0-9]{16}"
                r"|gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255}"
                r"|xox[abposr]-[A-Za-z0-9-]{10,200}|AIza[0-9A-Za-z_-]{35}"
                r"|sk-(?:ant-|proj-)[A-Za-z0-9_-]{20,200}|sk-[A-Za-z0-9]{32,200}"
                r"|eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})(?![A-Za-z0-9_-])"),
     "<REDACTED-TOKEN>"),
    # Modular-crypt hashes ($1$ md5, $5$/$6$ sha, $8$/$9$ Cisco, $y$ yescrypt, $aes1$ SR Linux, ...) anywhere.
    ("crypt-hash",
     re.compile(r"(?<![\w$])\$(?:aes1?|1|5|6|7|8|9|y|2[abxy])\$[A-Za-z0-9./$=,+-]{6,}"),
     "<REDACTED-HASH>"),
]


# Pseudonym tokens (PUB-xxxxxxxx, user-xxxxxxxx) leave the host in LLM prompts,
# webhooks and Slack, so they must not be reversible by hashing guesses: they are
# HMAC-SHA256 under a secret key. AI_LOG_ANALYZER_PSEUDONYM_KEY pins the key
# (stable across restarts and gunicorn workers); otherwise a random per-process
# key is generated once, so tokens are stable inside one process only.
_PSEUDONYM_KEY_ENV = "AI_LOG_ANALYZER_PSEUDONYM_KEY"
_random_key: bytes | None = None
_random_key_lock = threading.Lock()


def _pseudonym_key() -> bytes:
    global _random_key
    configured = os.environ.get(_PSEUDONYM_KEY_ENV, "").strip()
    if configured:
        return configured.encode()
    with _random_key_lock:
        if _random_key is None:
            _random_key = secrets.token_bytes(32)
        return _random_key


def _reset_pseudonym_key() -> None:
    """Forget the generated per-process key (tests)."""
    global _random_key
    with _random_key_lock:
        _random_key = None


def _hash_token(text: str, salt: str = "ai-log-analyzer") -> str:
    """Stable short keyed token for replacing identifiers — same input → same token
    (within one key), but not derivable without the key."""
    return hmac.new(_pseudonym_key(), f"{salt}:{text}".encode(), hashlib.sha256).hexdigest()[:8]


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
     re.compile(r'\b(user)\s+(?!user-[0-9a-f]{8}\b)([a-z][\w.\-]{1,40})(\s*\{)',
                re.IGNORECASE),
     _redact_user),
    # EOS / IOS: username name privilege 15 ...   |  username name secret ...
    ("eos-username",
     re.compile(r'\b(username)\s+(?!user-[0-9a-f]{8}\b)([a-z][\w.\-]{1,40})(\b)',
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
     re.compile(r'\b(full-name)\s+"(?!<REDACTED-NAME>")[^"]+"',
                re.IGNORECASE),
     r'\1 "<REDACTED-NAME>"'),
    # Interface / neighbor descriptions carry circuit IDs, customer names and
    # carrier references. Statement-anchored (start of line or after `{`/`;`,
    # optional Junos `set ...` prefix) and lowercase so prose like
    # "Description: ..." in a prompt header is left alone.
    ("config-description",
     re.compile(r'(?m)((?:^|[{;])[ \t]*(?:set [^\n]{0,200}?\s)?description)[ \t]+(?!"<REDACTED-DESC>")(?:"[^"\n]*"|[^;{}\n]+)'),
     r'\1 "<REDACTED-DESC>"'),
    # SNMP sysLocation / sysContact — street addresses, rack IDs, people.
    ("snmp-location-contact",
     re.compile(r'(?m)((?:^|[{;])[ \t]*(?:snmp-server\s+|set\s+snmp\s+)?(?:location|contact))[ \t]+(?!"<REDACTED>")(?:"[^"\n]*"|[^;{}\n]+)'),
     r'\1 "<REDACTED>"'),
    # Chassis / module serial numbers (asset identifiers). The value must
    # contain a digit so `serial console` / `interface Serial0/0` survive.
    ("serial-number",
     re.compile(r'(?i)\b(serial[ _-]?(?:number|num|no)?|s/n)(\s*[:=#]?\s*)(?=[A-Za-z0-9-]*\d)[A-Za-z0-9][A-Za-z0-9-]{4,}\b'),
     r'\1\2<REDACTED-SERIAL>'),
]


# Bounded local memory of PUB-token → raw IP so the LLM gateway can map a
# pseudonymized public address back for the operator (never sent anywhere).
_PUBLIC_TOKEN_MAX = 4096
_public_tokens: OrderedDict[str, str] = OrderedDict()
_public_tokens_lock = threading.Lock()


def _remember_public_token(token: str, ip_text: str) -> None:
    with _public_tokens_lock:
        _public_tokens[token] = ip_text
        _public_tokens.move_to_end(token)
        while len(_public_tokens) > _PUBLIC_TOKEN_MAX:
            _public_tokens.popitem(last=False)


def resolve_public_token(token: str) -> str | None:
    """Raw IP for a ``PUB-xxxxxxxx`` token minted in this process, if remembered."""
    with _public_tokens_lock:
        return _public_tokens.get(token)


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
        _remember_public_token(mapping[ip_text], ip_text)
        replacements += 1
        return mapping[ip_text]

    ipv4_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    out = ipv4_re.sub(replace_one, text)
    return out, replacements


# Redacting one value can expose another (a redacted keyword stops hiding the
# next one), so rules run until the text stops changing. Typical text takes
# one pass (+ one no-op pass when something was redacted); the cap bounds worst-case cost.
_MAX_PASSES = 4


def _apply_rules(text: str, rules: list, breakdown: dict[str, int] | None = None) -> tuple[str, int]:
    """Run ``rules`` to a fixed point, so ``sanitize(sanitize(x)) == sanitize(x)``."""
    total = 0
    for _ in range(_MAX_PASSES):
        before = text
        for name, pat, repl in rules:
            text, n = pat.subn(repl, text)
            if n:
                total += n
                if breakdown is not None:
                    breakdown[name] = breakdown.get(name, 0) + n
        if text == before:
            break
    return text, total


def sanitize(text: str, mask_pii: bool = False,
             mask_public_ip: bool | None = None) -> tuple[str, int]:
    """Redact secrets (and optionally PII) from a config blob.

    ``mask_public_ip`` defaults to ``mask_pii``. The LLM gateway passes
    ``False`` because its reversible vault tokenizes every address instead.

    Returns (sanitized_text, total_redactions).
    """
    out, total = _apply_rules(text, _RULES + _PII_RULES if mask_pii else _RULES)
    if mask_pii if mask_public_ip is None else mask_public_ip:
        out, n = _mask_public_ipv4(out)
        total += n
    return out, total


def sanitize_report(text: str, mask_pii: bool = False) -> dict:
    """Per-rule breakdown — useful for debugging false positives."""
    breakdown: dict[str, int] = {}
    out, _ = _apply_rules(text, _RULES + _PII_RULES if mask_pii else _RULES, breakdown)
    if mask_pii:
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
        breakdown: dict[str, int] = {}
        out, _ = _apply_rules(raw, _RULES + _PII_RULES if mask_pii else _RULES, breakdown)
        if mask_pii:
            out, n_ip = _mask_public_ipv4(out, mapping=ip_mapping)
            if n_ip:
                breakdown["public-ipv4"] = n_ip
        results[fname] = {
            "sanitized": out,
            "total": sum(breakdown.values()),
            "by_rule": breakdown,
        }
    return results
