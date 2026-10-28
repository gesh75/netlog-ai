"""Property tests (hypothesis): the sanitizer is idempotent and redacts a random
secret in every known format. Skipped when hypothesis is not installed."""
from __future__ import annotations

import time

import pytest

pytest.importorskip("hypothesis")

from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from ai_log_analyzer.sanitize import sanitize  # noqa: E402

pytestmark = pytest.mark.unit

# Line templates with a {s} secret slot (same formats as test_sanitize_secret_formats.py).
TEMPLATES = [
    "neighbor 10.0.0.1 password 0 {s}", "neighbor 10.0.0.1 password {s}", "enable password {s}",
    "enable secret 9 $9$abcdefghijklmn${s}", "enable secret 5 {s}", "username u privilege 15 secret 0 {s}",
    "username u password {s}", "ip ospf authentication-key {s}", "ip ospf message-digest-key 1 md5 {s}",
    "ntp authentication-key 1 md5 {s}", "tacacs-server key {s}", "tacacs-server key 7 {s}",
    "radius-server key {s}", "radius-server host 10.1.1.1 key 0 {s}", "crypto isakmp key {s} address 1.2.3.4",
    'pre-shared-key ascii-text "{s}";', 'authentication-key "{s}";', 'plain-text-password-value "{s}";',
    "snmp-server host 10.9.9.9 version 2c {s}", "key-string {s}", "Authorization: Bearer {s}",
    "Authorization: Basic {s}", "GET /x?api_key={s}&n=1", "token={s}", "password={s}", "passwd={s}",
    "secret={s}", '{{"password": "{s}"}}', "https://user:{s}@git.example.net/r.git", " password {s}",
    "ip ospf message-digest-key 7 md5 {s}", "ntp authentication-key 7 md5 7 {s}", "ntp authentication-key 1 md5 {s} 7",
    "ntp authentication-key 1 sha1 ciphertext {s}", "security wpa psk set-key ascii 0 {s}", 'secret-key "{s}"',
    "pre-shared-key 6 {s}", "ip nhrp authentication {s}", "password: {s}", "X-API-Key: {s}", "psk={s}",
    "set shared server-profile radius R secret {s}", "<secret>{s}</secret>", "set password ENC {s}",
    "snmp-server user u g auth sha-256 0x{s} priv aes-256 0x{s} localizedV2key", "radius server R\n key 0 {s}\n",
    "server-private 192.0.2.1 key {s}", "nv set system aaa tacacs server 1 secret {s}", "tacacs passkey {s}",
    "set snmp community {s} authorization read-only", "community {s};", "snmp\n community {s}\n  authorization x",
    "rocommunity {s} default", "isis password {s} level-2", "standby 1 authentication text {s}",
    "ip msdp password peer 192.0.2.1 {s}", "ip rip authentication string {s}",
]
SECRET = st.text(alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", min_size=12, max_size=40)

WORDS = st.sampled_from([
    "password", "secret", "key", "0", "7", "9", "enable", "username", "neighbor", "10.0.0.1", "8.8.8.8",
    "authentication-key", "tacacs-server", "radius-server", "host", "snmp-server", "community", "version",
    "2c", "md5", "sha512", "$9$", "$1$abc$", "token=", "api_key=", "Authorization:", "Bearer", "Basic",
    "<REDACTED>", '"<REDACTED>"', "user-0123abcd", "description", "location", "serial", "{", "}", ";", '"',
    "\n", "  ", "pre-shared-key", "ascii-text", "https://u:p@h/", "-----BEGIN PRIVATE KEY-----", "xyz", "ro",
    "key-string", "crypto", "isakmp", "level", "5", "line", "vty",
    "psk", "set-key", "ascii", "hex", "ENC", "set", "nv", "isis", "standby", "authentication", "text", "key-chain",
    "secret-key", "$aes1$AQD=$abc==", "-AQ==abcdefgh=", "<secret>", "</secret>", "priv", "auth", "aes-128", "sha-256",
    "0xABCDEF", "passkey", "password:", "token:", "community-entry", "snmp {", "from {", "message-digest-key", "ntp",
    "hmac-sha2-256", "ciphertext", "encrypted", "clear", "msdp", "peer", "rip", "string", "server-private",
    "shared-key", "rocommunity", "add", "serial number", "eyJ", ".", "-", "=", ":",
])


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(secret=SECRET, idx=st.integers(0, len(TEMPLATES) - 1), mask_pii=st.booleans())
def test_random_secret_never_survives(secret, idx, mask_pii):
    line = TEMPLATES[idx].format(s=secret)
    out, n = sanitize(line, mask_pii=mask_pii, mask_public_ip=False)
    assert secret not in out and n >= 1
    again, n2 = sanitize(out, mask_pii=mask_pii, mask_public_ip=False)
    assert again == out and n2 == 0


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(parts=st.lists(WORDS, max_size=40), seps=st.sampled_from([" ", "\n", "", "\t"]), mask_pii=st.booleans())
def test_sanitize_is_idempotent_on_config_like_text(parts, seps, mask_pii):
    text = seps.join(parts)
    once, _ = sanitize(text, mask_pii=mask_pii, mask_public_ip=False)
    twice, _ = sanitize(once, mask_pii=mask_pii, mask_public_ip=False)
    assert twice == once


@settings(max_examples=200, deadline=None)
@given(text=st.text(max_size=400), mask_pii=st.booleans())
def test_sanitize_is_idempotent_on_arbitrary_text(text, mask_pii):
    once, _ = sanitize(text, mask_pii=mask_pii, mask_public_ip=False)
    twice, _ = sanitize(once, mask_pii=mask_pii, mask_public_ip=False)
    assert twice == once


@settings(max_examples=60, deadline=None)
@given(parts=st.lists(WORDS, min_size=1, max_size=8), reps=st.integers(2_000, 6_000))
def test_repeated_fragments_stay_linear(parts, reps):
    text = (" ".join(parts) + " ") * reps
    start = time.perf_counter()
    sanitize(text[:65_536], mask_pii=True)
    assert time.perf_counter() - start < 2.0
