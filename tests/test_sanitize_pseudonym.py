"""Pseudonym tokens (PUB-/user-) are keyed HMACs, not an unsalted hash that
anyone can reproduce offline by enumerating the IPv4 space or a user list."""
from __future__ import annotations

import hashlib
import re

import pytest

from ai_log_analyzer import sanitize as san

pytestmark = pytest.mark.unit

_ENV = san._PSEUDONYM_KEY_ENV


@pytest.fixture(autouse=True)
def _fresh_key(monkeypatch):
    monkeypatch.delenv(_ENV, raising=False)
    san._reset_pseudonym_key()
    yield
    san._reset_pseudonym_key()


def _legacy_unsalted(text: str, salt: str = "ai-log-analyzer") -> str:
    return hashlib.sha256(f"{salt}:{text}".encode()).hexdigest()[:8]


def test_token_is_not_the_old_unsalted_hash():
    out, _ = san.sanitize("neighbor 8.8.8.8 remote-as 65000", mask_pii=True)
    token = re.search(r"PUB-([0-9a-f]{8})", out).group(1)
    assert token != _legacy_unsalted("8.8.8.8")
    user_out, _ = san.sanitize("username alice privilege 15", mask_pii=True)
    assert re.search(r"user-([0-9a-f]{8})", user_out).group(1) != _legacy_unsalted("alice", "username")


def test_tokens_stable_within_a_process():
    a, _ = san.sanitize("peer 8.8.8.8", mask_pii=True)
    b, _ = san.sanitize("other 8.8.8.8", mask_pii=True)
    assert re.search(r"PUB-[0-9a-f]{8}", a).group(0) == re.search(r"PUB-[0-9a-f]{8}", b).group(0)


def test_random_key_differs_between_processes():
    first = san._hash_token("8.8.8.8")
    san._reset_pseudonym_key()  # simulates a second worker process
    assert san._hash_token("8.8.8.8") != first


def test_env_key_gives_cross_process_stability(monkeypatch):
    monkeypatch.setenv(_ENV, "k1-shared-across-workers")
    first = san._hash_token("8.8.8.8")
    san._reset_pseudonym_key()
    assert san._hash_token("8.8.8.8") == first


def test_different_env_keys_give_different_tokens(monkeypatch):
    monkeypatch.setenv(_ENV, "key-one")
    one = san._hash_token("8.8.8.8")
    monkeypatch.setenv(_ENV, "key-two")
    assert san._hash_token("8.8.8.8") != one


def test_salt_still_separates_namespaces(monkeypatch):
    monkeypatch.setenv(_ENV, "key-one")
    assert san._hash_token("alice", salt="username") != san._hash_token("alice")


def test_username_token_is_not_rehashed_on_second_pass():
    once, _ = san.sanitize("username alice privilege 15", mask_pii=True)
    twice, n = san.sanitize(once, mask_pii=True)
    assert twice == once and n == 0


def test_public_ip_token_still_resolves_for_the_operator():
    out, _ = san.sanitize("neighbor 8.8.8.8 remote-as 65000", mask_pii=True)
    token = re.search(r"PUB-[0-9a-f]{8}", out).group(0)
    assert san.resolve_public_token(token) == "8.8.8.8"
