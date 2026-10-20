"""SanitizeVault: deterministic, reversible, bounded entity tokenization."""
from __future__ import annotations

import pytest

from ai_log_analyzer.llm import prepare_log_samples
from ai_log_analyzer.sanitize import sanitize
from ai_log_analyzer.sanitize_vault import SanitizeVault, anonymize

pytestmark = pytest.mark.unit

TYPE2_LINE = (
    "Oct 13 10:00:01 leaf1 bgpd: EVPN Type-2 MAC/IP aa:bb:cc:dd:ee:ff "
    "10.1.1.10 2001:db8::10 VNI 10010 withdraw AS65000 "
    "cisco aabb.ccdd.eeff dash aa-bb-cc-dd-ee-fe"
)


def test_tokenize_masks_ipv4_ipv6_mac_asn_with_indexed_tokens():
    vault = SanitizeVault()
    out = vault.tokenize(TYPE2_LINE)
    for raw in ("aa:bb:cc:dd:ee:ff", "aa-bb-cc-dd-ee-fe", "aabb.ccdd.eeff",
                "10.1.1.10", "2001:db8::10", "65000"):
        assert raw not in out
    assert "<IP_1>" in out
    assert "<IP6_1>" in out
    assert "AS<ASN_1>" in out
    # Same MAC in colon and Cisco-dotted notation is one entity; the dash
    # MAC differs in its last octet, so it is a second entity.
    assert out.count("<MAC_1>") == 2
    assert "<MAC_2>" in out
    # Non-entity context survives.
    assert "leaf1" in out and "EVPN Type-2" in out and "VNI 10010" in out


def test_bgp_peers_get_distinct_stable_numbers():
    vault = SanitizeVault()
    out = vault.tokenize(
        "neighbor 10.0.0.1 remote-as 65001; neighbor 10.0.0.2 remote-as 65002; "
        "BGP peer 10.0.0.1 (External AS 65001) down; peer 10.0.0.2 AS65002 idle"
    )
    assert out == (
        "neighbor <IP_1> remote-as <ASN_1>; neighbor <IP_2> remote-as <ASN_2>; "
        "BGP peer <IP_1> (External AS <ASN_1>) down; peer <IP_2> AS<ASN_2> idle"
    )


def test_numbering_is_deterministic_per_vault():
    text = "peer 192.0.2.7 AS64512 then 192.0.2.9 AS64513"
    assert SanitizeVault().tokenize(text) == SanitizeVault().tokenize(text)
    vault = SanitizeVault()
    assert vault.tokenize(text) == vault.tokenize(text)


def test_prose_as_is_not_an_asn():
    out = SanitizeVault().tokenize("same as 3 peers, as 12 seconds ago")
    assert "<ASN_" not in out


def test_colon_mac_is_not_eaten_as_ipv6():
    out = SanitizeVault().tokenize("mac aa:bb:cc:dd:ee:ff only")
    assert out == "mac <MAC_1> only"


def test_prefix_length_is_kept_outside_the_token():
    vault = SanitizeVault()
    out = vault.tokenize("route 10.20.0.0/16 via 10.20.0.1")
    assert out == "route <IP_1>/16 via <IP_2>"
    assert vault.detokenize(out) == "route 10.20.0.0/16 via 10.20.0.1"


def test_hostnames_tokenized_only_when_given_and_longest_first():
    vault = SanitizeVault()
    out = vault.tokenize("leaf1 lost BFD to leaf10; spine1 ok", hosts=["leaf1", "leaf10"])
    assert out == "<HOST_1> lost BFD to <HOST_2>; spine1 ok"
    assert vault.detokenize(out) == "leaf1 lost BFD to leaf10; spine1 ok"


def test_detokenize_round_trip_and_unknown_tokens_left_visible():
    vault = SanitizeVault()
    text = "peer 10.0.0.1 AS65001 mac aa:bb:cc:dd:ee:ff on 2001:db8::1"
    tokens = vault.tokenize(text)
    assert vault.detokenize(tokens) == text
    answer = "Run `clear ip bgp <IP_1> soft` on AS<ASN_1>; ignore <IP_99>."
    assert vault.detokenize(answer) == "Run `clear ip bgp 10.0.0.1 soft` on AS65001; ignore <IP_99>."


def test_public_ip_pseudonym_from_sanitize_resolves_to_same_entity():
    masked, _ = sanitize("peer 8.8.8.8 down", mask_pii=True)
    assert "PUB-" in masked
    vault = SanitizeVault()
    out = vault.tokenize(masked + " and 8.8.8.8 again")
    assert out == "peer <IP_1> down and <IP_1> again"
    assert vault.detokenize("<IP_1>") == "8.8.8.8"


def test_vault_is_lru_bounded():
    vault = SanitizeVault(max_entries=3)
    vault.tokenize(" ".join(f"10.0.0.{i}" for i in range(1, 11)))
    assert len(vault) == 3
    # Oldest entries were evicted from the reverse map too…
    assert vault.detokenize("<IP_1>") == "<IP_1>"
    assert vault.detokenize("<IP_10>") == "10.0.0.10"
    # …and counters never rewind, so a re-seen entity gets a fresh token.
    assert vault.tokenize("10.0.0.1") == "<IP_11>"


def test_vault_entries_expire_after_ttl():
    now = [1000.0]
    vault = SanitizeVault(ttl_seconds=60, clock=lambda: now[0])
    vault.tokenize("10.0.0.1")
    now[0] += 61
    vault.tokenize("10.0.0.2")
    assert "10.0.0.1" not in vault.mapping
    assert vault.mapping["10.0.0.2"] == "<IP_2>"


def test_vault_mapping_snapshot():
    vault = SanitizeVault()
    vault.tokenize("peer 10.0.0.1 mac aa:bb:cc:dd:ee:ff")
    assert vault.mapping["10.0.0.1"] == "<IP_1>"
    assert vault.mapping["aa:bb:cc:dd:ee:ff"] == "<MAC_1>"


def test_prepare_log_samples_leaves_tokenization_to_the_gateway():
    # The gateway tokenizes the whole prompt with one vault so a peer gets the
    # same token in every section; pre-masking here would break that.
    text = prepare_log_samples([TYPE2_LINE])
    assert "10.1.1.10" in text


def test_module_anonymize_wrapper():
    out = anonymize("host 192.0.2.1 AS65001")
    assert "192.0.2.1" not in out
    assert "65001" not in out
