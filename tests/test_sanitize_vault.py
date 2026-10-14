"""SanitizeVault: IPv4 / IPv6 / MAC / ASN masking before llm.py."""
from __future__ import annotations

import pytest

from ai_log_analyzer.llm import prepare_log_samples
from ai_log_analyzer.sanitize_vault import SanitizeVault, anonymize

TYPE2_LINE = (
    "Oct 13 10:00:01 leaf1 bgpd: EVPN Type-2 MAC/IP aa:bb:cc:dd:ee:ff "
    "10.1.1.10 2001:db8::10 VNI 10010 withdraw AS65000 "
    "cisco aabb.ccdd.eeff dash aa-bb-cc-dd-ee-ff"
)


@pytest.mark.unit
def test_anonymize_masks_ipv4_ipv6_mac_asn():
    vault = SanitizeVault()
    out = vault.anonymize(TYPE2_LINE)
    assert "aa:bb:cc:dd:ee:ff" not in out
    assert "aa-bb-cc-dd-ee-ff" not in out
    assert "aabb.ccdd.eeff" not in out
    assert "10.1.1.10" not in out
    assert "2001:db8::10" not in out
    assert "AS65000" not in out
    assert "<MAC>" in out
    assert "<IPV4>" in out
    assert "<IPV6>" in out
    assert "<ASN>" in out
    assert "leaf1" in out
    assert "EVPN Type-2" in out


@pytest.mark.unit
def test_vault_is_stable_within_instance():
    vault = SanitizeVault()
    a = vault.anonymize("peer 10.0.0.1 mac aa:bb:cc:dd:ee:ff")
    b = vault.anonymize("peer 10.0.0.1 mac aa:bb:cc:dd:ee:ff")
    assert a == b
    assert "10.0.0.1" in vault.mapping
    assert vault.mapping["10.0.0.1"] == "<IPV4>"


@pytest.mark.unit
def test_colon_mac_is_not_eaten_as_ipv6():
    vault = SanitizeVault()
    out = vault.anonymize("mac aa:bb:cc:dd:ee:ff only")
    assert out.count("<MAC>") == 1
    assert "<IPV6>" not in out


@pytest.mark.unit
def test_prepare_log_samples_runs_vault():
    text = prepare_log_samples([TYPE2_LINE])
    assert "aa:bb:cc:dd:ee:ff" not in text
    assert "10.1.1.10" not in text
    assert "2001:db8::10" not in text
    assert "<MAC>" in text
    assert "<IPV4>" in text


@pytest.mark.unit
def test_module_anonymize_wrapper():
    out = anonymize("host 192.0.2.1 AS65001")
    assert "192.0.2.1" not in out
    assert "AS65001" not in out
