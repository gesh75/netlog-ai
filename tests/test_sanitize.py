"""Tests for the config sanitizer — must strip secrets but preserve structure."""
import pytest

from ai_log_analyzer.sanitize import sanitize, sanitize_report


@pytest.mark.unit
def test_junos_encrypted_password_redacted():
    cfg = 'set system root-authentication encrypted-password "$6$abcDEF/.xyz123"'
    out, n = sanitize(cfg)
    assert "$6$" not in out
    assert "<REDACTED>" in out
    assert n >= 1


@pytest.mark.unit
def test_junos_pre_shared_key_redacted():
    cfg = 'pre-shared-key "$9$super_secret_psk_value"'
    out, _ = sanitize(cfg)
    assert "super_secret_psk_value" not in out


@pytest.mark.unit
def test_junos_authentication_key_redacted():
    cfg = 'authentication-key "myMD5SecretKey"'
    out, _ = sanitize(cfg)
    assert "myMD5SecretKey" not in out


@pytest.mark.unit
def test_eos_secret_7_redacted():
    cfg = "username admin secret 7 0822455D0A16"
    out, _ = sanitize(cfg)
    assert "0822455D0A16" not in out
    assert "<REDACTED>" in out


@pytest.mark.unit
def test_eos_snmp_community_redacted():
    cfg = "snmp-server community myCompanySecretCommunity ro"
    out, _ = sanitize(cfg)
    assert "myCompanySecretCommunity" not in out


@pytest.mark.unit
def test_eos_bgp_neighbor_password_redacted():
    cfg = "neighbor 10.0.0.1 password 7 1234abcd"
    out, _ = sanitize(cfg)
    assert "1234abcd" not in out


@pytest.mark.unit
def test_eos_radius_key_redacted():
    cfg = "radius-server host 10.1.1.1 key 7 supersecretRadiusKey"
    out, _ = sanitize(cfg)
    assert "supersecretRadiusKey" not in out


@pytest.mark.unit
def test_ssh_host_key_redacted():
    cfg = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDx" + "X" * 200
    out, _ = sanitize(cfg)
    assert "AAAAB3NzaC1yc2EAAAADAQAB" not in out
    assert "<REDACTED-SSH-KEY>" in out


@pytest.mark.unit
def test_private_key_block_redacted():
    cfg = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEAxYz...secretmaterial...\n"
        "-----END RSA PRIVATE KEY-----"
    )
    out, _ = sanitize(cfg)
    assert "secretmaterial" not in out
    assert "<REDACTED-PRIVATE-KEY>" in out


@pytest.mark.unit
def test_bgp_community_names_preserved():
    """BGP community NAMES (Junos policy-options) are labels, not secrets."""
    cfg = "    community MATCH_LUMEN_AMS1_GEOTAG members 3356:2067;"
    out, _ = sanitize(cfg)
    assert "MATCH_LUMEN_AMS1_GEOTAG" in out
    assert "3356:2067" in out


@pytest.mark.unit
def test_snmp_community_block_redacted():
    """Junos SNMP community block — community NAME followed by `authorization`."""
    cfg = """
    snmp {
        community myReadOnlyCommunity {
            authorization read-only;
        }
    }
    """
    out, _ = sanitize(cfg)
    assert "myReadOnlyCommunity" not in out


@pytest.mark.unit
def test_certificate_block_redacted():
    cfg = (
        "-----BEGIN CERTIFICATE-----\n"
        "MIIDXTCCAkWg...realcertdata...\n"
        "-----END CERTIFICATE-----"
    )
    out, _ = sanitize(cfg)
    assert "realcertdata" not in out


@pytest.mark.unit
def test_sanitize_report_structure():
    cfg = (
        'encrypted-password "$6$abc"\n'
        'snmp-server community public ro\n'
        'neighbor 10.0.0.1 password 7 abcd1234\n'
    )
    rpt = sanitize_report(cfg)
    assert "sanitized" in rpt
    assert "total" in rpt and rpt["total"] >= 3
    assert "by_rule" in rpt and isinstance(rpt["by_rule"], dict)


@pytest.mark.unit
def test_clean_config_yields_zero_redactions():
    cfg = "interface ge-0/0/0\n  description uplink\n  mtu 9000\n"
    out, n = sanitize(cfg)
    assert n == 0
    assert out == cfg


# ── PII masking (opt-in) ─────────────────────────────────────────────────────

@pytest.mark.unit
def test_pii_off_by_default_preserves_usernames():
    cfg = 'user georgi.gaydarov {\n  uid 2001;\n  class super-user;\n}'
    out, _ = sanitize(cfg)
    assert "georgi.gaydarov" in out  # PII off by default


@pytest.mark.unit
def test_pii_on_masks_junos_usernames():
    cfg = 'user georgi.gaydarov {\n  uid 2001;\n  class super-user;\n}'
    out, _ = sanitize(cfg, mask_pii=True)
    assert "georgi.gaydarov" not in out
    # Hashed token starts with "user-" followed by 8 hex chars
    import re as _re
    assert _re.search(r"user-[0-9a-f]{8}", out)
    # Structural info preserved
    assert "class super-user" in out


@pytest.mark.unit
def test_pii_on_masks_eos_usernames():
    cfg = "username adminbob privilege 15 secret 7 abc"
    out, _ = sanitize(cfg, mask_pii=True)
    assert "adminbob" not in out
    import re as _re
    assert _re.search(r"user-[0-9a-f]{8}", out)


@pytest.mark.unit
def test_pii_same_username_same_hash():
    """Same username appearing twice should map to the same hash."""
    cfg = "username alice privilege 15\nusername alice secret 7 xyz\n"
    out, _ = sanitize(cfg, mask_pii=True)
    import re as _re
    tokens = _re.findall(r"user-([0-9a-f]{8})", out)
    assert len(tokens) == 2 and tokens[0] == tokens[1]


@pytest.mark.unit
def test_pii_on_masks_junos_full_name():
    cfg = '  full-name "Jane Smith";'
    out, _ = sanitize(cfg, mask_pii=True)
    assert "Jane Smith" not in out
    assert "<REDACTED-NAME>" in out


@pytest.mark.unit
def test_pii_on_keeps_private_ipv4():
    cfg = "set interfaces ge-0/0/0 family inet address 10.1.1.1/24\n"
    out, _ = sanitize(cfg, mask_pii=True)
    assert "10.1.1.1" in out  # RFC1918 stays


@pytest.mark.unit
def test_pii_on_keeps_loopback_ipv4():
    cfg = "logging host 127.0.0.1\n"
    out, _ = sanitize(cfg, mask_pii=True)
    assert "127.0.0.1" in out


@pytest.mark.unit
def test_pii_on_masks_public_ipv4_consistently():
    cfg = "neighbor 8.8.8.8 remote-as 65000\nrouter-id 8.8.8.8\n"
    out, _ = sanitize(cfg, mask_pii=True)
    assert "8.8.8.8" not in out
    # Same IP → same token
    tokens = [line for line in out.splitlines() if "PUB-" in line]
    assert len(tokens) == 2
    a = tokens[0].split("PUB-")[1].split()[0]
    b = tokens[1].split("PUB-")[1].split()[0]
    assert a == b


@pytest.mark.unit
def test_sanitize_many_shares_ip_mapping_across_files():
    """Two files referencing the same public IP must map to the same token."""
    from ai_log_analyzer.sanitize import sanitize_many
    files = {
        "fw-01.txt": "neighbor 8.8.8.8 remote-as 100\n",
        "fw-02.txt": "neighbor 8.8.8.8 remote-as 100\n",
    }
    out = sanitize_many(files, mask_pii=True)
    a = out["fw-01.txt"]["sanitized"]
    b = out["fw-02.txt"]["sanitized"]
    assert "8.8.8.8" not in a and "8.8.8.8" not in b
    # Extract token from each
    import re
    ta = re.search(r"PUB-([0-9a-f]+)", a).group(1)
    tb = re.search(r"PUB-([0-9a-f]+)", b).group(1)
    assert ta == tb


@pytest.mark.unit
def test_sanitize_many_redacts_secrets_in_each_file():
    from ai_log_analyzer.sanitize import sanitize_many
    files = {
        "fw-01.txt": 'encrypted-password "$6$abc"\n',
        "fw-02.txt": 'pre-shared-key "$9$xyz"\n',
    }
    out = sanitize_many(files, mask_pii=True)
    assert "$6$" not in out["fw-01.txt"]["sanitized"]
    assert "$9$" not in out["fw-02.txt"]["sanitized"]
