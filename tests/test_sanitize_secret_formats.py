"""Regression table: every common secret format must lose its secret in both
``sanitize()`` and the full LLM-gateway chain (sanitize, then the reversible
vault's tokenizer), stay idempotent, and never trigger catastrophic regex
backtracking on hostile input."""
from __future__ import annotations

import time

import pytest

from ai_log_analyzer.sanitize import sanitize
from ai_log_analyzer.sanitize_vault import SanitizeVault

pytestmark = pytest.mark.unit

# (id, config text, secret that must not survive)
FORMATS: list[tuple[str, str, str]] = [
    ("bgp-password-0", "neighbor 10.0.0.1 password 0 PlainBgp", "PlainBgp"),
    ("bgp-password-7", "neighbor 10.0.0.1 password 7 094F471A1A0A", "094F471A1A0A"),
    ("bgp-password-bare", "neighbor 10.0.0.1 password PlainBgpBare", "PlainBgpBare"),
    ("bgp-password-group", "neighbor SPINES password 0 GroupSecret1", "GroupSecret1"),
    ("enable-password", "enable password EnablePw123", "EnablePw123"),
    ("enable-password-0", "enable password 0 EnablePw0x", "EnablePw0x"),
    ("enable-secret-5", "enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0", "hx5rVt7rPNoS4wqbXKX7m0"),
    ("enable-secret-8", "enable secret 8 $8$dsYGNam3K1SIJO$7nv/35M/qr6t.dVc7UY9zrJDWRVqncHub1PE9UlMQFs",
     "7nv/35M/qr6t.dVc7UY9zrJDWRVqncHub1PE9UlMQFs"),
    ("enable-secret-9", "enable secret 9 $9$nhEmQVczB7dqsO$X.HsgL6x1il0RxkOSSvyQYwucySCt7qFm4v7pqCxkKM",
     "X.HsgL6x1il0RxkOSSvyQYwucySCt7qFm4v7pqCxkKM"),
    ("enable-secret-level", "enable secret level 5 0 LevelSecret9", "LevelSecret9"),
    ("username-secret-9", "username admin privilege 15 secret 9 $9$abcdefghijklmn$ZyXwVuTsRqPoNmLkJiHgFeDcBa",
     "ZyXwVuTsRqPoNmLkJiHgFeDcBa"),
    ("username-secret-0", "username bob secret 0 UserSecretPlain", "UserSecretPlain"),
    ("username-password-bare", "username bob password UserPwBare", "UserPwBare"),
    ("username-sha512", "username admin privilege 15 role network-admin secret sha512 $6$salt$HashHashHashHash99",
     "HashHashHashHash99"),
    ("line-vty-password", "line vty 0 4\n password LineVtyPw1\n login", "LineVtyPw1"),
    ("ospf-authentication-key", "ip ospf authentication-key OspfKey77", "OspfKey77"),
    ("ospf-authentication-key-7", "ip ospf authentication-key 7 0822455D0A16", "0822455D0A16"),
    ("ospf-message-digest", "ip ospf message-digest-key 1 md5 OspfMd5Secret", "OspfMd5Secret"),
    ("ospf-message-digest-7", "ip ospf message-digest-key 10 md5 7 104D000A0618", "104D000A0618"),
    ("ntp-authentication-key", "ntp authentication-key 1 md5 NtpSecretKey1", "NtpSecretKey1"),
    ("tacacs-key", "tacacs-server key TacacsKey1", "TacacsKey1"),
    ("tacacs-key-0", "tacacs-server key 0 TacacsKey0", "TacacsKey0"),
    ("tacacs-key-7", "tacacs-server key 7 02050D480809", "02050D480809"),
    ("tacacs-host-key-0", "tacacs-server host 10.1.1.1 key 0 TacHostKey0", "TacHostKey0"),
    ("radius-key", "radius-server key RadiusKey1", "RadiusKey1"),
    ("radius-host-key-0", "radius-server host 10.1.1.1 key 0 RadHostKey0", "RadHostKey0"),
    ("radius-host-ports-key", "radius-server host 10.1.1.1 auth-port 1812 acct-port 1813 key RadPortsKey",
     "RadPortsKey"),
    ("crypto-isakmp-key", "crypto isakmp key IsakmpSecret1 address 203.0.113.9", "IsakmpSecret1"),
    ("crypto-isakmp-key-6", "crypto isakmp key 6 IsakmpSecret6 address 203.0.113.9", "IsakmpSecret6"),
    ("ikev2-psk", "pre-shared-key remote 0 Ikev2SecretXyz", "Ikev2SecretXyz"),
    ("keyring-psk", "pre-shared-key address 203.0.113.9 key KeyringSecret1", "KeyringSecret1"),
    ("junos-psk-ascii", 'pre-shared-key ascii-text "JunosPskPlain1";', "JunosPskPlain1"),
    ("junos-psk-hex", "pre-shared-key hexadecimal 0123456789abcdef0123;", "0123456789abcdef0123"),
    ("junos-auth-key", 'authentication-key "JunosAuthKey1";', "JunosAuthKey1"),
    ("junos-auth-key-bare", "authentication-key JunosBareKey1;", "JunosBareKey1"),
    ("junos-plain-text-password", 'plain-text-password-value "JunosPlainPw1";', "JunosPlainPw1"),
    ("junos-md5-key", 'authentication md5 1 key "JunosMd5Key1";', "JunosMd5Key1"),
    ("junos-simple-password", 'simple-password "JunosSimplePw1";', "JunosSimplePw1"),
    ("snmp-host-v2c", "snmp-server host 10.9.9.9 version 2c SnmpHostComm1", "SnmpHostComm1"),
    ("snmp-host-traps", "snmp-server host 10.9.9.9 traps SnmpTrapComm1 bgp", "SnmpTrapComm1"),
    ("snmp-host-vrf-informs", "snmp-server host 10.9.9.9 vrf MGMT informs version 2c SnmpInformComm", "SnmpInformComm"),
    ("key-string", "key-string KeyStringPlain1", "KeyStringPlain1"),
    ("key-string-7", "key-string 7 0705203D5A53", "0705203D5A53"),
    ("authz-bearer", "Authorization: Bearer abc123DEFtokenValue987", "abc123DEFtokenValue987"),
    ("authz-basic", "Authorization: Basic dXNlcjpzdXBlcnNlY3JldHBhc3M=", "dXNlcjpzdXBlcnNlY3JldHBhc3M="),
    ("authz-json", '{"Authorization": "Bearer jsonTokenValue12345"}', "jsonTokenValue12345"),
    ("bearer-bare", "retry with Bearer eyAbCdEfGhIjKlMnOpQrStUv now", "eyAbCdEfGhIjKlMnOpQrStUv"),
    ("kv-api_key", "GET /v1/x?api_key=AbCdEf123456&limit=5", "AbCdEf123456"),
    ("kv-apikey", "apikey=ZzZzApiKeyValue1 user=bob", "ZzZzApiKeyValue1"),
    ("kv-token", "https://h.example.net/cb?token=TokenValue99&x=1", "TokenValue99"),
    ("kv-password", "login failed password=Hunter2Hunter2 for web", "Hunter2Hunter2"),
    ("kv-passwd", "mysql passwd=MysqlPasswd77 host=db", "MysqlPasswd77"),
    ("kv-secret", "secret=TopSecretValue1;", "TopSecretValue1"),
    ("kv-quoted-spaces", 'password="two words secret" rest', "two words secret"),
    ("kv-prefixed", "db_password=PrefixedPw12 x", "PrefixedPw12"),
    ("kv-json", '{"client_secret": "JsonClientSecret1", "a": 1}', "JsonClientSecret1"),
    ("url-userinfo", "git clone https://deploy:UrlPassw0rd@git.example.net/r.git", "UrlPassw0rd"),
    ("url-userinfo-redis", "redis://:RedisPw1234@10.0.0.5:6379/0", "RedisPw1234"),
    ("url-token-only", "https://ghTokenOnlyUserinfoValue1234@host.example.net/x", "ghTokenOnlyUserinfoValue1234"),
    ("aws-akia", "aws_access_key_id AKIAIOSFODNN7EXAMPLE used", "AKIAIOSFODNN7EXAMPLE"),
    ("aws-secret", "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI/K7MDENG"),
    ("github-pat", "token ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"),
    ("pem-pkcs8", "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkSecretPkcs8\n-----END PRIVATE KEY-----",
     "SecretPkcs8"),
    ("pem-rsa", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEASecretRsa\n-----END RSA PRIVATE KEY-----",
     "SecretRsa"),
    ("pem-openssh", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEASecretOpenssh\n"
     "-----END OPENSSH PRIVATE KEY-----", "SecretOpenssh"),
    ("pem-pgp", "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQdGBFSecretPgp\n-----END PGP PRIVATE KEY BLOCK-----",
     "SecretPgp"),
    ("pem-truncated", "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkSecretTruncated\nmore lines", "SecretTruncated"),
    ("bare-crypt-hash", "admin hash $6$rounds=5000$saltsalt$CryptHashBodyValue1234567890", "CryptHashBodyValue1234567890"),
    # Key id 7 is an id, not a type-7 marker: the md5/sha word must survive as the rule anchor.
    ("ospf-md5-id7", "ip ospf message-digest-key 7 md5 OspfId7Secret", "OspfId7Secret"),
    ("ospf-md5-id7-eos7", "ip ospf message-digest-key 7 md5 7 104D000A0618", "104D000A0618"),
    ("ospf-md5-id7-nxos3", "ip ospf message-digest-key 7 md5 3 NxosEncKey77", "NxosEncKey77"),
    ("ospf-md5-id7-xr-encrypted", "message-digest-key 7 md5 encrypted 0822455D0A16", "0822455D0A16"),
    ("ospf-md5-id7-xr-clear", "message-digest-key 7 md5 clear XrClearKey77", "XrClearKey77"),
    ("ospf-vlink-id7", "area 1 virtual-link 192.0.2.2 message-digest-key 7 md5 VlinkSecret7", "VlinkSecret7"),
    ("ospf-sha256-id7-eos", "ip ospf message-digest-key 7 sha256 7 060506324F41", "060506324F41"),
    ("ntp-key-id7", "ntp authentication-key 7 md5 NtpId7Secret", "NtpId7Secret"),
    ("ntp-key-id7-ios-type", "ntp authentication-key 7 md5 NtpId7IosKey 7", "NtpId7IosKey"),
    ("ntp-key-id7-eos-type", "ntp authentication-key 7 md5 7 060506324F41", "060506324F41"),
    ("ntp-key-id7-xr", "ntp authentication-key 7 md5 encrypted 0822455D0A16", "0822455D0A16"),
    ("ntp-key-id7-sha1", "ntp authentication-key 7 sha1 NtpId7Sha1", "NtpId7Sha1"),
    ("ntp-key-id7-sha256", "ntp authentication-key 7 sha256 NtpId7Sha256", "NtpId7Sha256"),
    ("ntp-key-id7-hmac", "ntp authentication-key 7 hmac-sha2-256 NtpId7Hmac", "NtpId7Hmac"),
    # NTP keys with the type before the key (EOS, Aruba) or other algorithm names (IOS-XE).
    ("ntp-key-eos-type7", "ntp authentication-key 1 md5 7 06120A3258", "06120A3258"),
    ("ntp-key-aoscx-ciphertext", "ntp authentication-key 1 sha1 ciphertext AQBapXyzNtpAosCx", "AQBapXyzNtpAosCx"),
    ("ntp-key-aoscx-plaintext", "ntp authentication-key 1 md5 plaintext NtpAosPlain1", "NtpAosPlain1"),
    ("ntp-key-ios-hmac-type", "ntp authentication-key 1 hmac-sha2-256 MyNtpHmacKey 7", "MyNtpHmacKey"),
    ("ntp-key-ios-hmac-sha1", "ntp authentication-key 1 hmac-sha1 NtpHmacSha1Key", "NtpHmacSha1Key"),
    # A secret rule must never reach into the next line and eat the keyword that anchors another rule.
    ("keychain-id7-key-string", "key chain K\n key 7\n  key-string KeyChainSecret7\n", "KeyChainSecret7"),
    ("key7-eol-then-username", "x key 7\nusername bob password Hunter2Pw9", "Hunter2Pw9"),
    ("snmp-community-eol-then-host", "snmp-server community\nsnmp-server host 192.0.2.9 version 2c HostCommLeak1",
     "HostCommLeak1"),
    ("snmpv3-auth-eol-then-username", "snmp-server user u g v3 auth sha\nusername bob password Hunter2Pw9",
     "Hunter2Pw9"),
    ("junos-snmpv3-eol-then-username", "authentication-password\nusername bob password Hunter2Pw9", "Hunter2Pw9"),
    # Wireless PSKs.
    ("wpa-psk-ascii0", "security wpa psk set-key ascii 0 MyWifiPSK2024x", "MyWifiPSK2024x"),
    ("wpa-psk-hex0", "security wpa psk set-key hex 0 " + "0123456789abcdef" * 4, "0123456789abcdef0123456789abcdef"),
    ("wpa-psk-aireos", "config wlan security wpa akm psk set-key ascii 1 AireosPskKeyX 3", "AireosPskKeyX"),
    ("wpa-psk-autonomous-ap", "wpa-psk ascii 7 0822455D0A16", "0822455D0A16"),
    # Nokia SR Linux.
    ("srl-secret-key-quoted", 'secret-key "SrlQuotedSecretX"', "SrlQuotedSecretX"),
    ("srl-secret-key-bare", "secret-key SrlBareSecretX", "SrlBareSecretX"),
    ("srl-secret-key-aes1", "secret-key $aes1$AQDsrlBlobPart0123456789=$SrlSecondPart0123456789AbCd==",
     "SrlSecondPart0123456789AbCd"),
    ("srl-aaa-set", 'set / system aaa server-group G server 192.0.2.1 tacacs secret-key "SrlSetFormSecretX"',
     "SrlSetFormSecretX"),
    ("srl-community-entry-block", "community-entry E1 {\n    community SrlCommBlockX\n}", "SrlCommBlockX"),
    ("srl-community-entry-set", 'set / system snmp access-group G community-entry E1 community "SrlCommSetX"',
     "SrlCommSetX"),
    ("aes1-hash-anywhere", "value $aes1$AQDhashPart0123456789=$HashSecondPartAbCd0123456789==",
     "HashSecondPartAbCd0123456789"),
    ("aes-hash-anywhere", "value $aes$HashAesPlainPart0123456789", "HashAesPlainPart0123456789"),
    # IKEv2 keyring / ASA / DMVPN.
    ("psk-bare", "pre-shared-key BareIkePskX1", "BareIkePskX1"),
    ("psk-type6", "pre-shared-key 6 AesTypeSixBlobX1", "AesTypeSixBlobX1"),
    ("psk-asa-ikev1", "ikev1 pre-shared-key AsaIkev1PskX", "AsaIkev1PskX"),
    ("psk-asa-ikev2", "ikev2 remote-authentication pre-shared-key AsaIkev2PskX", "AsaIkev2PskX"),
    ("nhrp-authentication", "ip nhrp authentication NhrpKey1", "NhrpKey1"),
    # Colon-separated credentials and more credential names.
    ("colon-password", "password: ColonPasswordX1", "ColonPasswordX1"),
    ("colon-api_key", "api_key: ColonApiKeyX1", "ColonApiKeyX1"),
    ("hdr-x-api-key", "X-API-Key: HdrApiKeyValueX1", "HdrApiKeyValueX1"),
    ("hdr-x-auth-token", "x-auth-token: HdrAuthTokenX1", "HdrAuthTokenX1"),
    ("colon-token", "token: ColonTokenValueX1", "ColonTokenValueX1"),
    ("yaml-password-quoted", "  password: 'two words yaml' # note", "two words yaml"),
    ("kv-snmp_community", "snmp_community=EqSnmpCommX1", "EqSnmpCommX1"),
    ("kv-passkey", "passkey=EqPasskeyValX1", "EqPasskeyValX1"),
    ("kv-psk", "psk=EqPskValueX1 ssid=corp", "EqPskValueX1"),
    ("kv-pwd", "Server=db;Pwd=OdbcPwdValueX1;", "OdbcPwdValueX1"),
    # PAN-OS set-CLI and XML.
    ("panos-radius-secret-blob",
     "set shared server-profile radius R1 server S1 secret -AQ==ExampleBlobRadius0123456789abcdefg=",
     "ExampleBlobRadius0123456789abcdefg"),
    ("panos-ldap-bind-blob",
     "set shared server-profile ldap L1 server S1 bind-password -AQ==ExampleBlobLdap0123456789abcdefgh=",
     "ExampleBlobLdap0123456789abcdefgh"),
    ("panos-ike-psk-blob",
     "set network ike gateway GW1 authentication pre-shared-key key -AQ==ExampleBlobIke0123456789abcdefghij=",
     "ExampleBlobIke0123456789abcdefghij"),
    ("panos-snmp-community", "set deviceconfig system snmp-setting access-setting version v2c "
     "snmp-community-string PanSnmpCommX1", "PanSnmpCommX1"),
    ("panos-clear-secret", "set shared server-profile radius R1 server S1 secret PanClearSecretX1",
     "PanClearSecretX1"),
    ("panos-xml-secret", "<secret>-AQ==ExampleBlobXmlSecret0123456789abc=</secret>", "ExampleBlobXmlSecret0123456789abc"),
    ("panos-xml-bind-password", "<bind-password>PanXmlBindPwX1</bind-password>", "PanXmlBindPwX1"),
    ("panos-xml-psk", "<pre-shared-key><key>-AQ==ExampleBlobXmlPsk0123456789abcd=</key></pre-shared-key>",
     "ExampleBlobXmlPsk0123456789abcd"),
    ("panos-xml-snmp-community", "<snmp-community-string>PanXmlCommX1</snmp-community-string>", "PanXmlCommX1"),
    ("panos-blob-bare", "value -AQ==BareBlobExample0123456789abcdefghij= here", "BareBlobExample0123456789abcdefghij"),
    # FortiOS `set <field> ENC <blob>` and clear text.
    ("forti-password-enc", "    set password ENC SH2FortiAdminBlobExampleOnly0123456789==",
     "FortiAdminBlobExampleOnly0123456789"),
    ("forti-psksecret-enc", "        set psksecret ENC FortiPskBlobExampleOnly0123456789abcd==",
     "FortiPskBlobExampleOnly0123456789abcd"),
    ("forti-secret-enc", "set secret ENC FortiRadiusBlobExample0123456789==", "FortiRadiusBlobExample0123456789"),
    ("forti-key-enc", "set key ENC FortiKeyBlobExampleOnly0123456789==", "FortiKeyBlobExampleOnly0123456789"),
    ("forti-auth-pwd-enc", "set auth-pwd ENC FortiAuthPwdBlobEx0123456789==", "FortiAuthPwdBlobEx0123456789"),
    ("forti-priv-pwd-enc", "set priv-pwd ENC FortiPrivPwdBlobEx0123456789==", "FortiPrivPwdBlobEx0123456789"),
    ("forti-ospf-key-enc", "set authentication-key ENC FortiOspfBlobExample0123456789==",
     "FortiOspfBlobExample0123456789"),
    ("forti-password-clear", "set password FortiClearPwX1", "FortiClearPwX1"),
]


def _gateway(text: str) -> str:
    """What llm.query() sends to a provider: sanitize (PII on), then tokenize."""
    safe, _ = sanitize(text, mask_pii=True, mask_public_ip=False)
    return SanitizeVault().tokenize(safe)


@pytest.mark.parametrize("fid,text,secret", FORMATS, ids=[f[0] for f in FORMATS])
def test_secret_removed_by_sanitize(fid, text, secret):
    out, n = sanitize(text)
    assert secret not in out, out
    assert n >= 1


@pytest.mark.parametrize("fid,text,secret", FORMATS, ids=[f[0] for f in FORMATS])
def test_secret_removed_by_gateway_chain(fid, text, secret):
    assert secret not in _gateway(text)


@pytest.mark.parametrize("fid,text,secret", FORMATS, ids=[f[0] for f in FORMATS])
def test_sanitize_is_idempotent(fid, text, secret):
    once, _ = sanitize(text, mask_pii=True)
    twice, n2 = sanitize(once, mask_pii=True)
    assert twice == once
    # Already-redacted placeholders must not be counted as fresh redactions.
    assert n2 == 0, (once, n2)


def test_typed_password_keeps_the_type_digit():
    out, _ = sanitize("neighbor 10.0.0.1 password 0 PlainBgp")
    assert out == "neighbor 10.0.0.1 password 0 <REDACTED>"
    out, _ = sanitize("tacacs-server key 7 02050D480809")
    assert out == "tacacs-server key 7 <REDACTED>"


def test_structure_around_secrets_is_preserved():
    cfg = "ip ospf authentication-key OspfKey77\n ip ospf cost 10\ninterface Gi0/1\n"
    out, _ = sanitize(cfg)
    assert "ip ospf cost 10" in out and "interface Gi0/1" in out
    out, _ = sanitize("Authorization: Bearer tok123456789012\nHost: example.net")
    assert "Host: example.net" in out


@pytest.mark.parametrize("benign", [
    "Failed password for invalid user admin from 192.0.2.7 port 22 ssh2",
    "password authentication failed for user postgres",
    "Password policy: minimum length 12",
    "line vty 0 4\n password-encryption service enabled",
    "enable secret level not set",
    "key chain KC1\n key 1\n  key-string\n",
    "interface Ethernet1\n description tokenized-uplink to AS65001",
    "neighbor 10.0.0.1 remote-as 65001\n neighbor 10.0.0.1 description pw-peer",
    "ssh://git@git.example.net/repo.git",
    "the secret-manager token expired at 10:00",
    "BGP session reset: authentication failure",
])
def test_benign_text_untouched(benign):
    out, n = sanitize(benign)
    assert out == benign and n == 0


# ── ReDoS: hostile 64 KB single lines must stay fast ────────────────────────

_HOSTILE = {
    "spaces": "password" + " " * 70_000,
    "digits": "password 0 " + "0" * 70_000,
    "repeat-password": "password " * 8_000,
    "repeat-neighbor": "neighbor 10.0.0.1 password " * 2_600,
    "repeat-username": "username a " * 6_000,
    "repeat-pem": "-----BEGIN RSA PRIVATE KEY-----" * 2_100,
    "repeat-cert": "-----BEGIN CERTIFICATE-----" * 2_400,
    "repeat-url": "http://a:" * 7_000,
    "repeat-userinfo": "https://" + "u" * 100 + ":" + "p" * 60_000,
    "repeat-auth": "Authorization: Bearer " * 3_000,
    "repeat-kv": "password=" * 8_000,
    "repeat-kv-quote": 'password="' * 6_000,
    "repeat-snmp": "snmp-server host 1.1.1.1 version " * 2_000,
    "repeat-ntp": "ntp authentication-key 1 md5 " * 2_200,
    "tabs": "enable password\t" * 4_000,
    "dollar": "$1$" * 20_000,
    "ssh": "ssh-rsa " * 8_000,
    "quote": '"' * 65_000,
    "crypto": "crypto isakmp key " * 3_600,
    "radius": "radius-server host x " * 3_000,
    "semi-set": ";set " * 13_000,
    "desc": ";set a " * 9_000,
    "mixed": ("password 0 " + "x" * 50 + " neighbor 1.1.1.1 password ") * 800,
    "token-eq": "token = " * 8_000,
    "ws-eq": "password" + " " * 30_000 + "=" * 30_000,
}


@pytest.mark.parametrize("name", sorted(_HOSTILE))
def test_hostile_64kb_line_is_fast(name):
    text = _HOSTILE[name][:65_536]
    start = time.perf_counter()
    sanitize(text, mask_pii=True)
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, f"{name}: {elapsed:.2f}s"
