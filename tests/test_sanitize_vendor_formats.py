"""Vendor-syntax sanitizer rules: the secret goes, the keyword / type / structure stays, benign text and
neighbouring lines are untouched, and no rule backtracks badly on hostile input. The remove-the-secret
table lives in test_sanitize_secret_formats.py; these tests pin the exact output shape."""
from __future__ import annotations

import pytest

from ai_log_analyzer.sanitize import sanitize

pytestmark = pytest.mark.unit

R = "<REDACTED>"

# (input, expected sanitize() output): the secret token is replaced, everything else is kept.
EXACT: list[tuple[str, str]] = [
    # Key id 7 is an id, not a type-7 marker: the algorithm word stays.
    ("ip ospf message-digest-key 7 md5 K", f"ip ospf message-digest-key 7 md5 {R}"),
    ("ip ospf message-digest-key 7 md5 7 104D000A0618", f"ip ospf message-digest-key 7 md5 7 {R}"),
    ("ip ospf message-digest-key 7 md5 3 NxosEncKey77", f"ip ospf message-digest-key 7 md5 3 {R}"),
    ("message-digest-key 7 md5 encrypted 0822455D0A16", f"message-digest-key 7 md5 encrypted {R}"),
    ("message-digest-key 7 md5 clear XrClearKey77", f"message-digest-key 7 md5 clear {R}"),
    ("area 1 virtual-link 192.0.2.2 message-digest-key 7 md5 K", f"area 1 virtual-link 192.0.2.2 message-digest-key 7 md5 {R}"),
    ("ip ospf message-digest-key 7 sha256 7 060506324F41", f"ip ospf message-digest-key 7 sha256 7 {R}"),
    ("ntp authentication-key 7 md5 K", f"ntp authentication-key 7 md5 {R}"),
    ("ntp authentication-key 7 md5 K 7", f"ntp authentication-key 7 md5 {R} 7"),
    ("ntp authentication-key 7 md5 7 060506324F41", f"ntp authentication-key 7 md5 7 {R}"),
    ("ntp authentication-key 7 md5 encrypted 0822455D0A16", f"ntp authentication-key 7 md5 encrypted {R}"),
    ("ntp authentication-key 7 sha1 K", f"ntp authentication-key 7 sha1 {R}"),
    ("ntp authentication-key 7 sha256 K", f"ntp authentication-key 7 sha256 {R}"),
    ("ip ospf authentication-key 7 0822455D0A16", f"ip ospf authentication-key 7 {R}"),
    ("tacacs-server key 7 02050D480809", f"tacacs-server key 7 {R}"),
    # NTP keys with the type before the key (EOS / Aruba) or other algorithm names (IOS-XE).
    ("ntp authentication-key 1 md5 7 06120A3258", f"ntp authentication-key 1 md5 7 {R}"),
    ("ntp authentication-key 1 sha1 ciphertext AQB123", f"ntp authentication-key 1 sha1 ciphertext {R}"),
    ("ntp authentication-key 1 hmac-sha2-256 MyKey 7", f"ntp authentication-key 1 hmac-sha2-256 {R} 7"),
    ("ntp authentication-key 1 md5 MyKey", f"ntp authentication-key 1 md5 {R}"),
    # A secret rule never reaches into the next line.
    ("key chain K\n key 7\n  key-string MySecretKey\n", f"key chain K\n key 7\n  key-string {R}\n"),
    ("x key 7\nusername bob password Hunter2Pw9", f"x key 7\nusername bob password {R}"),
    # Wireless PSKs keep the type digit.
    ("security wpa psk set-key ascii 0 MyWifiPSK2024!", f"security wpa psk set-key ascii 0 {R}"),
    ("security wpa psk set-key hex 0 0123456789abcdef", f"security wpa psk set-key hex 0 {R}"),
    ("config wlan security wpa akm psk set-key ascii 1 MyWifiPSK 3", f"config wlan security wpa akm psk set-key ascii 1 {R} 3"),
    ("psk=MyWifiPSK&x=1", f"psk={R}&x=1"),
    # Nokia SR Linux.
    ('secret-key "X1y2Z3"', f"secret-key {R}"),
    ("secret-key X1y2Z3", f"secret-key {R}"),
    ("secret-key $aes1$AQDabcdef0123456789=$GhIjKlMnOp0123456789==", f"secret-key {R}"),
    ('set / system aaa server-group G server 192.0.2.1 tacacs secret-key "X1y2Z3"',
     f"set / system aaa server-group G server 192.0.2.1 tacacs secret-key {R}"),
    ("community-entry E1 {\n    community X1y2Z3\n}", f"community-entry E1 {{\n    community {R}\n}}"),
    ('set / system snmp access-group G community-entry E1 community "X1y2Z3"',
     f"set / system snmp access-group G community-entry E1 community {R}"),
    ("hash $aes1$AQDabcdef0123456789=$GhIjKlMnOp0123456789== end", "hash <REDACTED-HASH> end"),
    # IKEv2 / ASA / DMVPN.
    ("pre-shared-key MyVpnSecret", f"pre-shared-key {R}"),
    ("pre-shared-key 6 AesBlobX1", f"pre-shared-key 6 {R}"),
    ("ikev1 pre-shared-key X1y2Z3", f"ikev1 pre-shared-key {R}"),
    ("pre-shared-key local 0 X1y2Z3", f"pre-shared-key local 0 {R}"),
    ("pre-shared-key address 192.0.2.9 key X1y2Z3", f"pre-shared-key address 192.0.2.9 key {R}"),
    ('pre-shared-key ascii-text "X1y2Z3";', f'pre-shared-key ascii-text "{R}";'),
    ("pre-shared-key hexadecimal 0123456789abcdef0123;", f'pre-shared-key hexadecimal "{R}";'),
    ("ip nhrp authentication NhrpKey1", f"ip nhrp authentication {R}"),
    # Colon-separated credentials.
    ("password: X1y2Z3", f"password: {R}"),
    ("X-API-Key: X1y2Z3\nHost: example.net", f"X-API-Key: {R}\nHost: example.net"),
    ("x-auth-token: X1y2Z3", f"x-auth-token: {R}"),
    ("snmp_community=X1y2Z3", f"snmp_community={R}"),
    # PAN-OS.
    ("set shared server-profile radius R1 server S1 secret -AQ==ExampleBlob0123456789=",
     f"set shared server-profile radius R1 server S1 secret {R}"),
    ("set network ike gateway GW1 authentication pre-shared-key key -AQ==ExampleBlob0123456789=",
     f"set network ike gateway GW1 authentication pre-shared-key key {R}"),
    ("set deviceconfig system snmp-setting access-setting version v2c snmp-community-string X1y2Z3",
     f"set deviceconfig system snmp-setting access-setting version v2c snmp-community-string {R}"),
    ("<secret>-AQ==ExampleBlob0123456789=</secret>", f"<secret>{R}</secret>"),
    ("<bind-password>X1y2Z3</bind-password>", f"<bind-password>{R}</bind-password>"),
    ("<pre-shared-key><key>-AQ==ExampleBlob0123456789=</key></pre-shared-key>",
     f"<pre-shared-key><key>{R}</key></pre-shared-key>"),
    ("<snmp-community-string>X1y2Z3</snmp-community-string>",
     f"<snmp-community-string>{R}</snmp-community-string>"),
    # FortiOS keeps the field name and the ENC marker.
    ("    set password ENC SH2ExampleBlob0123456789==", f"    set password ENC {R}"),
    ("set psksecret ENC ExampleBlob0123456789==", f"set psksecret ENC {R}"),
    ("set authentication-key ENC ExampleBlob0123456789==", f"set authentication-key ENC {R}"),
    ("set password MyClearPass", f"set password {R}"),
    # NX-OS SNMPv3 localized keys.
    ("snmp-server user admin network-admin auth md5 0xA priv 0xB localizedkey",
     f"snmp-server user admin network-admin auth md5 {R} priv {R} localizedkey"),
    ("snmp-server user admin network-admin auth sha 0xA priv aes-128 0xB localizedkey",
     f"snmp-server user admin network-admin auth sha {R} priv aes-128 {R} localizedkey"),
    ("snmp-server user admin network-admin auth sha-256 0xA priv aes-256 0xB localizedV2key",
     f"snmp-server user admin network-admin auth sha-256 {R} priv aes-256 {R} localizedV2key"),
    ("snmp-server user u g v3 auth sha AuthPw1 priv aes 128 PrivPw1",
     f"snmp-server user u g v3 auth sha {R} priv aes 128 {R}"),
    # AAA shared secrets in block and vendor syntax keep the type digit.
    ("radius server RAD1\n address ipv4 192.0.2.1\n key 0 R4diusSecret\n",
     f"radius server RAD1\n address ipv4 192.0.2.1\n key 0 {R}\n"),
    ("tacacs server TAC1\n key TacSecret1\n", f"tacacs server TAC1\n key {R}\n"),
    ("tacacs server TAC1\n key 6 AesBlob1\n", f"tacacs server TAC1\n key 6 {R}\n"),
    ("aaa group server radius G1\n server-private 192.0.2.1 key Sp1\n",
     f"aaa group server radius G1\n server-private 192.0.2.1 key {R}\n"),
    ("isis authentication key 0 X1y2Z3", f"isis authentication key 0 {R}"),
    ("shared-key 0 X1y2Z3", f"shared-key 0 {R}"),
    ("nv set system aaa tacacs server 1 secret X1y2Z3", f"nv set system aaa tacacs server 1 secret {R}"),
    ("tacacs passkey X1y2Z3", f"tacacs passkey {R}"),
    # SNMP communities.
    ("set snmp community X1y2Z3 authorization read-only", f"set snmp community {R} authorization read-only"),
    ("set snmp community X1y2Z3 clients 192.0.2.0/24", f"set snmp community {R} clients 192.0.2.0/24"),
    ("community X1y2Z3;", f"community {R};"),
    ("community X1y2Z3 {\n view all;\n authorization read-only;\n}",
     f"community {R}{{\n view all;\n authorization read-only;\n}}"),
    ("snmp {\n    community X1y2Z3;\n    community Y1y2Z3 {\n        authorization read-only;\n    }\n}",
     f"snmp {{\n    community {R};\n    community {R}{{\n        authorization read-only;\n    }}\n}}"),
    ("snmp\n community X1y2Z3\n  authorization read-only", f"snmp\n community {R}\n  authorization read-only"),
    ("nv set service snmp-server readonly-community X1y2Z3 access any",
     f"nv set service snmp-server readonly-community {R} access any"),
    ("rocommunity X1y2Z3 default", f"rocommunity {R} default"),
    ("config snmp community add X1y2Z3 RO", f"config snmp community add {R} RO"),
]


@pytest.mark.parametrize("text,expected", EXACT, ids=[f"{i:02d}" for i in range(len(EXACT))])
def test_secret_replaced_and_structure_kept(text, expected):
    out, n = sanitize(text)
    assert out == expected
    assert n >= 1
    # Fixed point: a second run changes nothing and counts nothing.
    assert sanitize(out) == (out, 0)


# Text that merely resembles a secret statement must pass through byte for byte.
BENIGN = [
    # key ids and key-chain structure
    "key chain KC1\n key 1\n  key-string\n",
    "key chain KC1\n key 7\n  key-string\n",
    "key chain KC1\n key 12345\n",
    "no ip ospf message-digest-key 7",
    "ntp trusted-key 7",
    "ntp authentication-key 7",
    # SNMPv3 groups and users without keys
    "snmp-server group NMS v3 priv read V1 write V2",
    "snmp-server user admin network-admin",
    # BGP communities are labels, not secrets
    "community MATCH_X members 65000:1;",
    "policy-options {\n    community CUST members 65000:1;\n    community CUST2 {\n        members 65000:2;\n    }\n}",
    "from community CUST;\nthen community add TAG;",
    "term t1 {\n    from {\n        protocol bgp;\n        community CUST;\n    }\n    then accept;\n}",
    "route-map RM permit 10\n set community 65000:100 additive",
    "neighbor 192.0.2.1 send-community both",
    "ip community-list standard CL permit 65000:1",
    "set network virtual-router default protocol bgp policy export rules R action allow update community [ 65000:1 ]",
    # prose and logs
    "community policy applied to the uplink",
    "pre-shared-key authentication enabled for peer 192.0.2.1",
    "IKE: using pre-shared-key on both peers",
    "token_type: Bearer",
    "secret-manager: enabled",
    "Password: ",
    "Password policy: minimum length 12",
    "isis authentication key-chain KC",
    "no ip nhrp authentication",
    # FortiOS / PAN-OS statements with no secret
    "set status enable",
    "set password-expire 90",
    "    set minimum-length 8",
    "set deviceconfig system hostname fw1",
    "set shared server-profile radius R1 server S1 ip-address 192.0.2.1",
    'set interfaces ge-0/0/0 description "reset password"',
    "<hostname>fw1</hostname>",
    "<password></password>",
    # wireless without a key
    "security wpa psk set-key",
    "wlan corp 1 corp\n security wpa akm psk",
]


@pytest.mark.parametrize("text", BENIGN, ids=[f"{i:02d}" for i in range(len(BENIGN))])
def test_benign_statements_untouched(text):
    assert sanitize(text) == (text, 0)


@pytest.mark.parametrize("text", [
    "x key 7\nNEXT-LINE-MARKER",
    "secret 5\nNEXT-LINE-MARKER",
    "password 7\nNEXT-LINE-MARKER",
    "snmp-server community\nNEXT-LINE-MARKER",
    "snmp-server user u g v3 auth sha\nNEXT-LINE-MARKER",
    "snmp-server user u g v3 auth md5 K priv aes 128\nNEXT-LINE-MARKER",
    "authentication-password\nNEXT-LINE-MARKER",
    "privacy-password\nNEXT-LINE-MARKER",
    "authentication-key\n\"NEXT-LINE-MARKER\"",
    "community\nNEXT-LINE-MARKER {\n authorization read-only;\n}",
])
def test_keyword_at_end_of_line_never_eats_the_next_line(text):
    out, _ = sanitize(text)
    assert "NEXT-LINE-MARKER" in out
    assert out.count("\n") == text.count("\n")


def test_type_5_secret_keeps_the_line_break_before_its_hash():
    out, _ = sanitize("secret 5\n$1$salt$HashHashHash99")
    assert out.count("\n") == 1 and "HashHashHash99" not in out


def test_nxos_and_ios_snmpv3_keywords_do_not_redact_fields_next_to_them():
    cfg = "snmp-server group NMS v3 priv read V1\nsnmp-server user u NMS v3 auth sha AuthPw1 priv PrivPw1\n"
    out, _ = sanitize(cfg)
    assert out == f"snmp-server group NMS v3 priv read V1\nsnmp-server user u NMS v3 auth sha {R} priv {R}\n"
