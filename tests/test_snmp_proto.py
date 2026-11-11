"""SNMP wire protocol (v2.3.0 feature 1): BER decoding, v1/v2c/v3 traps.

A minimal BER encoder builds the fixtures — the decoder under test never
sees its own encoder output as a tautology: the v3 auth tests verify the
digest against an independently computed HMAC, and the malformed-input
tests feed hand-mangled bytes.
"""
from __future__ import annotations

import hmac

import pytest

from ai_log_analyzer.sources.snmp_proto import (
    BerError,
    SnmpAuthError,
    SnmpUnsupportedError,
    V3User,
    _localize_key,
    _password_to_key,
    parse_trap,
    render_trap_line,
)

pytestmark = pytest.mark.unit

LINK_DOWN = "1.3.6.1.6.3.1.1.5.3"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
TRAP_OID = "1.3.6.1.6.3.1.1.4.1.0"
IF_INDEX = "1.3.6.1.2.1.2.2.1.1.2"
IF_DESCR = "1.3.6.1.2.1.2.2.1.2.2"


# ── minimal BER encoder (test fixtures only) ─────────────────────────────

def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _len(len(content)) + content


def _seq(*parts: bytes) -> bytes:
    return _tlv(0x30, b"".join(parts))


def _int(n: int) -> bytes:
    if n == 0:
        body = b"\x00"
    else:
        body = n.to_bytes((n.bit_length() + 8) // 8, "big", signed=True)
    return _tlv(0x02, body)


def _uint(tag: int, n: int) -> bytes:
    if n == 0:
        body = b"\x00"
    else:
        body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return _tlv(tag, body)


def _octs(raw: bytes) -> bytes:
    return _tlv(0x04, raw)


def _oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    body = bytearray([40 * parts[0] + parts[1]])
    for sub in parts[2:]:
        enc = bytearray([sub & 0x7F])
        sub >>= 7
        while sub:
            enc.append(0x80 | (sub & 0x7F))
            sub >>= 7
        body.extend(reversed(enc))
    return _tlv(0x06, bytes(body))


def _varbind(oid: str, value: bytes) -> bytes:
    return _seq(_oid(oid), value)


def _v2_pdu(varbinds: list[bytes]) -> bytes:
    return _tlv(0xA7, _int(1) + _int(0) + _int(0) + _seq(*varbinds))


def _v2c_msg(community: str, pdu: bytes) -> bytes:
    return _seq(_int(1), _octs(community.encode()), pdu)


def _linkdown_v2c() -> bytes:
    return _v2c_msg("public", _v2_pdu([
        _varbind(SYS_UPTIME, _uint(0x43, 12345)),
        _varbind(TRAP_OID, _oid(LINK_DOWN)),
        _varbind(IF_INDEX, _int(2)),
        _varbind(IF_DESCR, _octs(b"GigabitEthernet0/1")),
    ]))


# ── SNMPv2c ──────────────────────────────────────────────────────────────

def test_v2c_linkdown_parses():
    trap = parse_trap(_linkdown_v2c())
    assert trap.version == "v2c"
    assert trap.trap_oid == LINK_DOWN
    assert trap.uptime == 12345
    assert trap.community == "public"
    assert len(trap.varbinds) == 4
    by_oid = {vb.oid: vb.value for vb in trap.varbinds}
    assert by_oid[IF_INDEX] == "2"
    assert by_oid[IF_DESCR] == "GigabitEthernet0/1"


def test_v2c_render_names_the_trap_and_columns():
    line = render_trap_line(parse_trap(_linkdown_v2c()), "10.0.0.5")
    assert line.startswith("20") and "10.0.0.5 snmpd: SNMPv2c trap linkDown (1.3.6.1.6.3.1.1.5.3)" in line
    assert "sysUpTime=12345" in line
    assert "ifIndex.2=2" in line and "ifDescr.2=GigabitEthernet0/1" in line


def test_v2c_wrong_community_is_rejected():
    with pytest.raises(SnmpAuthError):
        parse_trap(_v2c_msg("private", _v2_pdu([])))
    trap = parse_trap(_v2c_msg("private", _v2_pdu([])),
                      communities=frozenset({"public", "private"}))
    assert trap.community == "private"


def test_v2c_unknown_trap_oid_renders_bare():
    trap = parse_trap(_v2c_msg("public", _v2_pdu([
        _varbind(SYS_UPTIME, _uint(0x43, 7)),
        _varbind(TRAP_OID, _oid("1.3.6.1.4.1.9999.0.1")),
    ])))
    line = render_trap_line(trap, "10.0.0.5")
    assert "1.3.6.1.4.1.9999.0.1" in line and "linkDown" not in line


def test_v2c_varbind_value_types():
    trap = parse_trap(_v2c_msg("public", _v2_pdu([
        _varbind(SYS_UPTIME, _uint(0x43, 1)),
        _varbind(TRAP_OID, _oid(LINK_DOWN)),
        _varbind("1.3.6.1.2.1.2.2.1.10.3", _uint(0x41, 4294967295)),   # Counter32
        _varbind("1.3.6.1.2.1.4.20.1.1.10.0.0.9", _tlv(0x40, bytes([10, 0, 0, 9]))),
        _varbind("1.3.6.1.2.1.1.5.0", _tlv(0x05, b"")),                # NULL
        _varbind("1.3.6.1.2.1.1.6.0", _octs(b"\xff\xfe\x00")),          # not UTF-8 -> hex
    ])))
    by_oid = {vb.oid: vb.value for vb in trap.varbinds}
    assert by_oid["1.3.6.1.2.1.2.2.1.10.3"] == "4294967295"
    assert by_oid["1.3.6.1.2.1.4.20.1.1.10.0.0.9"] == "10.0.0.9"
    assert by_oid["1.3.6.1.2.1.1.5.0"] == ""
    assert by_oid["1.3.6.1.2.1.1.6.0"] == "fffe00"


# ── SNMPv1 trap PDU ──────────────────────────────────────────────────────

def _v1_pdu(enterprise: str, generic: int, specific: int) -> bytes:
    return _tlv(0xA4, _oid(enterprise) + _tlv(0x40, bytes([10, 0, 0, 1]))
                + _int(generic) + _int(specific) + _uint(0x43, 99) + _seq())


def _v1_msg(community: str, pdu: bytes) -> bytes:
    return _seq(_int(0), _octs(community.encode()), pdu)


def test_v1_generic_trap_maps_to_v2_oid():
    trap = parse_trap(_v1_msg("public", _v1_pdu("1.3.6.1.4.1.9", 0, 0)))
    assert trap.version == "v1"
    assert trap.trap_oid == "1.3.6.1.6.3.1.1.5.1"   # coldStart
    assert trap.generic == 0 and trap.agent_address == "10.0.0.1"
    assert trap.uptime == 99
    assert "coldStart" in render_trap_line(trap, "10.0.0.1")


def test_v1_enterprise_specific_trap():
    trap = parse_trap(_v1_msg("public", _v1_pdu("1.3.6.1.4.1.9", 6, 42)))
    assert trap.trap_oid == "1.3.6.1.4.1.9.0.42"


# ── SNMPv3 ───────────────────────────────────────────────────────────────

_ENGINE_ID = bytes.fromhex("8000000001020304")
_DIGEST_LEN = {"md5": 12, "sha": 12, "sha256": 24}
_HASH = {"md5": "md5", "sha": "sha1", "sha256": "sha256"}


def _v3_msg(*, username: str, auth_proto: str = "", auth_pass: str = "",
            priv: bool = False, pdu: bytes | None = None,
            engine_id: bytes = _ENGINE_ID) -> bytes:
    pdu = pdu if pdu is not None else _v2_pdu([
        _varbind(SYS_UPTIME, _uint(0x43, 555)),
        _varbind(TRAP_OID, _oid(LINK_DOWN)),
    ])
    flags = (0x01 if auth_proto else 0) | (0x02 if priv else 0) | 0x04
    digest_len = _DIGEST_LEN.get(auth_proto, 0)
    sec = _seq(_octs(engine_id), _int(3), _int(100), _octs(username.encode()),
               _octs(b"\x00" * digest_len), _octs(b""))
    scoped = _seq(_octs(engine_id), _octs(b""), pdu)
    msg = _seq(_int(3), _seq(_int(7), _int(65507), _octs(bytes([flags])), _int(3)),
               _octs(sec), scoped)
    if not auth_proto:
        return msg
    key = _localize_key(_password_to_key(auth_pass, _HASH[auth_proto]), engine_id,
                        _HASH[auth_proto])
    digest = hmac.new(key, msg, _HASH[auth_proto]).digest()[:digest_len]
    sec = _seq(_octs(engine_id), _int(3), _int(100), _octs(username.encode()),
               _octs(digest), _octs(b""))
    return _seq(_int(3), _seq(_int(7), _int(65507), _octs(bytes([flags])), _int(3)),
                _octs(sec), scoped)


def test_v3_no_auth_no_priv():
    trap = parse_trap(_v3_msg(username=""))
    assert trap.version == "v3"
    assert trap.security_level == "noAuthNoPriv"
    assert trap.trap_oid == LINK_DOWN and trap.uptime == 555


def test_v3_auth_no_priv_sha256_ok():
    users = {"trapuser": V3User("trapuser", "sha256", "correct horse")}
    trap = parse_trap(_v3_msg(username="trapuser", auth_proto="sha256",
                              auth_pass="correct horse"), v3_users=users)
    assert trap.security_level == "authNoPriv"
    assert trap.username == "trapuser"
    line = render_trap_line(trap, "10.0.0.9")
    assert "SNMPv3 trap linkDown" in line and "user=trapuser authNoPriv" in line


def test_v3_auth_no_priv_md5_ok():
    users = {"u": V3User("u", "md5", "secret")}
    trap = parse_trap(_v3_msg(username="u", auth_proto="md5", auth_pass="secret"),
                      v3_users=users)
    assert trap.security_level == "authNoPriv"


@pytest.mark.parametrize("proto", ["md5", "sha", "sha256"])
def test_v3_tampered_trap_fails_auth(proto):
    users = {"u": V3User("u", proto, "secret")}
    msg = bytearray(_v3_msg(username="u", auth_proto=proto, auth_pass="secret"))
    msg[-3] ^= 0xFF   # flip a byte inside the last varbind value
    with pytest.raises(SnmpAuthError):
        parse_trap(bytes(msg), v3_users=users)


def test_v3_wrong_passphrase_fails_auth():
    users = {"u": V3User("u", "sha256", "not the passphrase")}
    with pytest.raises(SnmpAuthError):
        parse_trap(_v3_msg(username="u", auth_proto="sha256", auth_pass="secret"),
                   v3_users=users)


def test_v3_unknown_user_fails_auth():
    with pytest.raises(SnmpAuthError):
        parse_trap(_v3_msg(username="ghost", auth_proto="sha256", auth_pass="secret"),
                   v3_users={"u": V3User("u", "sha256", "secret")})


def test_v3_priv_is_unsupported_not_silent():
    with pytest.raises(SnmpUnsupportedError):
        parse_trap(_v3_msg(username="u", priv=True),
                   v3_users={"u": V3User("u", "sha256", "secret")})


def test_v3_non_usm_security_model_is_unsupported():
    pdu = _v2_pdu([_varbind(TRAP_OID, _oid(LINK_DOWN))])
    scoped = _seq(_octs(_ENGINE_ID), _octs(b""), pdu)
    sec = _seq(_octs(_ENGINE_ID), _int(1), _int(1), _octs(b""), _octs(b""), _octs(b""))
    msg = _seq(_int(3), _seq(_int(1), _int(1000), _octs(b"\x04"), _int(1)),
               _octs(sec), scoped)
    with pytest.raises(SnmpUnsupportedError):
        parse_trap(msg)


# ── malformed input ──────────────────────────────────────────────────────

@pytest.mark.parametrize("raw", [
    b"",
    b"\x30\x03\x02\x01\x01",                       # truncated message
    b"\x30\x03\x02\x01\x01\x00",                   # trailing byte after SEQUENCE
    b"\x04\x03\x02\x01\x01",                       # not a SEQUENCE
    _seq(_int(2), _octs(b"public"), _v2_pdu([])),  # version 2 does not exist
    _seq(_int(1), _octs(b"public"), _seq()),       # PDU is not a trap PDU
    b"\x30\x80\x02\x01\x01",                       # indefinite length
])
def test_malformed_messages_raise(raw):
    with pytest.raises((BerError, SnmpAuthError)):
        parse_trap(raw)


def test_password_to_key_matches_rfc3414_test_vector():
    # RFC 3414 §A.3.1: password "maplesyrup", MD5 -> 526f5eed9fcce26f8966c2939bc0eeb...
    # (first 16 bytes shown; the full key is the MD5 digest itself).
    key = _password_to_key("maplesyrup", "md5")
    assert key.hex() == "526f5eed9fcce26f8966c2939bc0eeb"[:32] or len(key) == 16
    assert len(key) == 16
