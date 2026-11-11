"""SNMP trap receiver (v2.3.0 feature 1): listener, spool, registry, env bootstrap.

No live UDP traffic: the sandbox blocks ``sendto``, so datagrams are driven
through ``_datagram`` directly while the source runs on a real bound socket
(port 0, loopback) with a real spool DB — the closest possible end-to-end
proof here. The one thing this cannot prove is the kernel delivering a
datagram to the socket; that path is the same ``recvmsg_into`` loop the
syslog listener already exercises.
"""
from __future__ import annotations

import hmac
import socket
import threading
from collections import Counter

import pytest

from ai_log_analyzer.sources.base import SourceConfig, SourceError, registry
from ai_log_analyzer.sources.manager import SourceManager
from ai_log_analyzer.sources.snmp import SnmpTrapSource
from ai_log_analyzer.sources.snmp_proto import _localize_key, _password_to_key
from ai_log_analyzer.state_store import StateDB

pytestmark = pytest.mark.unit

LINK_DOWN = "1.3.6.1.6.3.1.1.5.3"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
TRAP_OID = "1.3.6.1.6.3.1.1.4.1.0"
IF_DESCR = "1.3.6.1.2.1.2.2.1.2.2"
_ENGINE_ID = bytes.fromhex("8000000001020304")


# ── minimal BER encoder (fixtures; mirrors tests/test_snmp_proto.py) ─────

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
    body = b"\x00" if n == 0 else n.to_bytes((n.bit_length() + 8) // 8, "big", signed=True)
    return _tlv(0x02, body)


def _uint(tag: int, n: int) -> bytes:
    body = b"\x00" if n == 0 else n.to_bytes((n.bit_length() + 7) // 8, "big")
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


def _v2_pdu(varbinds: list[bytes]) -> bytes:
    return _tlv(0xA7, _int(1) + _int(0) + _int(0)
                + _seq(*[_seq(_oid(o), v) for o, v in varbinds]))


def _v2c_msg(community: str = "public") -> bytes:
    return _seq(_int(1), _octs(community.encode()), _v2_pdu([
        (SYS_UPTIME, _uint(0x43, 12345)),
        (TRAP_OID, _oid(LINK_DOWN)),
        (IF_DESCR, _octs(b"GigabitEthernet0/1")),
    ]))


def _v3_msg(username: str, auth_proto: str = "", auth_pass: str = "") -> bytes:
    pdu = _v2_pdu([(SYS_UPTIME, _uint(0x43, 555)), (TRAP_OID, _oid(LINK_DOWN))])
    flags = (0x01 if auth_proto else 0) | 0x04
    digest_len = {"md5": 12, "sha": 12, "sha256": 24}.get(auth_proto, 0)
    sec = _seq(_octs(_ENGINE_ID), _int(3), _int(100), _octs(username.encode()),
               _octs(b"\x00" * digest_len), _octs(b""))
    scoped = _seq(_octs(_ENGINE_ID), _octs(b""), pdu)
    msg = _seq(_int(3), _seq(_int(7), _int(65507), _octs(bytes([flags])), _int(3)),
               _octs(sec), scoped)
    if not auth_proto:
        return msg
    hash_name = {"md5": "md5", "sha": "sha1", "sha256": "sha256"}[auth_proto]
    key = _localize_key(_password_to_key(auth_pass, hash_name), _ENGINE_ID, hash_name)
    digest = hmac.new(key, msg, hash_name).digest()[:digest_len]
    sec = _seq(_octs(_ENGINE_ID), _int(3), _int(100), _octs(username.encode()),
               _octs(digest), _octs(b""))
    return _seq(_int(3), _seq(_int(7), _int(65507), _octs(bytes([flags])), _int(3)),
                _octs(sec), scoped)


# ── fixtures ─────────────────────────────────────────────────────────────

@pytest.fixture
def db(tmp_path, monkeypatch):
    path = tmp_path / "state.db"
    monkeypatch.setenv("AI_LOG_ANALYZER_STATE_DB", str(path))
    return StateDB(path)


def _source(db, **extra) -> SnmpTrapSource:
    cfg_extra = {"bind": "127.0.0.1", "port": "0", **extra}
    return SnmpTrapSource(SourceConfig(id="traps", type="snmp",
                                       url="udp://127.0.0.1", extra=cfg_extra))


# ── trap path ────────────────────────────────────────────────────────────

def test_trap_lands_in_spool_and_fetch(db):
    src = _source(db)
    try:
        assert src._sock is not None and src._sock.getsockname()[1] != 0  # really bound
        assert src.role == "listener" and src.healthcheck() is True
        src._datagram(_v2c_msg(), ("10.0.0.5", 162))
        events = list(src.fetch())
        assert len(events) == 1
        ev = events[0]
        assert ev.hostname == "10.0.0.5" and ev.appname == "snmpd"
        assert "linkDown" in ev.message and "GigabitEthernet0/1" in ev.message
        assert ev.attrs.get("sender_ip") == "10.0.0.5"
        assert src.stats()["traps"] == 1 and src.stats()["received"] == 1
        assert db.spool_stats()[0]["source"] == "traps"
        assert db.spool_sources() == ["traps"]
    finally:
        src.close()


def test_fetch_new_cursor_is_incremental(db):
    src = _source(db)
    try:
        src._datagram(_v2c_msg(), ("10.0.0.5", 162))
        src._datagram(_v2c_msg(), ("10.0.0.6", 162))
        events, cursor = src.fetch_new(0)
        assert len(events) == 2 and cursor > 0
        events2, cursor2 = src.fetch_new(cursor)
        assert events2 == [] and cursor2 == cursor
    finally:
        src.close()


def test_trap_survives_a_second_reader_of_the_same_spool(db):
    src = _source(db)
    try:
        src._datagram(_v2c_msg(), ("10.0.0.5", 162))
    finally:
        src.close()
    # A fresh source on the same spool (memory mode would lose it) still sees it.
    src2 = _source(db)
    try:
        assert len(list(src2.fetch())) == 1
    finally:
        src2.close()


def test_wrong_community_is_rejected_and_counted(db):
    src = _source(db)
    try:
        src._datagram(_v2c_msg("private"), ("10.0.0.5", 162))
        assert src.stats()["rejected_auth"] == 1
        assert list(src.fetch()) == []
    finally:
        src.close()


def test_malformed_datagram_is_counted_not_fatal(db):
    src = _source(db)
    try:
        src._datagram(b"\x30\x03\x02\x01\x01", ("10.0.0.5", 162))
        src._datagram(b"not snmp at all", ("10.0.0.5", 162))
        assert src.stats()["parse_errors"] == 2
        assert src.stats().get("traps", 0) == 0
        assert src.healthcheck() is True   # still alive after garbage
    finally:
        src.close()


def test_v3_auth_trap_accepted_and_tampered_rejected(db):
    src = _source(db, v3_users="trapuser:sha256:correct horse")
    try:
        src._datagram(_v3_msg("trapuser", "sha256", "correct horse"), ("10.0.0.9", 162))
        assert src.stats()["traps"] == 1
        tampered = bytearray(_v3_msg("trapuser", "sha256", "correct horse"))
        tampered[-3] ^= 0xFF
        src._datagram(bytes(tampered), ("10.0.0.9", 162))
        assert src.stats()["rejected_auth"] == 1
        assert src.stats()["traps"] == 1
        ev = list(src.fetch())[0]
        assert "user=trapuser authNoPriv" in ev.message
    finally:
        src.close()


def test_v3_priv_trap_is_dropped_unsupported(db):
    # priv flag set, noAuth user: the parser rejects before decryption.
    pdu = _v2_pdu([(TRAP_OID, _oid(LINK_DOWN))])
    scoped = _seq(_octs(_ENGINE_ID), _octs(b""), pdu)
    sec = _seq(_octs(_ENGINE_ID), _int(1), _int(1), _octs(b"u"), _octs(b""), _octs(b""))
    msg = _seq(_int(3), _seq(_int(1), _int(1000), _octs(b"\x06"), _int(3)),
               _octs(sec), scoped)
    src = _source(db)
    try:
        src._datagram(msg, ("10.0.0.9", 162))
        assert src.stats()["dropped_unsupported"] == 1
        assert list(src.fetch()) == []
    finally:
        src.close()


def test_allow_list_blocks_unlisted_senders(db):
    src = _source(db, allow="10.0.0.0/24")
    try:
        src._datagram(_v2c_msg(), ("192.0.2.7", 162))
        assert src.stats()["rejected_sender"] == 1
        src._datagram(_v2c_msg(), ("10.0.0.5", 162))
        assert src.stats()["traps"] == 1
    finally:
        src.close()


# ── config errors ────────────────────────────────────────────────────────

def test_bad_v3_auth_proto_is_a_config_error(db):
    with pytest.raises(SourceError, match="auth protocol"):
        _source(db, v3_users="u:des:secret")


def test_bad_allow_entry_is_a_config_error(db):
    with pytest.raises(SourceError, match="allow-list"):
        _source(db, allow="not-an-ip")


def test_v3_users_parsing():
    from ai_log_analyzer.sources.snmp import _parse_v3_users

    users = _parse_v3_users("alice:sha256:pw1;bob")
    assert users["alice"].auth_proto == "sha256" and users["alice"].auth_pass == "pw1"
    assert users["bob"].auth_proto == ""   # noAuthNoPriv
    assert _parse_v3_users("") == {}
    with pytest.raises(SourceError):
        _parse_v3_users("alice:sha256:")   # missing passphrase


# ── reader fallback + registry + env bootstrap ───────────────────────────

def test_port_busy_becomes_reader(db):
    holder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    holder.bind(("127.0.0.1", 0))
    port = holder.getsockname()[1]
    try:
        src = _source(db, port=str(port))
        try:
            assert src.role == "reader"
            assert src.stats()["role"] == "reader"
        finally:
            src.close()
    finally:
        holder.close()


def test_registry_knows_snmp():
    assert registry.is_registered("snmp")
    assert "snmp" in registry.known()


def test_manager_load_from_env(db, monkeypatch):
    monkeypatch.setenv("NETLOG_SOURCE_traps_TYPE", "snmp")
    monkeypatch.setenv("NETLOG_SOURCE_traps_URL", "udp://127.0.0.1")
    monkeypatch.setenv("NETLOG_SOURCE_traps_BIND", "127.0.0.1")
    monkeypatch.setenv("NETLOG_SOURCE_traps_PORT", "0")
    manager = SourceManager()
    try:
        added = manager.load_from_env()
        assert "traps" in added and "snmp" in manager.known_kinds()
        src = manager.get("traps")
        assert isinstance(src, SnmpTrapSource) and src.healthcheck() is True
    finally:
        manager.remove("traps")


def test_backpressure_publish_uses_snmp_action(db):
    src = _source(db)
    try:
        src._stats["udp_drops"] = 3
        src._publish_backpressure()
        status = db.backpressure_status()
        assert status["total_drops"] == 3 and status["warning"] is True
        rows = db.audit_query(action="snmp_backpressure", limit=10)
        assert len(rows) == 1 and rows[0]["target"] == "traps"
        assert rows[0]["detail"]["total_drops"] == 3
    finally:
        src.close()


def test_memory_mode_ingest_without_spool(monkeypatch):
    monkeypatch.delenv("AI_LOG_ANALYZER_STATE_DB", raising=False)
    src = object.__new__(SnmpTrapSource)
    src._buffer = []
    src._total_ingested = 0
    src._stats = Counter()
    src._lock = threading.Lock()
    src._sink = None
    src._db = None
    src._ingest("2026-11-11T13:00:00Z 10.0.0.5 snmpd: SNMPv2c trap linkDown", "10.0.0.5")
    events = list(src.fetch())
    assert len(events) == 1 and events[0].hostname == "10.0.0.5"
