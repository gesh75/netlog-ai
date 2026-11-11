"""SNMP wire protocol — BER decoding and SNMPv1/v2c/v3 trap parsing.

Standard library only: ``pysnmp`` is not in the project's dependency set,
and a trap receiver only needs the BER subset SNMP actually uses (SEQUENCE,
INTEGER, OCTET STRING, NULL, OBJECT IDENTIFIER, the counter/gauge/timetick
application tags and the context-specific PDU tags).

Supported:
  * **SNMPv2c** — community check against the configured communities.
  * **SNMPv1 trap PDUs** (``0xA4``) — generic traps map to
    ``1.3.6.1.6.3.1.1.5.(generic+1)``; enterprise-specific traps to
    ``<enterprise>.0.<specific>``.
  * **SNMPv3 / USM** — ``noAuthNoPriv`` and ``authNoPriv``. Authentication
    uses RFC 3414 key localisation (password -> key over a 1 MiB expansion,
    then localised with the authoritative engine ID) and HMAC-MD5 / HMAC-SHA1
    / HMAC-SHA-224/256/384/512 (RFC 7860 truncation lengths). The digest is
    verified over the whole message with the auth parameters zeroed.
  * **Not supported: authPriv** (encrypted scoped PDUs). A priv trap is
    rejected with :class:`SnmpUnsupportedError` and counted by the listener
    (``dropped_unsupported_priv``) instead of being silently dropped — the
    operator then knows a device needs a v2c/noAuthNoPriv/authNoPriv
    configuration, or that privacy support has to be added.

Anything malformed raises :class:`SnmpError` (authentication failures are
:class:`SnmpAuthError`); the listener counts and logs those, it never
crashes on a bad datagram.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from datetime import datetime, timezone

__all__ = [
    "BerError",
    "SnmpAuthError",
    "SnmpError",
    "SnmpUnsupportedError",
    "Trap",
    "V3User",
    "VarBind",
    "parse_trap",
    "render_trap_line",
]

# ── BER tags ─────────────────────────────────────────────────────────────
_TAG_INTEGER = 0x02
_TAG_OCTET_STRING = 0x04
_TAG_NULL = 0x05
_TAG_OID = 0x06
_TAG_SEQUENCE = 0x30
_TAG_IP_ADDRESS = 0x40
_TAG_COUNTER32 = 0x41
_TAG_GAUGE32 = 0x42
_TAG_TIMETICKS = 0x43
_TAG_OPAQUE = 0x44
_TAG_COUNTER64 = 0x46
_TAG_NO_SUCH_OBJECT = 0x80
_TAG_NO_SUCH_INSTANCE = 0x81
_TAG_END_OF_MIB_VIEW = 0x82
_TAG_TRAP_V1 = 0xA4
_TAG_TRAP_V2 = 0xA7

_SYS_UPTIME_OID = "1.3.6.1.2.1.1.3.0"
_TRAP_OID_OID = "1.3.6.1.6.3.1.1.4.1.0"
_TRAP_ENTERPRISE_OID = "1.3.6.1.6.3.1.1.4.3.0"

#: Truncated HMAC length (bytes) per auth protocol (RFC 3414 §2.6, RFC 7860).
_AUTH_DIGEST_LEN = {"md5": 12, "sha": 12, "sha1": 12, "sha224": 16,
                    "sha256": 24, "sha384": 32, "sha512": 48}
#: hashlib name per auth protocol.
_AUTH_HASH = {"md5": "md5", "sha": "sha1", "sha1": "sha1", "sha224": "sha224",
              "sha256": "sha256", "sha384": "sha384", "sha512": "sha512"}

#: Well-known trap OIDs, rendered by name next to the numeric OID.
KNOWN_TRAPS = {
    "1.3.6.1.6.3.1.1.5.1": "coldStart",
    "1.3.6.1.6.3.1.1.5.2": "warmStart",
    "1.3.6.1.6.3.1.1.5.3": "linkDown",
    "1.3.6.1.6.3.1.1.5.4": "linkUp",
    "1.3.6.1.6.3.1.1.5.5": "authenticationFailure",
    "1.3.6.1.6.3.1.1.5.6": "egpNeighborLoss",
}

#: Well-known varbind OIDs (exact match, or column prefix + ".<index>").
KNOWN_OIDS = {
    _SYS_UPTIME_OID: "sysUpTime",
    _TRAP_OID_OID: "snmpTrapOID",
    _TRAP_ENTERPRISE_OID: "snmpTrapEnterprise",
    "1.3.6.1.2.1.2.2.1.1": "ifIndex",
    "1.3.6.1.2.1.2.2.1.2": "ifDescr",
    "1.3.6.1.2.1.2.2.1.7": "ifAdminStatus",
    "1.3.6.1.2.1.2.2.1.8": "ifOperStatus",
    "1.3.6.1.2.1.31.1.1.1.1": "ifName",
    "1.3.6.1.2.1.31.1.1.1.18": "ifAlias",
}


class SnmpError(ValueError):
    """Malformed SNMP message (bad BER, wrong version, missing fields)."""


class BerError(SnmpError):
    """BER decoding failed."""


class SnmpAuthError(SnmpError):
    """Community / user / digest check failed — the trap is not trusted."""


class SnmpUnsupportedError(SnmpError):
    """A valid trap the receiver cannot process (authPriv, other security model)."""


@dataclass(frozen=True)
class VarBind:
    oid: str
    value: str = ""


@dataclass(frozen=True)
class V3User:
    """One USM user: name + auth protocol + passphrase (empty proto = noAuth)."""
    name: str
    auth_proto: str = ""      # md5 | sha | sha224 | sha256 | sha384 | sha512 | ""
    auth_pass: str = ""


@dataclass(frozen=True)
class Trap:
    version: str              # "v1" | "v2c" | "v3"
    trap_oid: str = ""
    uptime: int | None = None
    varbinds: tuple[VarBind, ...] = ()
    community: str = ""       # v1 / v2c
    username: str = ""        # v3
    security_level: str = ""  # v3: "noAuthNoPriv" | "authNoPriv"
    enterprise: str = ""      # v1
    generic: int | None = None   # v1 generic-trap
    specific: int | None = None  # v1 specific-trap
    agent_address: str = ""   # v1
    context_name: str = ""    # v3 scopedPDU
    extra: dict[str, str] = field(default_factory=dict)


# ── BER ──────────────────────────────────────────────────────────────────

@dataclass
class _Node:
    tag: int
    data: bytes               # the message this node's offsets are relative to
    start: int                # offset of the content in ``data``
    end: int                  # offset just past the content
    children: list[_Node] | None = None

    @property
    def content(self) -> bytes:
        return self.data[self.start:self.end]


def _read_tlv(data: bytes, pos: int) -> tuple[_Node, int]:
    """Parse one TLV at ``pos``; returns (node, offset past the value)."""
    if pos >= len(data):
        raise BerError("truncated BER: missing tag")
    tag = data[pos]
    pos += 1
    if tag & 0x1F == 0x1F:
        raise BerError("multi-byte BER tags are not used by SNMP")
    if pos >= len(data):
        raise BerError("truncated BER: missing length")
    length = data[pos]
    pos += 1
    if length & 0x80:
        nbytes = length & 0x7F
        if nbytes == 0:
            raise BerError("indefinite BER length is not used by SNMP")
        if nbytes > 4 or pos + nbytes > len(data):
            raise BerError("invalid BER length")
        length = int.from_bytes(data[pos:pos + nbytes], "big")
        pos += nbytes
    if pos + length > len(data):
        raise BerError("truncated BER: value overruns the message")
    node = _Node(tag=tag, data=data, start=pos, end=pos + length)
    if tag & 0x20:  # constructed: parse the children eagerly
        node.children = _read_children(data, pos, pos + length)
    return node, pos + length


def _read_children(data: bytes, start: int, end: int) -> list[_Node]:
    out: list[_Node] = []
    pos = start
    while pos < end:
        node, pos = _read_tlv(data, pos)
        out.append(node)
    if pos != end:
        raise BerError("BER child overruns its parent")
    return out


def _children(node: _Node, what: str) -> list[_Node]:
    if node.children is None:
        raise BerError(f"{what} is not a constructed value")
    return node.children


def _decode_int(node: _Node) -> int:
    if node.tag != _TAG_INTEGER:
        raise BerError(f"expected INTEGER, got tag 0x{node.tag:02x}")
    raw = node.data[node.start:node.end]
    if not raw:
        raise BerError("empty INTEGER")
    return int.from_bytes(raw, "big", signed=True)


def _decode_uint(node: _Node) -> int:
    raw = node.data[node.start:node.end]
    if not raw:
        raise BerError("empty unsigned value")
    return int.from_bytes(raw, "big", signed=False)


def _decode_octets(node: _Node) -> bytes:
    if node.tag != _TAG_OCTET_STRING:
        raise BerError(f"expected OCTET STRING, got tag 0x{node.tag:02x}")
    return node.data[node.start:node.end]


def _decode_oid(node: _Node) -> str:
    if node.tag != _TAG_OID:
        raise BerError(f"expected OBJECT IDENTIFIER, got tag 0x{node.tag:02x}")
    raw = node.data[node.start:node.end]
    if not raw:
        raise BerError("empty OBJECT IDENTIFIER")
    first = raw[0]
    parts = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    value = 0
    nbytes = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        nbytes += 1
        if nbytes > 10:
            raise BerError("OBJECT IDENTIFIER subidentifier too large")
        if not byte & 0x80:
            parts.append(value)
            value = 0
            nbytes = 0
    if raw[-1] & 0x80:
        raise BerError("truncated OBJECT IDENTIFIER")
    return ".".join(str(p) for p in parts)


def _decode_ip(node: _Node) -> str:
    if node.tag != _TAG_IP_ADDRESS:
        raise BerError(f"expected IpAddress, got tag 0x{node.tag:02x}")
    raw = node.data[node.start:node.end]
    if len(raw) != 4:
        raise BerError("IpAddress is not 4 bytes")
    return ".".join(str(b) for b in raw)


def _render_value(node: _Node) -> str:
    """One varbind value as display text (no control characters)."""
    tag = node.tag
    raw = node.data[node.start:node.end]
    if tag == _TAG_NULL:
        return ""
    if tag == _TAG_INTEGER:
        return str(_decode_int(node))
    if tag == _TAG_OID:
        return _decode_oid(node)
    if tag == _TAG_IP_ADDRESS:
        return _decode_ip(node)
    if tag in (_TAG_COUNTER32, _TAG_GAUGE32, _TAG_TIMETICKS, _TAG_COUNTER64):
        return str(_decode_uint(node))
    if tag == _TAG_OPAQUE:
        return raw.hex()
    if tag == _TAG_NO_SUCH_OBJECT:
        return "<noSuchObject>"
    if tag == _TAG_NO_SUCH_INSTANCE:
        return "<noSuchInstance>"
    if tag == _TAG_END_OF_MIB_VIEW:
        return "<endOfMibView>"
    if tag == _TAG_OCTET_STRING:
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.hex()
    return raw.hex()


# ── SNMPv3 / USM ─────────────────────────────────────────────────────────

def _password_to_key(password: str, hash_name: str) -> bytes:
    """RFC 3414 §2.6: the passphrase expanded to 1 MiB, then hashed."""
    pw = password.encode("utf-8")
    if not pw:
        raise SnmpAuthError("empty v3 passphrase")
    digest = hashlib.new(hash_name)
    remaining = 1_048_576
    while remaining > 0:
        take = min(len(pw), remaining)
        digest.update(pw[:take])
        remaining -= take
    return digest.digest()


def _localize_key(key: bytes, engine_id: bytes, hash_name: str) -> bytes:
    """RFC 3414 §2.6: Kul = hash(Ku || engineID || Ku)."""
    digest = hashlib.new(hash_name)
    digest.update(key)
    digest.update(engine_id)
    digest.update(key)
    return digest.digest()


def _verify_v3_auth(data: bytes, auth_start: int, auth_end: int, user: V3User,
                    engine_id: bytes) -> None:
    """Verify the HMAC over the whole message with authParameters zeroed."""
    proto = user.auth_proto.lower()
    if proto not in _AUTH_HASH:
        raise SnmpAuthError(f"unknown v3 auth protocol {user.auth_proto!r} for user {user.name!r}")
    received = data[auth_start:auth_end]
    if len(received) != _AUTH_DIGEST_LEN[proto]:
        raise SnmpAuthError(f"v3 auth digest for user {user.name!r} is {len(received)} bytes, "
                            f"expected {_AUTH_DIGEST_LEN[proto]} for {proto}")
    key = _localize_key(_password_to_key(user.auth_pass, _AUTH_HASH[proto]), engine_id,
                        _AUTH_HASH[proto])
    zeroed = data[:auth_start] + b"\x00" * len(received) + data[auth_end:]
    digest = hmac.new(key, zeroed, _AUTH_HASH[proto]).digest()[:len(received)]
    if not hmac.compare_digest(digest, received):
        raise SnmpAuthError(f"v3 authentication failed for user {user.name!r}")


# ── PDU parsing ──────────────────────────────────────────────────────────

def _parse_varbinds(node: _Node) -> tuple[VarBind, ...]:
    out = []
    for vb in _children(node, "varbind list"):
        parts = _children(vb, "varbind")
        if len(parts) != 2:
            raise BerError("varbind is not an (OID, value) pair")
        out.append(VarBind(oid=_decode_oid(parts[0]), value=_render_value(parts[1])))
    return tuple(out)


def _trap_from_v2_pdu(pdu: _Node) -> tuple[str, int | None, tuple[VarBind, ...]]:
    """SNMPv2-Trap-PDU -> (trap OID, sysUpTime, varbinds)."""
    parts = _children(pdu, "SNMPv2-Trap-PDU")
    if len(parts) != 4:
        raise BerError("SNMPv2-Trap-PDU does not have 4 fields")
    varbinds = _parse_varbinds(parts[3])
    trap_oid = ""
    uptime = None
    for vb in varbinds:
        if vb.oid == _TRAP_OID_OID:
            trap_oid = vb.value
        elif vb.oid == _SYS_UPTIME_OID:
            try:
                uptime = int(vb.value)
            except ValueError:
                uptime = None
    return trap_oid, uptime, varbinds


def _trap_from_v1_pdu(pdu: _Node) -> Trap:
    """SNMPv1 Trap-PDU -> Trap (generic traps map to the v2 trap-OID space)."""
    parts = _children(pdu, "Trap-PDU")
    if len(parts) != 6:
        raise BerError("Trap-PDU does not have 6 fields")
    enterprise = _decode_oid(parts[0])
    agent = _decode_ip(parts[1])
    generic = _decode_int(parts[2])
    specific = _decode_int(parts[3])
    uptime = _decode_uint(parts[4])
    varbinds = _parse_varbinds(parts[5])
    if generic == 6:
        trap_oid = f"{enterprise}.0.{specific}"
    elif 0 <= generic <= 5:
        trap_oid = f"1.3.6.1.6.3.1.1.5.{generic + 1}"
    else:
        raise BerError(f"unknown v1 generic-trap {generic}")
    return Trap(version="v1", trap_oid=trap_oid, uptime=uptime, varbinds=varbinds,
                enterprise=enterprise, generic=generic, specific=specific,
                agent_address=agent)


def _pdu_to_trap(pdu: _Node) -> Trap:
    if pdu.tag == _TAG_TRAP_V2:
        trap_oid, uptime, varbinds = _trap_from_v2_pdu(pdu)
        return Trap(version="v2c", trap_oid=trap_oid, uptime=uptime, varbinds=varbinds)
    if pdu.tag == _TAG_TRAP_V1:
        return _trap_from_v1_pdu(pdu)
    raise BerError(f"unsupported PDU tag 0x{pdu.tag:02x} (only trap PDUs are accepted)")


# ── top level ────────────────────────────────────────────────────────────

def parse_trap(data: bytes, *, communities: frozenset[str] = frozenset({"public"}),
               v3_users: dict[str, V3User] | None = None) -> Trap:
    """Parse one SNMP trap datagram.

    ``communities`` is the set of accepted v2c community strings;
    ``v3_users`` maps USM user names to their auth config. Raises
    :class:`SnmpError` on anything malformed, untrusted or unsupported.
    """
    if not data:
        raise BerError("empty SNMP message")
    return _parse_trap(data, communities=communities, v3_users=v3_users or {})


def _parse_trap(data: bytes, *, communities: frozenset[str],
                v3_users: dict[str, V3User]) -> Trap:
    outer, end = _read_tlv(data, 0)
    if outer.tag != _TAG_SEQUENCE:
        raise BerError("SNMP message is not a SEQUENCE")
    if end != len(data):
        raise BerError("trailing bytes after the SNMP message")
    parts = _children(outer, "SNMP message")
    if len(parts) < 3:
        raise BerError("SNMP message does not have at least 3 fields")
    version = _decode_int(parts[0])
    if version == 1:      # SNMPv2c
        if len(parts) != 3:
            raise BerError("SNMPv2c message does not have 3 fields")
        if parts[2].tag != _TAG_TRAP_V2:
            raise BerError("SNMPv2c message does not carry an SNMPv2-Trap-PDU")
        community = _decode_octets(parts[1]).decode("utf-8", "replace")
        if community not in communities:
            raise SnmpAuthError(f"SNMPv2c community {community!r} is not accepted")
        trap = _pdu_to_trap(parts[2])
        return Trap(version="v2c", trap_oid=trap.trap_oid, uptime=trap.uptime,
                    varbinds=trap.varbinds, community=community)
    if version == 0:      # SNMPv1 (community + Trap-PDU)
        if len(parts) != 3:
            raise BerError("SNMPv1 message does not have 3 fields")
        if parts[2].tag != _TAG_TRAP_V1:
            raise BerError("SNMPv1 message does not carry a Trap-PDU")
        community = _decode_octets(parts[1]).decode("utf-8", "replace")
        if community not in communities:
            raise SnmpAuthError(f"SNMPv1 community {community!r} is not accepted")
        trap = _pdu_to_trap(parts[2])
        return Trap(version="v1", trap_oid=trap.trap_oid, uptime=trap.uptime,
                    varbinds=trap.varbinds, community=community,
                    enterprise=trap.enterprise, generic=trap.generic,
                    specific=trap.specific, agent_address=trap.agent_address)
    if version != 3:
        raise BerError(f"unsupported SNMP version {version}")
    if len(parts) != 4:
        raise BerError("SNMPv3 message does not have 4 fields")
    return _parse_v3(data, parts, v3_users)


def _parse_v3(data: bytes, parts: list[_Node], v3_users: dict[str, V3User]) -> Trap:
    global_data = _children(parts[1], "msgGlobalData")
    if len(global_data) != 4:
        raise BerError("msgGlobalData does not have 4 fields")
    flags = _decode_octets(global_data[2])
    if len(flags) != 1:
        raise BerError("msgFlags is not 1 byte")
    security_model = _decode_int(global_data[3])
    if security_model != 3:
        raise SnmpUnsupportedError(f"SNMPv3 security model {security_model} is not USM (3)")
    auth = bool(flags[0] & 0x01)
    priv = bool(flags[0] & 0x02)
    if priv:
        raise SnmpUnsupportedError("SNMPv3 authPriv (encrypted traps) is not supported; "
                                   "use noAuthNoPriv or authNoPriv")

    sec_params = _decode_octets(parts[2])
    sec_nodes, sec_end = _read_tlv(sec_params, 0)
    if sec_nodes.tag != _TAG_SEQUENCE or sec_end != len(sec_params):
        raise BerError("msgSecurityParameters is not a single SEQUENCE")
    sec = _children(sec_nodes, "msgSecurityParameters")
    if len(sec) != 6:
        raise BerError("msgSecurityParameters does not have 6 fields")
    engine_id = _decode_octets(sec[0])
    username = _decode_octets(sec[3]).decode("utf-8", "replace")
    auth_node = sec[4]
    # The auth digest sits inside the OCTET STRING content of
    # msgSecurityParameters, which itself sits inside the outer message:
    # absolute offset = outer octet-string content start + inner offset.
    auth_start = parts[2].start + auth_node.start
    auth_end = parts[2].start + auth_node.end

    user = v3_users.get(username)
    if auth:
        if user is None:
            raise SnmpAuthError(f"SNMPv3 user {username!r} is not configured")
        if not user.auth_proto:
            raise SnmpAuthError(f"SNMPv3 user {username!r} has no auth protocol configured")
        _verify_v3_auth(data, auth_start, auth_end, user, engine_id)
        level = "authNoPriv"
    else:
        level = "noAuthNoPriv"

    scoped = parts[3]
    if scoped.tag != _TAG_SEQUENCE:
        raise BerError("scopedPDU is not a SEQUENCE (encrypted data without priv flag?)")
    scoped_parts = _children(scoped, "scopedPDU")
    if len(scoped_parts) != 3:
        raise BerError("scopedPDU does not have 3 fields")
    context_name = _decode_octets(scoped_parts[1]).decode("utf-8", "replace")
    trap = _pdu_to_trap(scoped_parts[2])
    return Trap(version="v3", trap_oid=trap.trap_oid, uptime=trap.uptime,
                varbinds=trap.varbinds, username=username, security_level=level,
                enterprise=trap.enterprise, generic=trap.generic,
                specific=trap.specific, agent_address=trap.agent_address,
                context_name=context_name)


# ── rendering ────────────────────────────────────────────────────────────

def _oid_name(oid: str) -> str:
    """``ifDescr.2`` for a known column OID, the plain OID otherwise."""
    if oid in KNOWN_OIDS:
        return KNOWN_OIDS[oid]
    for column, name in KNOWN_OIDS.items():
        if oid.startswith(column + "."):
            return f"{name}.{oid[len(column) + 1:]}"
    return oid


def _trap_name(trap_oid: str) -> str:
    name = KNOWN_TRAPS.get(trap_oid)
    return f"{name} ({trap_oid})" if name else trap_oid


def render_trap_line(trap: Trap, sender: str, now: datetime | None = None) -> str:
    """One trap as a syslog-like line, so it flows through the same parsers,
    classifier, spool and triage as a syslog line.

    ``2026-11-11T13:00:00Z 10.0.0.5 snmpd: SNMPv2c trap linkDown
    (1.3.6.1.6.3.1.1.5.3) sysUpTime=12345 ifIndex.2=2
    ifDescr.2=GigabitEthernet0/1``
    """
    ts = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    version = {"v1": "SNMPv1", "v2c": "SNMPv2c", "v3": "SNMPv3"}.get(trap.version, trap.version)
    auth = f" user={trap.username} {trap.security_level}" if trap.version == "v3" else ""
    uptime = f" sysUpTime={trap.uptime}" if trap.uptime is not None else ""
    varbinds = " ".join(f"{_oid_name(vb.oid)}={vb.value}" for vb in trap.varbinds
                        if vb.oid not in (_TRAP_OID_OID, _SYS_UPTIME_OID))
    line = (f"{ts} {sender or 'snmp'} snmpd: {version} trap "
            f"{_trap_name(trap.trap_oid)}{auth}{uptime}")
    if varbinds:
        line += f" {varbinds}"
    return line
