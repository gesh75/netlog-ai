"""Parser and classifier regexes must run in time linear in the line length.

Ingest caps a line at 64 KiB and the sender controls the text. Several regexes put two repeats that
can take the same characters side by side (``\\s*[:=]?\\s*``, a lazy ``.*?`` ended by a whitespace
lookahead, a key run restarted at every character), so one datagram cost seconds to minutes of CPU on
every fetch, tail poll and triage tick that parsed it.

Timings use generous absolute limits (the fixed code needs milliseconds) or input scaling.
"""
from __future__ import annotations

import ast
import random
import re
import time
from pathlib import Path

import pytest

from ai_log_analyzer import classifier
from ai_log_analyzer.classifier import LogEvent, classify_events
from ai_log_analyzer.parsers import (
    base,
    ensure_structured,
    entities,
    fortinet,
    generic,
    panos,
    parse_line,
    sdwan,
    structured,
    timeutil,
)

try:  # Python 3.11+ moved these under re._*
    from re import _constants as _sre_constants
    from re import _parser as _sre_parse
except ImportError:  # pragma: no cover - Python 3.10
    import sre_constants as _sre_constants  # type: ignore[no-redef]
    import sre_parse as _sre_parse  # type: ignore[no-redef]

pytestmark = pytest.mark.unit


def _elapsed(fn) -> float:
    t0 = time.perf_counter()
    fn()
    return time.perf_counter() - t0


def _assert_fast(fn, limit: float, label: str) -> None:
    took = _elapsed(fn)
    if took > limit:   # one retry against a noisy machine
        took = min(took, _elapsed(fn))
    assert took < limit, f"{label}: {took:.2f}s (limit {limit}s)"


def _syslog(body: str) -> str:
    return "<13>Oct 22 10:15:01 leaf1 sw1: " + body


# (id, line builder, size). The sizes are what the old code needs seconds for; the 65_000 ones are the
# 64 KiB lines named in the findings.
CASES = [
    ("cef-ext", lambda n: "CEF:0|v|p|1|100|n|5|msg=x" + " " * n + "y", 12_000),
    ("cef-ext-tabs", lambda n: "CEF:0|v|p|1|100|n|5|msg=x" + "\t " * (n // 2) + "y", 12_000),
    ("leef-ext", lambda n: "LEEF:1.0|v|p|1|e|msg=x" + " " * n + "y", 12_000),
    ("leef2-ext", lambda n: "LEEF:2.0|v|p|1|e|^|msg=x" + " " * n + "y", 12_000),
    ("sdwan-word", lambda n: "%Viptela-" + "a" * n, 12_000),
    ("sdwan-word-dash", lambda n: "%Viptela-" + "a-" * (n // 2), 12_000),
    ("sdwan-colon-no-value", lambda n: "%Viptela-" + "a" * n + ": ", 12_000),
    ("fortios-kv-word", lambda n: "devname=x type=y " + "a" * n, 12_000),
    ("fortios-kv-dash", lambda n: "devname=x type=y " + "a-" * (n // 2), 12_000),
    ("fortios-phase-gap", lambda n: 'devname=x type=y subtype=vpn msg="phase' + " " * n + '!"', 12_000),
    ("fortios-sla", lambda n: 'devname=x type=y subtype=sdwan msg="' + "sla " * (n // 4) + '"', 65_000),
    ("fortios-back", lambda n: 'devname=x type=y subtype=sdwan msg="' + "back " * (n // 5) + '"', 65_000),
    ("bgp-state-gap", lambda n: _syslog("bgp state" + " " * n + "!"), 12_000),
    ("bgp-new-state-gap", lambda n: _syslog("bgp new state" + "\t" * n + "!"), 12_000),
    ("vni-gap", lambda n: _syslog("evpn vni" + " " * n + "!"), 12_000),
    ("bfd-to-gap", lambda n: _syslog("bfd to" + " " * n + "!"), 12_000),
    ("bfd-remote-peer-gap", lambda n: _syslog("bfd remote peer" + " " * n + "!"), 12_000),
    ("ospf-neighbor-gap", lambda n: _syslog("ospf neighbor" + " " * n + "!"), 12_000),
    ("ldp-peer-gap", lambda n: _syslog("ldp peer" + " " * n + "!"), 12_000),
    ("ipsec-source-gap", lambda n: _syslog("ipsec source" + " " * n + "!"), 12_000),
    ("ipsec-local-ip-gap", lambda n: _syslog("ipsec local-ip" + " " * n + "!"), 12_000),
    ("ipsec-tunnel-id-gap", lambda n: _syslog("ipsec tunnel id" + " " * n + "!"), 12_000),
]
CASE_IDS = [c[0] for c in CASES]


@pytest.mark.parametrize("name, build, size", CASES, ids=CASE_IDS)
def test_adversarial_line_parses_in_milliseconds(name, build, size):
    line = build(size)
    _assert_fast(lambda: parse_line(line, "dflt"), 0.25, f"{name} ({len(line)} chars)")


_AT_12K = [c for c in CASES if c[2] == 12_000]


@pytest.mark.parametrize("name, build, size", _AT_12K, ids=[c[0] for c in _AT_12K])
def test_the_same_line_at_64_kib_is_still_fast(name, build, size):
    """The ingest cap is 64 KiB: the parse of a line that long must stay well under a second."""
    line = build(65_000)
    _assert_fast(lambda: parse_line(line, "dflt"), 1.0, f"{name} ({len(line)} chars)")


def test_cost_grows_linearly_with_the_line():
    def cost(n: int) -> float:
        line = "CEF:0|v|p|1|100|n|5|msg=x" + " " * n + "y"
        return min(_elapsed(lambda: parse_line(line, "dflt")) for _ in range(2))

    small, large = cost(8_000), cost(32_000)
    assert large < 12 * max(small, 0.01), f"4x the input cost {large / max(small, 1e-9):.1f}x"


# ── every keyword followed by a long run of whatever the regexes tolerate ──────────────────────────

_TRIGGERS = [
    "CEF:0|v|p|1|100|n|5|msg=x", "LEEF:1.0|v|p|1|e|msg=x", "LEEF:2.0|v|p|1|e|^|msg=x", "%Viptela-",
    "bfd-state-change", "devname=x type=y ", 'devname=x type=y subtype=vpn msg="phase',
    'devname=x type=y subtype=sdwan msg="sla', 'devname=x type=y subtype=sdwan msg=back',
    "bgp", "bgp neighbor", "bgp peer", "bgp session with", "bgp sent to", "bgp received from", "bgp BGP:",
    "bgp state", "bgp new state", "bgp changed state from", "bgp from", "bgp old state", "bgp External AS",
    "bgp remote-as", "bgp peer-as", "bgp AS", "bgp vrf", "bgp virtual-router", "bgp routing-instance",
    "bgp interface", "bgp ifName", "bgp vni", "bgp origin as", "bgp as-path", "bgp max-prefix",
    "bfd to", "bfd from", "bfd peer", "bfd remote", "bfd remote peer", "bfd nbr", "ospf neighbor",
    "ospf state", "ospf from", "isis adj to", "ldp peer", "ldp neighbor", "ipsec source",
    "ipsec local-ip", "ipsec local address", "ipsec tunnel id", "ipsec tunnel-name", "ipsec vpn name:",
    "ipsec VPN", "ike peer", "kmd_vpn", "vpn tunnel", "lacp", "link is", "oper state", "carrier",
    "changed state to", "%ADJCHANGE", "command", "UI_CMD", "command '", "vni", "VNI", "evpn vni", "state",
    "to", "from", "peer", "neighbor",
    "<13>Oct 22 10:15:01 h app: bgp state", "<13>Oct 22 10:15:01 h app: vni",
    "<13>Oct 22 10:15:01 h app: command", "<13>1 2026-10-22T10:15:01Z h app 1 m - bgp state",
    "Oct 22 10:15:01 h kmd: ipsec source", "<13>Oct 22 10:15:01 h ", "<13>1 2026-10-22T10:15:01Z h a b ",
    "<13>Oct 22 10:15:01 ", "<13>", '{"message":"', "{",
    "1,2026/10/20 08:16:30,013201001235,SYSTEM,routing,0,2026/10/20 08:16:30,,x,y,0,0,general,high,BGP peer ",
    "12:00:00.00 § ", "Oct 22 10:15:01 xr1 RP/0/RP0/CPU0:Oct 22 10:15:01.1 UTC: ",
    "Oct 22 10:15:01 h app[1", "Oct 22 ", "2026-10-22T10:15:01Z h ",
]
_FILLS = [" ", "\t", "a", "1", ":", "=", "-", ".", ",", "|", "\\", "[", "]", "/", "%", "_", '"', "A"]


def test_no_keyword_is_followed_by_a_run_that_costs_more_than_a_scan():
    size, slow = 5_000, []
    for trig in _TRIGGERS:
        for fill in _FILLS:
            for suffix in ("!", ""):
                line = trig + fill * size + suffix
                took = _elapsed(lambda: parse_line(line, "dflt"))
                if took > 0.1:
                    slow.append((round(took, 2), trig, fill, suffix))
    assert not slow, slow


# ── the connector path has no ingest cap: cap it before any parser regex runs ──────────────────────

def test_connector_message_is_capped_before_any_parser_regex_runs(monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_MAX_LINE_BYTES", "2000")
    for message in ("devname=x type=y " + "a" * 40_000, "%Viptela-" + "a" * 40_000,
                    "bfd to" + " " * 40_000 + "!"):
        ev = LogEvent("2026-10-22T10:15:01Z", "r1", "app", "info", message)
        out = []
        _assert_fast(lambda: out.append(ensure_structured(ev)), 0.25, f"{message[:12]!r}")
        assert out[0].attrs["parse_truncated"] == "1" and out[0].attrs["parser"].startswith("enrich")


def test_connector_message_under_the_cap_is_not_flagged(monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_MAX_LINE_BYTES", "2000")
    out = ensure_structured(LogEvent("", "r1", "app", "info", "bgp peer 192.0.2.1 down"))
    assert "parse_truncated" not in out.attrs and out.peer_ip == "192.0.2.1"
    # the ingest rule: 0 means unlimited
    monkeypatch.setenv("AI_LOG_ANALYZER_MAX_LINE_BYTES", "0")
    out = ensure_structured(LogEvent("", "r1", "app", "info", "bgp peer 192.0.2.1 down " + "x" * 5000))
    assert "parse_truncated" not in out.attrs


def test_connector_message_keeps_its_text_but_is_flagged_past_the_default_cap():
    message = "bgp peer 192.0.2.1 down " + "x" * 70_000
    out = ensure_structured(LogEvent("", "r1", "app", "info", message))
    assert out.attrs["parse_truncated"] == "1" and out.message == message and out.peer_ip == "192.0.2.1"


def test_fortios_classification_flags_text_it_did_not_fully_scan():
    long_msg = "x" * 5000 + " sla failed"
    ev = parse_line(f'devname=x type=y subtype=sdwan msg="{long_msg}"', "dflt")
    assert ev.event_type == "sdwan_sla" and ev.attrs.get("classify_truncated") == "1"
    ev = parse_line('devname=x type=y subtype=sdwan msg="sla failed"', "dflt")
    assert ev.state == "down" and "classify_truncated" not in ev.attrs


# ── classifier: the CLI-audit rule and a whole-table sweep with whitespace/digit runs ──────────────

def test_cli_audit_rule_does_not_backtrack_on_a_4_kib_run_of_spaces():
    rule = classifier._COMPILED[0][0]
    for fill in (" ", "\t"):
        text = "command" + fill * 4000
        _assert_fast(lambda: rule.search(text), 0.02, "first KB rule")
    ev = LogEvent("2026-05-09T10:00:00", "edge1", "app", "info", "command" + " " * 4000)
    _assert_fast(lambda: classify_events([ev]), 0.05, "classify_events")


@pytest.mark.parametrize("message, hit", [
    ("command 'show bgp neighbor | match down'", True),
    ("command: 'show interfaces'", True),
    ("command =  \"configure terminal\"", True),
    ('command   :   "show version"', True),
    ("command 'rollback'", False),
    ("command show version", False),
    ("commands: 'show version'", False),
])
def test_cli_audit_rule_still_matches_what_it_matched(message, hit):
    rule = classifier._COMPILED[0][0]
    assert bool(rule.search(message)) is hit


def test_every_builtin_pattern_is_bounded_on_whitespace_and_digit_runs():
    size, slow = classifier._MAX_MATCH_CHARS, []
    for (src, *_), (compiled, *_rest) in zip(classifier._KB_PATTERNS, classifier._COMPILED):
        toks = list(dict.fromkeys(re.findall(r"[a-z][a-z0-9_%\-]{2,}", src)))[:20] or ["x"]
        worst = 0.0
        for tok in toks:
            for fill in (" ", "\t", ":", "-", "1", "a", "_", "."):
                for suffix in ("!", ""):
                    text = (tok + fill * size)[:size - 1] + suffix
                    worst = max(worst, _elapsed(lambda: compiled.search(text)))
        if worst > 0.05:
            slow.append((round(worst, 3), src[:80]))
    assert not slow, slow


# ── equivalence: the rewritten expressions find exactly what the old ones found ────────────────────

_OLD_EXT = re.compile(r"(?<![\w.])(?P<k>[A-Za-z][\w.]*)=(?P<v>.*?)(?=\s+[A-Za-z][\w.]*=|\s*$)", re.DOTALL)
_OLD_FORTI_KV = re.compile(r'(?P<k>[A-Za-z_][\w-]*)=(?P<v>"(?:[^"\\]|\\.)*"|\S*)')
_OLD_SDWAN_KV = re.compile(r'(?P<k>[a-z][\w-]*):(?P<v>"[^"]*"|[^\s,]+)')
_IP = entities._IP
_IPS = ["10.0.0.1", "::1", "2001:db8::2", "::ffff:10.1.1.2", "x", "1.2.3"]
# name -> (new regex, the pre-fix regex, keywords that start a match, what follows them)
_OLD_ENTITY = {
    "generic_peer": (entities._GENERIC_PEER_RES[0], re.compile(
        rf"\b(?:neighbou?r|peer|nbr|to|from|remote(?:[- ](?:peer|gateway|address|ip))?)\s*:?\s+(?P<ip>{_IP})",
        re.IGNORECASE),
        ["peer", "to", "from", "nbr", "neighbor", "neighbour", "remote", "remote peer", "remote-ip"], _IPS),
    "vni": (entities._VNI_RE, re.compile(
        r"\b(?:VNI|vni|VNID|vnid|l2vni|l3vni)\s*[:=]?\s*(?P<vni>\d{1,8})\b"),
        ["vni", "VNI", "VNID", "vnid", "l2vni", "l3vni"], ["100", "99999999", "123456789", "x", "7 ", "1a"]),
    "state_to": (entities._STATE_TO_RE, re.compile(
        r"(?:changed state from|from|old state)\s+(?P<old>\w+)(?:\s+(?:to|event \w+ new state)\s+|\s*->\s*)(?P<new>\w+)"
        r"|(?:new[- ]state|state changed to|state)\s*[:=]?\s*(?P<new2>\w+)"
        r"|->\s*(?P<new3>\w+)", re.IGNORECASE),
        ["state", "new state", "new-state", "state changed to", "from", "old state", "changed state from"],
        ["up", "Idle", "a -> b", "a to b", "a event e new state b", "Established", "->c", "x"]),
    "local_ip": (entities._LOCAL_IP_RE, re.compile(
        rf"\b(?:Local-ip|local[- ]address|local ip|source)\s*[:=]?\s*(?P<ip>{_IP})", re.IGNORECASE),
        ["Local-ip", "local address", "local-address", "local ip", "source"], _IPS),
    "kmd_tunnel": (entities._KMD_TUNNEL_RE, re.compile(
        r"\bvpn name:\s*(?P<t>[^,]+)|\bVPN\s+(?P<t2>\S+)\s+from\b|\btunnel[- ](?:name|id)\s*[:=]?\s*(?P<t3>[\w.\-]+)",
        re.IGNORECASE),
        ["tunnel id", "tunnel-name", "tunnel name", "vpn name:", "VPN", "vpn"],
        ["abc", "x-1", "a from", "t1, x", "  y", "t.2 from b"]),
}
_SEPS = ["", " ", "  ", "\t", ":", " : ", "=", ": ", " :", "=  ", "\n", " \t:\t", "::", ",", "-"]
_EXT_TOKENS = ["a=", "msg=", "k.j=", "x", "y z", " ", "  ", "\t", "\n", "=", "==", "\\=", ".", "_", "é", "1",
               "dvc=", "b=c", ",", "|", "\\", "z=", "A1.b2=", " \n ", "a b=", "é=", "-"]
_FORTI_TOKENS = ["a=", 'b="x y"', '"', "\\", " ", "k-1=", "_x=", "1a=", "-b=", "é=", "x", "=", 'c="q\\"r"',
                 "devname=", "9", "--", "a-", "=\"", "\t", "é"]
_SDWAN_TOKENS = ["a:", 'b:"x y"', "cd:ef", " ", ",", "1", "a-b:c", ":", "é:", "A:b", "x", "-", '"', "k:v,",
                 "9:", "-z:", "é", "\t"]
_ENTITY_TOKENS = ["peer", "to", "from", "vni", "VNI", "VNID", "state", "new state", "new-state", ":", "=",
                  " ", "\t", "  ", "10.0.0.1", "::1", "2001:db8::2", "up", "Down", "100", "source",
                  "Local-ip", "local address", "tunnel id", "tunnel-name", "tunnel name:", "vpn name:",
                  "VPN", "vpn1", "x", "->", "changed state from", "old state", "event e new state", "remote",
                  "remote peer", "neighbor", "Established", "to ", "l2vni", "\n", "é"]


def _random_texts(tokens, rng, count=3000, longest=12):
    for _ in range(count):
        yield "".join(rng.choice(tokens) for _ in range(rng.randint(1, longest)))


def test_ext_pairs_equal_the_old_lazy_regex():
    rng = random.Random(11)
    seen = 0
    for text in _random_texts(_EXT_TOKENS, rng, 6000):
        old = [(m.group("k"), m.group("v"), m.group(0)) for m in _OLD_EXT.finditer(text)]
        assert structured._ext_pairs(text) == old, repr(text)
        seen += bool(old)
    assert seen > 2000   # the generator produces real extensions, not just junk


def test_fortios_kv_scanner_equals_the_old_regex():
    rng = random.Random(12)
    for text in _random_texts(_FORTI_TOKENS, rng, 6000):
        old = [(m.start("k"), m.end(), m.group("k"), m.group("v")) for m in _OLD_FORTI_KV.finditer(text)]
        new = [(m.start("k"), m.end(), m.group("k"), m.group("v")) for m in fortinet._KV_RE.finditer(text)]
        assert new == old, repr(text)


def test_sdwan_kv_scanner_equals_the_old_regex():
    rng = random.Random(13)
    for text in _random_texts(_SDWAN_TOKENS, rng, 6000):
        old = [(m.start("k"), m.end(), m.group("k"), m.group("v")) for m in _OLD_SDWAN_KV.finditer(text)]
        new = [(m.start("k"), m.end(), m.group("k"), m.group("v")) for m in sdwan._KV_RE.finditer(text)]
        assert new == old, repr(text)


@pytest.mark.parametrize("name", sorted(_OLD_ENTITY))
def test_entity_regexes_find_what_the_old_ones_found(name):
    new_re, old_re, keywords, values = _OLD_ENTITY[name]
    rng = random.Random(14)
    hits = 0
    for i in range(8000):
        if i % 2:   # keyword, separator, value: the shapes the regexes exist for, with the separator varied
            text = (rng.choice(["", " ", "x ", "a=b "]) + rng.choice(keywords) + rng.choice(_SEPS)
                    + rng.choice(values) + rng.choice(["", " ", " tail", "\n"]))
        else:
            text = next(_random_texts(_ENTITY_TOKENS, rng, 1))
        old = [(m.span(), m.groupdict()) for m in old_re.finditer(text)]
        new = [(m.span(), m.groupdict()) for m in new_re.finditer(text)]
        assert new == old, repr(text)
        hits += bool(old)
    assert hits > 500


@pytest.mark.parametrize("text, phase", [
    ("ike phase 2 negotiation", "ike_phase2"), ("ike phase-2 negotiation", "ike_phase2"),
    ("ike phase - 2 negotiation", "ike_phase2"), ("ike phase  -  2 negotiation", "ike_phase2"),
    ("ike phase2 negotiation", "ike_phase2"), ("ike phase 1 negotiation", "ike_phase1"),
    ("ike phase -1 negotiation", "ike_phase1"), ("ike phase- 1 negotiation", "ike_phase1"),
    ("ike phase x negotiation", "ipsec_tunnel"),
])
def test_fortios_phase_wording_still_classifies(text, phase):
    ev = parse_line(f'devname=x type=y subtype=vpn msg="{text}"', "dflt")
    assert ev.event_type == phase


# Well-formed records parse to the same fields they always did (expected values taken from the old code).
_WELL_FORMED = [
    (r"CEF:0|Sec\|Co|FW\\1|1.0|100|Port scan|7|src=192.0.2.1 dst=198.51.100.2 msg=a\=b c=d rt=1792664101000 "
     r"dvchost=fw1 cs1Label=x y z=1",
     ("2026-10-22T10:15:01Z", "fw1", "FW\\1", "err", "Port scan: a\\=b", "", "")),
    ("<189>Oct 22 10:15:01 collector CEF:0|V|P|1|100|BGP|3|msg=neighbor 192.0.2.7 Down  dvc=edge7   ",
     ("Oct 22 10:15:01", "edge7", "P", "info", "BGP: neighbor 192.0.2.7 Down", "192.0.2.7", "down")),
    ("CEF:0|V|P|1|100|Empty|3|a= msg=hello world  b=2 c.d=3.4 e_f=g==h",
     ("", "dflt", "P", "info", "Empty: hello world", "", "")),
    ("CEF:0|V|P|1|100|Multi|3|msg=line one\nline two  x=1",
     ("", "dflt", "P", "info", "Multi: line one\nline two", "", "")),
    ("CEF:0|V|P|1|100|Lead|3|   junk msg=ok  ", ("", "dflt", "P", "info", "Lead: ok", "", "")),
    ("LEEF:1.0|V|P|1|E1|devTime=2026-10-22T10:15:01Z\tdevName=sw1\tmsg=link down Ethernet1\tsev=7",
     ("2026-10-22T10:15:01Z", "sw1", "P", "err", "E1: link down Ethernet1", "", "down")),
    ("LEEF:2.0|V|P|1|ev|^|devName=h^msg=link down Ethernet1^sev=3",
     ("", "h", "P", "info", "ev: link down Ethernet1", "", "down")),
    ("LEEF:2.0|V|P|1|ev|x5e|devName=h^msg=peer 192.0.2.4 down",
     ("", "h", "P", "info", "ev: peer 192.0.2.4 down", "", "")),
    ("LEEF:1.0|V|P|1|e|devName=h msg=bgp peer 192.0.2.1 down sev=5",
     ("", "h", "P", "warning", "e: bgp peer 192.0.2.1 down", "192.0.2.1", "down")),
    ("LEEF:1.0|V|P|1|e|devName=h   msg=bgp peer 192.0.2.1  down   sev=5  ",
     ("", "h", "P", "warning", "e: bgp peer 192.0.2.1  down", "192.0.2.1", "down")),
    (r"LEEF:1.0|V\|W|P|1|e|devName=h msg=a\=b  c d=e", ("", "h", "P", "info", "e: a\\=b  c", "", "")),
]


@pytest.mark.parametrize("line, expected", _WELL_FORMED, ids=[f"sample{i}" for i in range(len(_WELL_FORMED))])
def test_well_formed_cef_and_leef_records_keep_their_fields(line, expected):
    ev = parse_line(line, "dflt")
    assert (ev.timestamp, ev.hostname, ev.appname, ev.severity_raw, ev.message, ev.peer_ip, ev.state) == expected


def test_escaped_header_pipe_and_extension_equals_survive():
    ev = parse_line(_WELL_FORMED[0][0], "dflt")
    assert ev.attrs["cef_vendor"] == "Sec|Co" and ev.attrs["cef_signature"] == "100"
    assert structured._ext_pairs(r"msg=a\=b c=d") == [("msg", r"a\=b", r"msg=a\=b"), ("c", "d", "c=d")]
    assert structured._ext_pairs("a=b=c d=e,f=g") == [("a", "b=c", "a=b=c"), ("d", "e,f=g", "d=e,f=g")]
    assert structured._ext_pairs("") == [] and structured._ext_pairs("   no keys here ") == []


# ── a lint for the shape that caused most of this: adjacent repeats that can take the same characters ──

_MAXREPEAT = _sre_constants.MAXREPEAT
_PROBE = [chr(i) for i in range(0x250)] + [" ", "　", "٣", " "]


def _in_category(name: str, ch: str) -> bool:
    base_name = name.replace("CATEGORY_", "").replace("NOT_", "")
    if base_name == "SPACE":
        hit = ch.isspace()
    elif base_name == "DIGIT":
        hit = ch.isdecimal()
    elif base_name == "WORD":
        hit = ch.isalnum() or ch == "_"
    else:
        return False
    return not hit if "NOT_" in name else hit


def _chars(node) -> set[str] | None:
    """Characters (over a probe alphabet) a one-character node can match; None for anything else."""
    op, av = node
    name = op.name
    if name == "LITERAL":
        return {chr(av)}
    if name == "NOT_LITERAL":
        return set(_PROBE) - {chr(av)}
    if name == "ANY":
        return set(_PROBE) - {"\n"}
    if name == "CATEGORY":
        return {c for c in _PROBE if _in_category(av.name, c)}
    if name == "IN":
        taken: set[str] = set()
        negate = False
        for iop, iav in av:
            if iop.name == "NEGATE":
                negate = True
            elif iop.name == "LITERAL":
                taken.add(chr(iav))
            elif iop.name == "RANGE":
                taken |= {c for c in _PROBE if iav[0] <= ord(c) <= iav[1]}
            elif iop.name == "CATEGORY":
                taken |= {c for c in _PROBE if _in_category(iav.name, c)}
        return set(_PROBE) - taken if negate else taken
    return None


def _adjacent_overlaps(parsed, found: list[str]) -> None:
    """Append a note for each pair of unbounded repeats that can take the same characters and sit
    next to each other (only optional items between): ``\\s*[:=]?\\s*``, ``\\s*:?\\s+``, ``\\d+\\w*``."""
    prev: set[str] | None = None
    for op, av in parsed:
        name = op.name
        if name in ("MAX_REPEAT", "MIN_REPEAT"):
            low, high, body = av
            chars = _chars(body[0]) if len(body) == 1 else None
            if chars is None:
                _adjacent_overlaps(body, found)
                prev = prev if low == 0 else None
            elif high == _MAXREPEAT:
                if prev is not None and prev & chars:
                    found.append("adjacent repeats overlap on " + repr(sorted(prev & chars)[:4]))
                prev = chars | prev if (low == 0 and prev) else chars
            elif low == 0:
                pass   # an optional single item between two repeats does not separate them
            else:
                prev = None
        elif name in ("ASSERT", "ASSERT_NOT"):
            _adjacent_overlaps(av[1], found)
        elif name == "AT":
            pass
        elif name == "SUBPATTERN":
            _adjacent_overlaps(av[3], found)
            prev = None
        elif name == "BRANCH":
            for alt in av[1]:
                _adjacent_overlaps(alt, found)
            prev = None
        else:
            prev = None


def _overlap_notes(pattern: str) -> list[str]:
    found: list[str] = []
    _adjacent_overlaps(_sre_parse.parse(pattern), found)
    return found


@pytest.mark.parametrize("pattern", [r"\s*[:=]?\s*x", r"\s*:?\s+x", r"phase\s*-?\s*2", r"\d+\d*", r"a\s+\s*b",
                                     r"\w+[a-z]+", r"x.*.*y"])
def test_the_lint_flags_the_bad_shapes(pattern):
    assert _overlap_notes(pattern)


@pytest.mark.parametrize("pattern", [r"\s*(?:[:=]\s*)?x", r"(?:\s+|\s*:\s+)x", r"\s+\S+\s+", r"\d+(?:[/.:]\d+)*",
                                     r"a\s*b\s*c", r"\w+\s*=\s*\w+", r"(?:\s+is\s*)?x\s*"])
def test_the_lint_passes_unambiguous_shapes(pattern):
    assert not _overlap_notes(pattern)


def _inline_patterns(path: str) -> list[str]:
    out = []
    for node in ast.walk(ast.parse(Path(path).read_text(encoding="utf-8"))):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "re"
                and node.func.attr in ("search", "match", "fullmatch", "sub", "split", "findall", "finditer",
                                       "compile")
                and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
            out.append(node.args[0].value)
    return out


def _module_patterns(module) -> list[str]:
    out = []
    for value in vars(module).values():
        items = value if isinstance(value, (tuple, list)) else [value]
        out += [v.pattern for v in items if isinstance(v, re.Pattern)]
    return out


# Overlapping on purpose: nothing follows the second repeat, so a match never has to give characters back.
_ALLOWED = {r"(?i)\b(user ?name|user|login user)\s*:\s*[^,;]+"}


def test_no_parser_or_classifier_regex_has_adjacent_overlapping_repeats():
    # the KB is linted as the classifier compiles it: ``.*`` already bounded to ``.{0,300}``
    patterns: list[tuple[str, str]] = [("classifier KB", classifier._bound_gaps(p[0]))
                                       for p in classifier._KB_PATTERNS]
    for module in (base, entities, fortinet, generic, panos, sdwan, structured, timeutil, classifier):
        patterns += [(module.__name__, p) for p in _module_patterns(module)]
        patterns += [(module.__name__, p) for p in _inline_patterns(module.__file__)]
    assert len(patterns) > 150
    bad = [(where, pattern[:90], notes) for where, pattern in patterns
           if pattern not in _ALLOWED and (notes := _overlap_notes(pattern))]
    assert not bad, bad
