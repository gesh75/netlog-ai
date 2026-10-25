"""Robustness: the parsers never raise and never hang on arbitrary text.

A seeded random corpus always runs; the hypothesis variants run when the
library is installed (``pytest.importorskip``).
"""
from __future__ import annotations

import random
import time

import pytest

from ai_log_analyzer.adapters.file import parse_lines
from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.parsers import parse_line

pytestmark = pytest.mark.unit

_SEEDS = [
    "<189>Oct 22 10:15:01 leaf1 bgpd[12]: %ADJCHANGE: neighbor 10.1.1.2 in vrf default Down",
    "2026-10-22T10:15:01.123456+00:00 leaf1 bgpd[12]: peer:2001:db8::2 went down",
    "Oct 22 10:15:01.123456 leaf1 NOTICE bgp#bgpd[12]: neighbor ::ffff:10.1.1.2 Down",
    "<186>Oct 22 2026 10:15:01 UTC r1: %SYS-2-MALLOCFAIL: x",
    "Oct 22 10:15:01 xr1 RP/0/RP0/CPU0:Oct 22 10:15:01.1 UTC: bgp[1]: %ROUTING-BGP-5-ADJCHANGE : neighbor 1.2.3.4 Up",
    '{"message": "peer 10.1.1.2 down", "host": "leaf1", "time": 1792664101}',
    "CEF:0|a|b|1|2|name|7|msg=x dvchost=h rt=1792664101000",
    "LEEF:2.0|a|b|1|ev|^|devName=h^msg=link down Ethernet1",
    "1,2026/10/20 08:16:30,013201001235,SYSTEM,routing,0,2026/10/20 08:16:30,,x,y,0,0,general,high,BGP peer 1.1.1.1,7,0x0",
    'date=2026-10-20 time=07:01:02 devname="FGT" logid="1" type="event" subtype="vpn" level="error" msg="x"',
    "\x1b[32mOK\x1b[0m Oct 22 10:15:01 r1 bgpd: neighbor 10.1.1.2 Up (Established->Idle)",
]
_ALPHABET = list("<>[]{}()|=:;,.%#/\\'\" \t-_@*+") + list("abcdefABCDEF0123456789") + ["\x1b[", "ï¿½", "�", "é"]


def _check(line: str) -> None:
    ev = parse_line(line, "dflt")
    assert ev is None or isinstance(ev, LogEvent)
    if ev is not None:
        assert isinstance(ev.message, str) and isinstance(ev.hostname, str) and isinstance(ev.timestamp, str)


def _mutate(rng: random.Random, text: str) -> str:
    out = list(text)
    for _ in range(rng.randint(1, 6)):
        op = rng.random()
        pos = rng.randrange(len(out) + 1)
        if op < 0.4 and out:
            del out[min(pos, len(out) - 1)]
        elif op < 0.8:
            out.insert(pos, rng.choice(_ALPHABET))
        elif out:
            out = out[:pos] + out[pos:][::-1]
    return "".join(out)


def test_seeded_random_and_mutated_lines_never_raise():
    rng = random.Random(7)
    for _ in range(1500):
        _check("".join(rng.choice(_ALPHABET) for _ in range(rng.randint(0, 120))))
    for seed in _SEEDS:
        _check(seed)
        for _ in range(150):
            _check(_mutate(rng, seed))


def test_parse_lines_survives_bytes_and_non_utf8_junk():
    junk = [bytes(random.Random(i).randrange(256) for _ in range(200)) for i in range(50)]
    junk += [b"\xff\xfe<189>Oct 22 10:15:01 r1 bgpd: peer 10.1.1.2 down\x00\x1b[31m", b"", b"\r\n", b"   "]
    for ev in parse_lines(junk, "dflt"):
        assert isinstance(ev, LogEvent)


@pytest.mark.parametrize("make", [
    lambda n: "A" * n,
    lambda n: "<189>Oct 22 10:15:01 r1 " + "a" * n,
    lambda n: "<189>Oct 22 10:15:01 r1 bgpd[1]: neighbor " + "1." * (n // 2),
    lambda n: "Oct 22 10:15:01 " + "x:" * (n // 2),
    lambda n: '{"message": "' + "=" * n + '"}',
    lambda n: "CEF:0|" + "a|" * (n // 2),
    lambda n: "CEF:0|a|b|1|2|n|5|" + "k=" * (n // 2),
    lambda n: "LEEF:1.0|a|b|1|e|" + "k=v\t" * (n // 4),
    lambda n: "bgp " + "AS " * (n // 3),
    lambda n: "peer " + "::" * (n // 2),
    lambda n: "\x1b[" + "3;" * (n // 2),
    lambda n: ("Oct 22 10:15:01 r1 " + "é") * (n // 22),
])
def test_70kb_lines_parse_quickly(make):
    line = make(70_000)
    t0 = time.perf_counter()
    _check(line)
    assert time.perf_counter() - t0 < 5.0   # generous: catches quadratic regex backtracking, not speed


def test_hypothesis_parse_line_never_raises():
    hypothesis = pytest.importorskip("hypothesis")
    st = pytest.importorskip("hypothesis.strategies")

    @hypothesis.settings(max_examples=300, deadline=None)
    @hypothesis.given(st.text(max_size=400))
    def run(text: str) -> None:
        _check(text)

    run()


def test_hypothesis_structured_mutations_never_raise():
    hypothesis = pytest.importorskip("hypothesis")
    st = pytest.importorskip("hypothesis.strategies")

    @hypothesis.settings(max_examples=300, deadline=None)
    @hypothesis.given(st.sampled_from(_SEEDS), st.text(max_size=60), st.integers(min_value=0, max_value=200))
    def run(seed: str, noise: str, cut: int) -> None:
        _check(seed[:cut] + noise + seed[cut:])

    run()
