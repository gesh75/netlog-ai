"""Config-drift correlation is bounded: findings x changed lines used to be unbounded regex work."""
from __future__ import annotations

import random
import time

import pytest

from ai_log_analyzer import analytics
from ai_log_analyzer.analytics import Finding, correlate_config_drift
from ai_log_analyzer.diff import ConfigDiff

pytestmark = pytest.mark.unit


_GENERIC = {"session", "bgp", "ospf", "bfd", "lacp"}


def _old_best_drift_hit(finding, lines, hostname):
    """The pre-fix per-pair implementation, kept verbatim as the reference."""
    best = None
    for line in lines:
        blob = f"{finding.message}\n{line}"
        keywords = [name for name, pat in analytics._DRIFT_GROUPS
                    if pat.search(blob) and pat.search(finding.message) and pat.search(line)]
        entity = analytics._entity_id(finding.message)
        if entity.lower() in line.lower() and entity.lower() not in {k.lower() for k in keywords}:
            keywords = [*keywords, entity]
        if not keywords:
            continue
        score = 0.45
        if len(keywords) > 1:
            score += 0.1
        if entity.lower() not in _GENERIC and entity.lower() in line.lower():
            score += 0.25
        device = finding.device.lower()
        if device and (device in line.lower() or hostname.lower() == device):
            score += 0.2
        hit = analytics.ConfigDriftHit(
            device=finding.device, finding_message=finding.message, changed_line=line,
            confidence=round(min(1.0, score), 4),
            explanation=(f"Changed line shares {', '.join(keywords)} with a {finding.severity} finding "
                         f"on {finding.device or 'unknown'}."),
            matched_keywords=keywords)
        if best is None or hit.confidence > best.confidence:
            best = hit
    return best


def test_config_drift_caps_findings_and_changed_lines(monkeypatch):
    # Small caps keep this fast; raising=False lets the unfixed code run (and fail) instead of erroring.
    monkeypatch.setattr(analytics, "_MAX_DRIFT_FINDINGS", 40, raising=False)
    monkeypatch.setattr(analytics, "_MAX_DRIFT_LINES", 30, raising=False)
    findings = [Finding("", "high", "bgp down") for _ in range(300)]
    lines = [f"router bgp {65000 + i}" for i in range(300)]
    report = correlate_config_drift(ConfigDiff(added=lines), findings)
    assert report.correlated_count <= 40
    assert report.truncated["findings"] == {"seen": 300, "used": 40, "dropped": 260}
    assert report.truncated["changed_lines"] == {"seen": 300, "used": 30, "dropped": 270}


def test_config_drift_stays_fast_at_the_real_caps():
    findings = [Finding("", "high", "bgp down") for _ in range(2_500)]
    lines = [f"router bgp {65000 + i}" for i in range(2_500)]
    t0 = time.perf_counter()
    report = correlate_config_drift(ConfigDiff(added=lines), findings)
    elapsed = time.perf_counter() - t0
    assert elapsed < 5.0, f"2500 findings x 2500 lines took {elapsed:.1f}s"
    assert report.truncated and report.correlated_count <= 1_000


def test_config_drift_results_are_unchanged_below_the_caps():
    rng = random.Random(11)
    topics = ["bgp neighbor 192.0.2.{n} down", "Ethernet{n} mtu mismatch", "vlan {n} flapping",
              "ospf area 0 adjacency lost on Ethernet{n}", "acl BLOCK-{n} denied", "snmp poll ok", "shutdown on Ethernet{n}"]
    cfg = ["router bgp 65000", " neighbor 192.0.2.{n} remote-as 65001", "interface Ethernet{n}", " mtu 9000",
           " shutdown", "vlan {n}", "ip access-list BLOCK-{n}", "router ospf 1", " area 0", "hostname leaf{n}"]
    findings = [Finding(rng.choice(["leaf1", "leaf2", ""]), rng.choice(["high", "info"]),
                        rng.choice(topics).format(n=rng.randint(1, 4))) for _ in range(60)]
    lines = [rng.choice(cfg).format(n=rng.randint(1, 4)) for _ in range(80)]
    for hostname in ("", "leaf1"):
        got = correlate_config_drift(ConfigDiff(added=lines, hostname=hostname), findings)
        want = [h for h in (_old_best_drift_hit(f, lines, hostname) for f in findings) if h is not None]
        want.sort(key=lambda h: (-h.confidence, h.device))
        assert [h.to_dict() for h in got.hits] == [h.to_dict() for h in want]
        assert got.correlated_count == len(want) and got.truncated == {}
    assert want, "the fixture must produce hits or the comparison proves nothing"


def test_config_drift_reports_an_approximate_diff():
    before = "\n".join(f"line-{i:06d}" for i in range(10_001))   # over diff.MAX_DIFF_LINES
    after = "\n".join(f"router bgp {i}" for i in range(10_001))
    report = correlate_config_drift(ConfigDiff(before=before, after=after), [Finding("", "high", "bgp down")])
    assert report.truncated["config_diff"] == {"approximate": True}
    assert report.truncated["changed_lines"]["seen"] == 20_002
