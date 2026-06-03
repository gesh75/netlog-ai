"""Tests for DCN _AI_KB RCA enrichment merged into kb.py (Item 2)."""
from __future__ import annotations

import pytest

from ai_log_analyzer import kb


_PHASE_NAMES = {"Diagnose", "Mitigate", "Remediate", "Verify", "Optimize"}
_RCA_KEYS = {"root_cause", "risk", "resolution_steps", "cli_junos", "cli_eos", "timeline"}


@pytest.mark.unit
def test_vpn_category_exists_and_phased() -> None:
    """vpn category must exist and every non-default entry must carry 5 phases."""
    e = kb.lookup("vpn", "ipsec tunnel down")
    assert "phases" in e, "vpn entry must contain 'phases'"
    names = {p["name"] for p in e["phases"]}
    assert names.issuperset(_PHASE_NAMES), f"vpn entry missing phases: {_PHASE_NAMES - names}"


@pytest.mark.unit
def test_redundancy_category_exists_and_phased() -> None:
    """redundancy category must exist and carry all 5 phases."""
    e = kb.lookup("redundancy", "vrrp master change")
    assert "phases" in e, "redundancy entry must contain 'phases'"
    names = {p["name"] for p in e["phases"]}
    assert names.issuperset(_PHASE_NAMES), f"redundancy entry missing phases: {_PHASE_NAMES - names}"


@pytest.mark.unit
def test_hardware_fpc_subpattern_matches() -> None:
    """lookup('hardware', 'fpc0 offline crash') must resolve to FPC entry with RCA mentioning FPC/line card."""
    e = kb.lookup("hardware", "fpc0 offline crash")
    assert "rca" in e, "FPC hardware entry must have an 'rca' block"
    root = e["rca"]["root_cause"].upper()
    assert "FPC" in root or "LINE CARD" in root, (
        f"rca.root_cause should mention FPC or line card, got: {e['rca']['root_cause']!r}"
    )


@pytest.mark.unit
def test_hardware_chassis_subpattern_matches() -> None:
    """lookup('hardware', 'chassis alarm power supply fail') must resolve to chassis entry."""
    e = kb.lookup("hardware", "chassis alarm power supply fail")
    assert "rca" in e, "Chassis hardware entry must have an 'rca' block"
    root = e["rca"]["root_cause"].lower()
    # Should mention PSU, fan, or temperature
    assert any(kw in root for kw in ("psu", "fan", "power supply", "temperature", "thermal")), (
        f"rca.root_cause should mention PSU/fan/temperature for chassis entry, got: {root!r}"
    )


@pytest.mark.unit
def test_rca_block_has_dcn_fields() -> None:
    """BGP routing entry must expose all 6 DCN RCA fields, with non-empty lists."""
    e = kb.lookup("routing", "bgp peer down")
    assert "rca" in e, "BGP entry must have an 'rca' block"
    rca = e["rca"]
    assert _RCA_KEYS == set(rca.keys()), (
        f"rca must have exactly {_RCA_KEYS}, got {set(rca.keys())}"
    )
    assert isinstance(rca["resolution_steps"], list) and len(rca["resolution_steps"]) > 0, \
        "rca.resolution_steps must be a non-empty list"
    assert isinstance(rca["cli_junos"], list) and len(rca["cli_junos"]) > 0, \
        "rca.cli_junos must be a non-empty list"
    assert isinstance(rca["cli_eos"], list) and len(rca["cli_eos"]) > 0, \
        "rca.cli_eos must be a non-empty list"


@pytest.mark.unit
def test_rca_does_not_break_phases() -> None:
    """Every entry that has an 'rca' block must also still have 'phases' with 5 phase names."""
    seen: set[int] = set()
    for cat, entries in kb.KB.items():
        for key, entry in entries.items():
            if id(entry) in seen:
                continue
            seen.add(id(entry))
            if "rca" not in entry:
                continue
            assert "phases" in entry, (
                f"{cat}.{key}: entry has 'rca' but is missing 'phases'"
            )
            names = {p["name"] for p in entry["phases"]}
            assert names.issuperset(_PHASE_NAMES), (
                f"{cat}.{key}: rca entry missing phases — got {names}"
            )


@pytest.mark.unit
def test_resolution_steps_are_strings() -> None:
    """All resolution_steps in the BGP RCA block must be plain strings."""
    e = kb.lookup("routing", "bgp peer down")
    rca = e["rca"]
    for step in rca["resolution_steps"]:
        assert isinstance(step, str), f"resolution_steps must contain strings, got {type(step)}: {step!r}"
