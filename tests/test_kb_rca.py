"""Tests for RCA enrichment merged into kb.py."""
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
def test_rca_block_has_required_fields() -> None:
    """BGP routing entry must expose all 6 RCA fields, with non-empty lists."""
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


@pytest.mark.unit
def test_optical_transceiver_degradation_rca() -> None:
    """Optical degradation entry must identify low Rx power + rising CRC and prescribe transceiver checks."""
    e = kb.lookup("interface", "optical transceiver degradation low rx power rising fcs crc errors")
    assert "rca" in e, "Optical degradation must have an 'rca' block"
    rca = e["rca"]
    root = rca["root_cause"].lower()
    assert "optical" in root or "transceiver" in root or "crc" in root, (
        f"Unexpected root cause: {rca['root_cause']}"
    )
    assert any("clean" in s.lower() and "crc" in s.lower() for s in rca["resolution_steps"]), (
        "Resolution steps must differentiate low-power CRC degradation from clean dark-fiber cut"
    )
    assert any("optics" in c.lower() for c in rca["cli_junos"])
    assert any("transceiver" in c.lower() for c in rca["cli_eos"])


@pytest.mark.unit
def test_optical_clean_dark_fiber_shutdown_rca() -> None:
    """Clean dark-fiber cut entry must identify hard Rx LOS with 0 CRC errors."""
    e = kb.lookup("interface", "clean dark-fiber cut hard rx los zero crc")
    assert "rca" in e, "Clean shutdown entry must have an 'rca' block"
    rca = e["rca"]
    root = rca["root_cause"].lower()
    assert "dark" in root or "fiber" in root or "shutdown" in root, (
        f"Unexpected root cause: {rca['root_cause']}"
    )
    assert any("otdr" in s.lower() or "provider" in s.lower() for s in rca["resolution_steps"])


@pytest.mark.unit
def test_control_plane_microburst_congestion_copp_rca() -> None:
    """Microburst congestion entry must prescribe strict-priority queue 6/7 or CoPP boost."""
    e = kb.lookup("routing", "control-plane microburst congestion output queue discard bfd drop")
    assert "rca" in e, "Microburst congestion entry must have an 'rca' block"
    rca = e["rca"]
    root = rca["root_cause"].lower()
    assert "buffer" in root or "copp" in root or "queue" in root or "burst" in root, (
        f"Unexpected root cause: {rca['root_cause']}"
    )
    assert any("strict-priority" in s.lower() or "copp" in s.lower() for s in rca["resolution_steps"])
    assert any("queue" in c.lower() or "class-of-service" in c.lower() for c in rca["cli_junos"])
    assert any("queue" in c.lower() or "qos" in c.lower() for c in rca["cli_eos"])

    # Also verifiable under qos category
    e_qos = kb.lookup("qos", "output queue discards bfd timeout")
    assert e_qos.get("match") == e.get("match")


@pytest.mark.unit
def test_evpn_underlay_to_overlay_failure_cascade_rca() -> None:
    """EVPN cascade entry must emphasize suppressing overlay symptoms for underlay root causes."""
    e = kb.lookup("evpn", "underlay failure cascade suppressing overlay route withdrawals")
    assert "rca" in e, "EVPN cascade entry must have an 'rca' block"
    rca = e["rca"]
    root = rca["root_cause"].lower()
    assert "underlay" in root and "overlay" in root, (
        f"Unexpected root cause: {rca['root_cause']}"
    )
    assert any("suppress" in s.lower() for s in rca["resolution_steps"]), (
        "Resolution steps must instruct operators to suppress downstream overlay tickets"
    )
    assert any("evpn" in c.lower() for c in rca["cli_junos"])
    assert any("evpn" in c.lower() for c in rca["cli_eos"])

    # Also verifiable under routing category
    e_routing = kb.lookup("routing", "evpn underlay failure cascade vtep flap")
    assert e_routing.get("match") == e.get("match")


@pytest.mark.unit
def test_evpn_mac_mobility_duplicate_freeze_rca() -> None:
    """EVPN MAC mobility entry must identify freeze condition and prescribe clearing host flaps."""
    e = kb.lookup("evpn", "evpn duplicate mac mobility freeze detection")
    assert "rca" in e, "EVPN MAC mobility entry must have an 'rca' block"
    rca = e["rca"]
    root = rca["root_cause"].lower()
    assert "mac" in root or "mobility" in root or "loop" in root, (
        f"Unexpected root cause: {rca['root_cause']}"
    )
    assert any("freeze" in s.lower() or "migration" in s.lower() for s in rca["resolution_steps"])
    assert any("duplicate-mac" in c.lower() for c in rca["cli_junos"])
    assert any("host-flap" in c.lower() for c in rca["cli_eos"])

