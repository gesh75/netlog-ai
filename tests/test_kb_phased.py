"""Tests for the phased knowledge base structure."""
import pytest

from ai_log_analyzer import kb


PHASE_NAMES = {"Diagnose", "Mitigate", "Remediate", "Verify", "Optimize"}


@pytest.mark.unit
def test_every_kb_entry_has_five_phases():
    """Every non-default entry must have all 5 phases in canonical order."""
    seen = set()
    for cat, entries in kb.KB.items():
        for key, entry in entries.items():
            if key == "_default":
                continue
            if id(entry) in seen:
                continue
            seen.add(id(entry))
            phases = entry.get("phases", [])
            names = [p["name"] for p in phases]
            assert set(names).issuperset(PHASE_NAMES), \
                f"{cat}.{key} missing phases — got {names}"


@pytest.mark.unit
def test_phases_have_actions_with_cli_dict():
    """Each action must have a `cli` dict keyed by platform string."""
    for cat, entries in kb.KB.items():
        for key, entry in entries.items():
            if key == "_default":
                continue
            for phase in entry.get("phases", []):
                for action in phase.get("actions", []):
                    cli = action.get("cli")
                    assert isinstance(cli, dict), \
                        f"{cat}.{key}.{phase['name']} action.cli must be dict, got {type(cli)}"


@pytest.mark.unit
def test_bgp_lookup_returns_phased_entry():
    e = kb.lookup("routing", "BGP peer down / connect failure")
    assert "phases" in e
    assert any(p["name"] == "Optimize" for p in e["phases"])


@pytest.mark.unit
def test_optimize_phase_has_concrete_config_suggestions():
    """The Optimize phase must propose actual config changes, not just commentary."""
    e = kb.lookup("routing", "BGP peer down / connect failure")
    optimize = next(p for p in e["phases"] if p["name"] == "Optimize")
    actions = optimize.get("actions", [])
    assert len(actions) >= 1, "Optimize phase must have at least 1 action"
    # At least one action must mention a config keyword
    cli_text = " ".join(
        cmd for a in actions for cmd in a.get("cli", {}).values()
    ).lower()
    assert any(kw in cli_text for kw in ["bfd", "timers", "graceful-restart", "prefix-list"])


@pytest.mark.unit
def test_preventive_config_is_a_list():
    e = kb.lookup("routing", "BGP peer down / connect failure")
    assert isinstance(e.get("preventive_config"), list)
    assert len(e["preventive_config"]) > 0


@pytest.mark.unit
def test_lookup_unknown_category_returns_safe_default():
    e = kb.lookup("nonsense-category", "nothing matches")
    assert "phases" in e
    assert isinstance(e["phases"], list)
    assert len(e["phases"]) == 5


@pytest.mark.unit
def test_phase_cli_for_returns_platform_match():
    entry = kb.lookup("routing", "bgp peer down")
    diagnose = entry["phases"][0]
    frr_cmds = kb.phase_cli_for(diagnose, "frr")
    junos_cmds = kb.phase_cli_for(diagnose, "junos")
    assert frr_cmds and junos_cmds
    assert "vtysh" in frr_cmds[0].lower() or "show" in frr_cmds[0].lower()


@pytest.mark.unit
def test_monitoring_recommendations_present():
    e = kb.lookup("interface", "Interface link down")
    assert e.get("monitoring")
    assert all(isinstance(m, str) for m in e["monitoring"])
