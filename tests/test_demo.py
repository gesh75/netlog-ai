"""Demo mode: deterministic storyline exercises every analysis surface."""
from __future__ import annotations

import pytest

from ai_log_analyzer.adapters.file import parse_lines
from ai_log_analyzer.analyzer import analyze
from ai_log_analyzer.demo import generate_demo_lines


pytestmark = pytest.mark.unit


def test_storyline_is_deterministic():
    assert generate_demo_lines() == generate_demo_lines()


def test_storyline_lights_up_every_surface():
    result = analyze(parse_lines(generate_demo_lines()), use_llm=False)
    d = result.to_dict()

    # action items across categories
    cats = {a["category"] for a in d["action_items"]}
    assert {"system", "hardware", "security", "routing"} <= cats

    # unknown-pattern miner catches the invented appdaemon shape
    templates = " ".join(t["template"] for t in d["unknown_patterns"]["top_templates"])
    assert "quantum optics calibration drift" in templates

    # stability engine sees the leaf-11 interface flapping
    leaf = next(dev for dev in d["stability"]["devices"] if dev["hostname"] == "leaf-11")
    assert leaf["flaps"] >= 2
    assert leaf["flapping_entity"] == "interface"

    # multi-vendor: NX-OS crash and SR Linux BGP churn both classified
    descs = {a["description"] for a in d["action_items"]}
    assert "NX-OS service crash" in descs
    assert any("BGP peer" in x for x in descs)


def test_demo_cli_smoke(capsys):
    import sys as _sys
    from ai_log_analyzer.cli import main
    argv = _sys.argv
    _sys.argv = ["ai-log-analyzer", "demo"]
    try:
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
    finally:
        _sys.argv = argv
    out = capsys.readouterr().out
    assert "Health score" in out
    assert "Unknown patterns" in out
