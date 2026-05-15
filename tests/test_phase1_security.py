"""Phase 1 security + correctness regression tests.

Covers:
  - BadCommand rejection (no shell fallback in _parse_frr_command)
  - Recovery events excluded from action items
  - optimize_config sanitizes secrets before sending to the LLM
  - copilot.ask sanitizes context blocks before sending to the LLM
  - explain_diff sanitizes both inputs before LLM/raw_diff
  - render_dot returns clean bytes (no latin-1 round-trip)
  - _mask_public_ipv4 returns per-text replacement count
  - llm.is_enabled() does not touch _state.enabled
  - _parse_bool string handling
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from ai_log_analyzer import llm
from ai_log_analyzer.analyzer import build_action_items, optimize_config
from ai_log_analyzer.classifier import LogEvent, classify_events
from ai_log_analyzer.copilot import ask as copilot_ask
from ai_log_analyzer.diff import explain_diff
from ai_log_analyzer.sanitize import _mask_public_ipv4
from ai_log_analyzer.web.app import BadCommand, _parse_bool, _parse_frr_command


@pytest.fixture(autouse=True)
def restore_llm_state():
    snap = dict(llm._state)
    yield
    for k, v in snap.items():
        llm._state[k] = v


# ── BadCommand rejection — no shell fallback ─────────────────────────────────

@pytest.mark.unit
def test_parse_frr_command_rejects_unbalanced_quotes():
    """Previously fell back to ['sh', '-c', raw] — now hard-rejects."""
    with pytest.raises(BadCommand):
        _parse_frr_command("vtysh -c 'show ip bgp summary")


@pytest.mark.unit
def test_parse_frr_command_rejects_empty():
    with pytest.raises(BadCommand):
        _parse_frr_command("")


@pytest.mark.unit
def test_parse_frr_command_accepts_known_prefix():
    assert _parse_frr_command("ping -c 5 10.0.0.1") == ["ping", "-c", "5", "10.0.0.1"]


@pytest.mark.unit
def test_parse_frr_command_treats_unknown_as_vtysh():
    assert _parse_frr_command("show ip bgp summary") == ["vtysh", "-c", "show ip bgp summary"]


@pytest.mark.unit
def test_parse_frr_command_iptables_removed_from_allowlist():
    # iptables is no longer in the allowlist → treated as vtysh, not shell
    assert _parse_frr_command("iptables -L") == ["vtysh", "-c", "iptables -L"]


# ── Recovery events excluded ─────────────────────────────────────────────────

@pytest.mark.unit
def test_recovery_events_not_action_items():
    classified, _, _ = classify_events([
        LogEvent("", "r1", "bgpd", "info", "bgp peer 10.0.0.1 established"),
        LogEvent("", "sw1", "mib2d", "info", "ifIndex 538 link up"),
    ])
    items = build_action_items(classified, llm_top_n=0)
    assert items == []


@pytest.mark.unit
def test_real_incidents_still_become_action_items():
    classified, _, _ = classify_events([
        LogEvent("", "r1", "bgpd", "err", "bgp peer 10.0.0.1 down (hold timer expired)"),
        LogEvent("", "sw1", "mib2d", "info", "ifIndex 538 link up"),  # recovery
    ])
    items = build_action_items(classified, llm_top_n=0)
    assert len(items) == 1
    assert items[0].severity == "high"


# ── Sanitize-before-LLM in optimize_config ───────────────────────────────────

@pytest.mark.unit
def test_optimize_config_sanitizes_before_llm():
    """The LLM must never see encrypted-password or unmasked public IPs."""
    captured: dict = {}

    def fake_query(system, user, max_tokens=0):
        captured["user"] = user
        return '{"summary":"ok","findings":[],"monitoring_gaps":[],"score":95}'

    llm.set_enabled(True)
    with patch.object(llm, "query", side_effect=fake_query):
        result = optimize_config(
            hostname="r1",
            platform="junos",
            running_config=(
                'encrypted-password "$6$supersecret"\n'
                'neighbor 8.8.8.8 peer-as 65000\n'
            ),
        )
    assert "supersecret" not in captured["user"]
    assert "8.8.8.8" not in captured["user"]
    assert result.get("redactions_applied", 0) >= 2


# ── Sanitize-before-LLM in copilot ──────────────────────────────────────────

@pytest.mark.unit
def test_copilot_sanitizes_context_before_llm():
    captured: dict = {}

    def fake_query(system, user, max_tokens=0):
        captured["user"] = user
        return "Looks fine."

    llm.set_enabled(True)
    with patch.object(llm, "query", side_effect=fake_query):
        r = copilot_ask(
            "Is SSH secure?",
            [{"hostname": "h1", "platform": "junos",
              "config_text": 'snmp-server community totallyPrivateString ro\n'}],
        )
    assert "totallyPrivateString" not in captured["user"]
    assert r["llm_powered"] is True
    assert r.get("redactions_applied", 0) >= 1


# ── Sanitize-before-LLM in diff ─────────────────────────────────────────────

@pytest.mark.unit
def test_explain_diff_redacts_secrets_from_raw_diff():
    """The returned raw_diff must NOT contain encrypted-password values either."""
    llm.set_enabled(False)  # skip LLM call — just check the raw diff
    r = explain_diff(
        before='encrypted-password "$6$oldSecretXYZ"',
        after='encrypted-password "$6$newSecretABC"',
    )
    assert "oldSecretXYZ" not in r["raw_diff"]
    assert "newSecretABC" not in r["raw_diff"]
    assert r["redactions_applied"] >= 2


# ── Sanitizer public-IP count fix ────────────────────────────────────────────

@pytest.mark.unit
def test_mask_public_ipv4_counts_each_occurrence():
    """Used to return len(mapping) (unique IPs); should now count rewrites."""
    text = "neighbor 8.8.8.8\nneighbor 8.8.8.8\nneighbor 1.1.1.1\n"
    out, n = _mask_public_ipv4(text)
    assert "8.8.8.8" not in out
    # 3 replacements: 8.8.8.8 twice, 1.1.1.1 once
    assert n == 3


# ── llm.is_enabled() does not probe providers ───────────────────────────────

@pytest.mark.unit
def test_is_enabled_does_not_probe_providers():
    """Should be a pure dict read — important for hot-path callers."""
    llm.set_enabled(True)
    assert llm.is_enabled() is True
    llm.set_enabled(False)
    assert llm.is_enabled() is False


# ── _parse_bool handles JSON-string booleans ────────────────────────────────

@pytest.mark.unit
def test_parse_bool_strings():
    assert _parse_bool("false") is False
    assert _parse_bool("0") is False
    assert _parse_bool("true") is True
    assert _parse_bool("1") is True
    assert _parse_bool("yes") is True
    assert _parse_bool(None, default=True) is True
    assert _parse_bool(None, default=False) is False
