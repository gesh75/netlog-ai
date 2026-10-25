"""Regression tests: exported plays must gate confirm/persist on a real assertion, and exports must resist injection."""

from __future__ import annotations

import re
import sys
import types

import pytest
import yaml

from ai_log_analyzer.remediation import RemediationGenerator, SafetyViolationError, VendorOS
from ai_log_analyzer.remediation_export import to_ansible_playbook, to_nornir_script

pytestmark = pytest.mark.unit

GEN = RemediationGenerator()
PEER = "10.0.0.1"

SUMMARY = {  # post-check `show bgp summary` text per vendor: peer still up / drained
    VendorOS.JUNIPER_JUNOS: (
        "Groups: 1 Peers: 1\n10.0.0.1  65001  100  100  0  0  1d 2:3:4 Establ\n  inet.0: 5/5/5/0\n",
        "Groups: 1 Peers: 1\n10.0.0.1  65001  0  0  0  0  5 Idle\n"),
    VendorOS.ARISTA_EOS: (
        "BGP summary information\n  10.0.0.1 4 65001 12 13 0 0 1d02h Estab   5  5\n",
        "BGP summary information\n  10.0.0.1 4 65001 12 13 0 0 00:01:00 Idle\n"),
    VendorOS.CISCO_IOS_XE: (
        "BGP router identifier 1.1.1.1\n10.0.0.1  4  65001  100  100  15  0  0 00:10:00  5\n",
        "BGP router identifier 1.1.1.1\n10.0.0.1  4  65001  0  0  1  0  0 never    Idle (Admin)\n"),
    VendorOS.CISCO_NXOS: (
        "BGP router identifier 1.1.1.1\n10.0.0.1  4  65001  100  100  15  0  0 00:10:00 0\n",
        "BGP router identifier 1.1.1.1\n10.0.0.1  4  65001  0  0  1  0  0 never    Idle\n"),
}
INTF = {VendorOS.JUNIPER_JUNOS: "xe-0/0/1", VendorOS.ARISTA_EOS: "Ethernet1",
        VendorOS.CISCO_IOS_XE: "GigabitEthernet0/1", VendorOS.CISCO_NXOS: "Ethernet1/1"}


def _play(plan):
    (play,) = yaml.safe_load(to_ansible_playbook(plan))
    return play


def _guarded(play):
    return next(t for t in play["tasks"] if "block" in t)


def _names(tasks):
    return [t["name"] for t in tasks]


def _jinja_eval(expr: str, stdout: list[str]) -> bool:
    jinja2 = pytest.importorskip("jinja2")
    env = jinja2.Environment()
    env.tests["search"] = lambda value, pattern: re.search(pattern, str(value)) is not None
    return bool(env.compile_expression(expr)(netlog_post={"stdout": stdout}))


@pytest.mark.parametrize("vendor", list(SUMMARY))
def test_drain_with_known_peer_asserts_before_confirming(vendor):
    play = _play(GEN.build_graceful_link_drain("r1", vendor, INTF[vendor], bgp_neighbor_ip=PEER))
    block = _guarded(play)["block"]
    assert_task = next(t for t in block if "ansible.builtin.assert" in t)
    gate_idx = block.index(next(t for t in block if "ansible.builtin.set_fact" in t))
    assert block.index(assert_task) < gate_idx
    assert not any("ansible.builtin.pause" in t for t in block)
    final = block[-1]            # confirm_commit (Junos) / persist (IOS, NX-OS, EOS)
    assert final["when"] == "netlog_verified | default(false) | bool" and block.index(final) > gate_idx
    still_up, drained = SUMMARY[vendor]
    conds = assert_task["ansible.builtin.assert"]["that"]
    assert all(_jinja_eval(c, [drained]) for c in conds)
    assert not all(_jinja_eval(c, [still_up]) for c in conds)          # peer Established -> assertion fails
    assert not all(_jinja_eval(c, [""]) for c in conds)                # empty output never passes
    assert not all(_jinja_eval(c, ["% Invalid input"]) for c in conds)


@pytest.mark.parametrize("make", [
    lambda: GEN.build_graceful_link_drain("r1", VendorOS.JUNIPER_JUNOS, "xe-0/0/1"),               # no peer known
    lambda: GEN.build_graceful_link_drain("r1", VendorOS.ARISTA_EOS, "Ethernet1", bgp_neighbor_ip="2001:db8::1"),
    lambda: GEN.build_qos_copp_remediation("r1", VendorOS.ARISTA_EOS, "Ethernet1"),
    lambda: GEN.build_custom_safe_plan("r1", VendorOS.CISCO_IOS_XE, ["router bgp 65000", " bgp log-neighbor-changes"],
                                       ["show ip bgp summary"], ["show ip bgp summary"], "log"),
    lambda: GEN.build_graceful_link_drain("r1", VendorOS.CISCO_IOS_XE, "Gi0/1"),
])
def test_unassertable_plans_stop_for_an_operator_yes_instead_of_auto_confirming(make):
    block = _guarded(_play(make()))["block"]
    pause = next(t for t in block if "ansible.builtin.pause" in t)
    gate = next(t for t in block if t["name"].startswith("Roll back unless the operator confirmed"))
    assert "yes" in gate["ansible.builtin.assert"]["that"][0] and pause["register"] == "netlog_manual"
    assert block.index(pause) < block.index(gate)
    final = block[-1]
    assert final["when"] == "netlog_verified | default(false) | bool"
    assert block.index(final) > block.index(gate)


@pytest.mark.parametrize("vendor,intf", [(VendorOS.FORTINET_FORTIOS, "wan1"), (VendorOS.PALOALTO_PANOS, "ethernet1/1"),
                                         (VendorOS.FRR, "eth1")])
def test_object_and_frr_exports_require_operator_confirmation_inside_the_block(vendor, intf):
    block = _guarded(_play(GEN.build_graceful_link_drain("d1", vendor, intf, bgp_neighbor_ip=PEER)))
    assert any("ansible.builtin.pause" in t for t in block["block"])
    assert any("ansible.builtin.assert" in t for t in block["block"])      # failure -> rescue rolls back
    assert "ansible.builtin.fail" in block["rescue"][-1]


def test_no_playbook_task_confirms_without_a_gate():
    for vendor in (VendorOS.JUNIPER_JUNOS, VendorOS.CISCO_IOS_XE, VendorOS.ARISTA_EOS, VendorOS.CISCO_NXOS, VendorOS.FRR):
        plan = GEN.build_graceful_link_drain("r1", vendor, INTF.get(vendor, "eth1"), bgp_neighbor_ip=PEER)
        block = _guarded(_play(plan))["block"]
        gate = next(i for i, t in enumerate(block) if "ansible.builtin.set_fact" in t)
        for i, task in enumerate(block):
            text = yaml.safe_dump(task)
            if "confirm_commit" in text or "save_when" in text or "write memory" in text:
                assert i > gate and "netlog_verified" in task["when"], task["name"]


def test_header_documents_rollback_honestly():
    junos = to_ansible_playbook(GEN.build_graceful_link_drain("r1", VendorOS.JUNIPER_JUNOS, "xe-0/0/1", bgp_neighbor_ip=PEER))
    eos = to_ansible_playbook(GEN.build_graceful_link_drain("r1", VendorOS.ARISTA_EOS, "Ethernet1"))
    assert "commit confirmed 5 min auto-reverts" in junos
    assert "no device-side auto-revert timer" in eos


# ── pre/post checks are screened ────────────────────────────────────────────

@pytest.mark.parametrize("field", ["pre_checks", "post_checks"])
@pytest.mark.parametrize("bad", ["reload", "write erase", "show version; reload", "configure terminal", "clear ip bgp 10.0.0.1"])
@pytest.mark.parametrize("vendor", [VendorOS.ARISTA_EOS, VendorOS.FRR])
def test_exports_reject_non_read_only_checks(field, bad, vendor):
    plan = GEN.build_graceful_link_drain("r1", vendor, "Ethernet1")
    setattr(plan, field, [*getattr(plan, field), bad])
    with pytest.raises(SafetyViolationError):
        to_ansible_playbook(plan)
    if vendor == VendorOS.ARISTA_EOS:
        with pytest.raises(SafetyViolationError):
            to_nornir_script(plan)


# ── injection ───────────────────────────────────────────────────────────────

def test_device_name_cannot_break_out_of_the_nornir_docstring():
    plan = GEN.build_graceful_link_drain("r1", VendorOS.ARISTA_EOS, "Ethernet1")
    plan.device = 'r1"""\nimport os; os.system("id")\n"""'
    with pytest.raises(SafetyViolationError, match="device"):
        to_nornir_script(plan)
    with pytest.raises(SafetyViolationError, match="device"):
        to_ansible_playbook(plan)


def test_rationale_newlines_cannot_add_yaml_documents_or_top_level_python():
    plan = GEN.build_graceful_link_drain("r1", VendorOS.ARISTA_EOS, "Ethernet1")
    plan.rationale = "x\n---\n- hosts: all\n  tasks: []\n# y"
    plan.blast_radius_notes = "a\r\nb"
    text = to_ansible_playbook(plan)
    header = text.split("\n---\n", 1)[0]
    assert all(line.startswith("#") for line in header.splitlines())
    assert len(list(yaml.safe_load_all(text))) == 1
    assert yaml.safe_load(text)[0]["hosts"] == "r1"
    compile(to_nornir_script(plan), "x.py", "exec")


@pytest.mark.parametrize("device", ["all", "ALL", "*", "ungrouped", "r1:r2", "r1,r2", "r[1:3]", "!r1", "~r.*", "r1&r2", "r1 r2"])
def test_ansible_hosts_cannot_widen_beyond_one_device(device):
    plan = GEN.build_graceful_link_drain("r1", VendorOS.ARISTA_EOS, "Ethernet1")
    plan.device = device
    with pytest.raises(SafetyViolationError):
        to_ansible_playbook(plan)


def test_ipv6_literal_and_fqdn_devices_are_accepted():
    for device in ("2001:db8::1", "edge-1.dc1.example.net", "r1"):
        plan = GEN.build_graceful_link_drain(device, VendorOS.ARISTA_EOS, "Ethernet1")
        assert yaml.safe_load(to_ansible_playbook(plan))[0]["hosts"] == device


def test_tampered_interface_and_template_syntax_are_rejected():
    plan = GEN.build_graceful_link_drain("r1", VendorOS.ARISTA_EOS, "Ethernet1")
    plan.interface = "Ethernet1\nreload"
    with pytest.raises(SafetyViolationError, match="interface"):
        to_ansible_playbook(plan)
    plan = GEN.build_graceful_link_drain("r1", VendorOS.ARISTA_EOS, "Ethernet1")
    plan.body_commands = ["interface Ethernet1", " description {{ lookup('pipe','id') }}"]
    with pytest.raises(SafetyViolationError, match="template"):
        to_ansible_playbook(plan)
    plan.body_commands = ["interface Ethernet1\nreload"]
    with pytest.raises(SafetyViolationError):
        to_nornir_script(plan)


def test_frr_backup_file_is_unique_per_plan_instance():
    a = _guarded(_play(GEN.build_graceful_link_drain("frr1", VendorOS.FRR, "eth1")))["block"][0]["ansible.builtin.copy"]["dest"]
    b = _guarded(_play(GEN.build_graceful_link_drain("frr1", VendorOS.FRR, "eth1")))["block"][0]["ansible.builtin.copy"]["dest"]
    assert a != b and a.startswith("/etc/frr/frr.conf.rem-") and a.endswith(".bak")


# ── Nornir script behaviour ─────────────────────────────────────────────────

class _Res:
    failed = False


class _Post(_Res):
    def __init__(self, text: str):
        self.text = text

    def __getitem__(self, _host):
        return [types.SimpleNamespace(result={"show ip bgp summary": self.text})]


class _FakeNR:
    def __init__(self, post_text: str, calls: list):
        self.post_text, self.calls = post_text, calls
        self.inventory = types.SimpleNamespace(hosts={"r1": object()})

    def filter(self, **_):
        return self

    def run(self, task, **_):
        self.calls.append(task.__name__)
        return _Post(self.post_text) if task.__name__ == "napalm_cli" else _Res()


def _load_script(plan, post_text, calls, monkeypatch, argv):
    script = to_nornir_script(plan)
    compile(script, "netlog_nornir.py", "exec")
    nornir = types.ModuleType("nornir")
    nornir.InitNornir = lambda **_: _FakeNR(post_text, calls)
    tasks = types.ModuleType("nornir_napalm.plugins.tasks")

    def napalm_cli(task=None, **_): ...

    def napalm_configure(task=None, **_): ...
    tasks.napalm_cli, tasks.napalm_configure = napalm_cli, napalm_configure
    util = types.ModuleType("nornir_utils.plugins.functions")
    util.print_result = lambda *_a, **_k: None
    for name, mod in {"nornir": nornir, "nornir_napalm": types.ModuleType("nornir_napalm"),
                      "nornir_napalm.plugins": types.ModuleType("nornir_napalm.plugins"),
                      "nornir_napalm.plugins.tasks": tasks, "nornir_utils": types.ModuleType("nornir_utils"),
                      "nornir_utils.plugins": types.ModuleType("nornir_utils.plugins"),
                      "nornir_utils.plugins.functions": util}.items():
        monkeypatch.setitem(sys.modules, name, mod)
    monkeypatch.setattr(sys, "argv", argv)
    ns: dict = {"__name__": "netlog_nornir"}
    exec(compile(script, "netlog_nornir.py", "exec"), ns)  # noqa: S102
    return ns


def test_nornir_script_assertion_logic_and_exit_codes(monkeypatch):
    plan = GEN.build_graceful_link_drain("r1", VendorOS.ARISTA_EOS, "Ethernet1", bgp_neighbor_ip=PEER)
    still_up, drained = SUMMARY[VendorOS.ARISTA_EOS]
    ns = _load_script(plan, drained, [], monkeypatch, ["x", "--apply"])
    assert ns["assertion_failure"](drained) is None
    assert "still Established" in ns["assertion_failure"](still_up)
    assert "does not contain" in ns["assertion_failure"]("")
    assert ns["APPLY"] is True and ns["POST_CHECKS"] == plan.post_checks


@pytest.mark.parametrize("post_text,rolled_back,code", [
    (SUMMARY[VendorOS.ARISTA_EOS][1], False, 0),     # peer drained -> keep
    (SUMMARY[VendorOS.ARISTA_EOS][0], True, 2),      # peer still Established -> roll back, non-zero exit
])
def test_nornir_script_rolls_back_and_exits_non_zero_when_the_assertion_fails(monkeypatch, post_text, rolled_back, code):
    plan = GEN.build_graceful_link_drain("r1", VendorOS.ARISTA_EOS, "Ethernet1", bgp_neighbor_ip=PEER)
    calls: list = []
    ns = _load_script(plan, post_text, calls, monkeypatch, ["x", "--apply"])
    assert ns["main"]() == code
    assert ("rollback" in calls) is rolled_back
    calls.clear()
    ns = _load_script(plan, post_text, calls, monkeypatch, ["x"])      # dry run never post-checks or rolls back
    assert ns["main"]() == 0 and "rollback" not in calls and calls.count("napalm_cli") == 1


def test_nornir_script_without_assertion_never_confirms_non_interactively(monkeypatch):
    plan = GEN.build_graceful_link_drain("r1", VendorOS.ARISTA_EOS, "Ethernet1")        # no peer -> manual gate
    ns = _load_script(plan, "anything", [], monkeypatch, ["x", "--apply"])
    assert ns["REQUIRE"] is None
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: False))
    assert ns["operator_confirms"]() is False
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr("builtins.input", lambda _p="": "yes")
    assert ns["operator_confirms"]() is True
    monkeypatch.setattr("builtins.input", lambda _p="": "no")
    assert ns["operator_confirms"]() is False


def test_nornir_script_is_valid_python_with_hostile_text_fields():
    plan = GEN.build_graceful_link_drain("r1", VendorOS.CISCO_IOS_XE, "Gi0/1")
    plan.rationale = 'quote""" and \\ backslash\nimport os'
    script = to_nornir_script(plan)
    compile(script, "x.py", "exec")
    assert "import os" not in script.split('"""')[0]
