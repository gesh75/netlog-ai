"""Export remediation plans as Ansible playbooks or Nornir/NAPALM scripts.

Every export re-screens the change and its rollback through
``SafetyGuardrail``, so a destructive command cannot slip in through the
automation path. Each export runs in three stages:

1. **Pre-checks**: read-only show commands, always executed.
2. **Dry run**: an Ansible ``check_mode: true`` + ``diff: true`` task
   (``--tags dry_run``), or NAPALM ``dry_run=True``. Nothing is applied.
3. **Apply → verify → confirm**, with a ``rescue`` rollback that only fires
   when the apply step actually changed the device.

Collections: ``cisco.ios``, ``cisco.nxos``, ``arista.eos``,
``junipernetworks.junos`` (native ``commit confirmed`` + ``rollback``),
``fortinet.fortios`` and ``paloaltonetworks.panos`` (object modules — the
graceful-drain action is mapped; arbitrary CLI is not), and FRR via
``vtysh`` on the Linux host. Cisco Catalyst SD-WAN edges are template-
managed: change them through vManage (``cisco.catalystwan``), not this export.
Check-mode / diff support depends on the collection version — run the dry
run against a lab device first.
"""
from __future__ import annotations

import json
from typing import Any

from ai_log_analyzer.remediation import (
    RemediationActionType,
    RemediationPlan,
    SafetyGuardrail,
    VendorOS,
)


class ExportUnsupportedError(ValueError):
    """The plan cannot be expressed safely for the requested automation tool."""


_CLI_FAMILY: dict[VendorOS, dict[str, str]] = {
    VendorOS.CISCO_IOS_XE: {"os": "cisco.ios.ios", "cmd": "cisco.ios.ios_command", "cfg": "cisco.ios.ios_config"},
    VendorOS.CISCO_NXOS: {"os": "cisco.nxos.nxos", "cmd": "cisco.nxos.nxos_command", "cfg": "cisco.nxos.nxos_config"},
    VendorOS.ARISTA_EOS: {"os": "arista.eos.eos", "cmd": "arista.eos.eos_command", "cfg": "arista.eos.eos_config"},
}
_NAPALM_DRIVER = {
    VendorOS.CISCO_IOS_XE: "ios", VendorOS.ARISTA_EOS: "eos",
    VendorOS.JUNIPER_JUNOS: "junos", VendorOS.CISCO_NXOS: "nxos_ssh",
}


# ── minimal strict YAML emitter (dicts / lists / scalars) ───────────────────

def _scalar(value: Any) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value), ensure_ascii=False)  # JSON strings are valid YAML double-quoted scalars


def _dump(obj: Any, indent: int = 0) -> list[str]:
    pad = "  " * indent
    if isinstance(obj, dict):
        if not obj:
            return [pad + "{}"]
        out: list[str] = []
        for key, value in obj.items():
            if isinstance(value, (dict, list)) and value:
                out.append(f"{pad}{key}:")
                out.extend(_dump(value, indent + 1))
            elif isinstance(value, dict):
                out.append(f"{pad}{key}: {{}}")
            elif isinstance(value, list):
                out.append(f"{pad}{key}: []")
            else:
                out.append(f"{pad}{key}: {_scalar(value)}")
        return out
    if isinstance(obj, list):
        out = []
        for item in obj:
            if isinstance(item, dict) and item:
                sub = _dump(item, indent + 1)
                out.append(f"{pad}- {sub[0].lstrip()}")
                out.extend(sub[1:])
            elif isinstance(item, list) and item:
                out.append(f"{pad}-")
                out.extend(_dump(item, indent + 1))
            else:
                out.append(f"{pad}- {_scalar(item)}")
        return out
    return [pad + _scalar(obj)]


def to_yaml(doc: Any) -> str:
    return "\n".join(_dump(doc)) + "\n"


# ── helpers ─────────────────────────────────────────────────────────────────

def config_blocks(lines: list[str]) -> list[dict[str, list[str]]]:
    """Indentation-hierarchy → ordered [{"parents": [...], "lines": [...]}] for *_config modules."""
    rows = [(len(line) - len(line.lstrip()), line.strip()) for line in lines if line.strip()]
    blocks: dict[tuple[str, ...], list[str]] = {}
    stack: list[tuple[int, str]] = []
    for i, (indent, text) in enumerate(rows):
        while stack and stack[-1][0] >= indent:
            stack.pop()
        has_children = i + 1 < len(rows) and rows[i + 1][0] > indent
        if has_children:
            stack.append((indent, text))
            blocks.setdefault(tuple(t for _, t in stack), [])
            continue
        blocks.setdefault(tuple(t for _, t in stack), []).append(text)
    return [{"parents": list(p), "lines": ls} for p, ls in blocks.items() if ls]


def _screen(plan: RemediationPlan) -> None:
    if not plan.body_commands:
        raise ExportUnsupportedError(f"plan {plan.plan_id} has no body commands to export")
    SafetyGuardrail.validate(plan.body_commands, plan.rollback_minutes)
    if plan.inverse_commands:
        SafetyGuardrail.validate(plan.inverse_commands, plan.rollback_minutes)


def _header(plan: RemediationPlan, tool: str) -> str:
    return (
        f"# netlog-ai remediation {plan.plan_id} — {plan.device} ({plan.vendor.value}) — {plan.action_type.value}\n"
        f"# Generated {plan.created_at} for {tool}. Rationale: {plan.rationale}\n"
        f"# Blast radius: {plan.blast_radius_notes or 'review before running'}\n"
        "# 1) Dry run (nothing applied):  ansible-playbook -i <inventory> this.yml --check --diff\n"
        "#    or only the diff task:      ansible-playbook -i <inventory> this.yml --tags dry_run\n"
        "# 2) Apply, verify, confirm:     ansible-playbook -i <inventory> this.yml --diff\n"
        "# Screened by netlog-ai SafetyGuardrail. Validate against a lab device first.\n"
        "---\n"
    )


def _fail_task(plan: RemediationPlan, how: str) -> dict[str, Any]:
    return {"name": "Stop — change rolled back or needs manual rollback",
            "ansible.builtin.fail": {"msg": f"netlog-ai {plan.plan_id}: post-checks failed. {how}"}}


# ── Ansible ─────────────────────────────────────────────────────────────────

def to_ansible_playbook(plan: RemediationPlan) -> str:
    """Ready-to-run playbook YAML for ``plan``. Raises ExportUnsupportedError."""
    _screen(plan)
    if plan.vendor in _CLI_FAMILY:
        play = _cli_play(plan)
    elif plan.vendor == VendorOS.JUNIPER_JUNOS:
        play = _junos_play(plan)
    elif plan.vendor == VendorOS.FORTINET_FORTIOS:
        play = _fortios_play(plan)
    elif plan.vendor == VendorOS.PALOALTO_PANOS:
        play = _panos_play(plan)
    elif plan.vendor == VendorOS.FRR:
        play = _frr_play(plan)
    else:
        raise ExportUnsupportedError(
            f"{plan.vendor.value}: SD-WAN edges are template-managed — push this change through vManage "
            "(cisco.catalystwan collection); use the CLI card for review.")
    return _header(plan, "Ansible") + to_yaml([play])


def _base_play(plan: RemediationPlan, connection: str, network_os: str | None) -> dict[str, Any]:
    play: dict[str, Any] = {
        "name": f"netlog-ai {plan.plan_id}: {plan.action_type.value} on {plan.device}",
        "hosts": plan.device,
        "gather_facts": False,
        "connection": connection,
        "vars": {},
    }
    if network_os:
        play["vars"]["ansible_network_os"] = network_os
    return play


def _cli_play(plan: RemediationPlan) -> dict[str, Any]:
    fam = _CLI_FAMILY[plan.vendor]
    play = _base_play(plan, "ansible.netcommon.network_cli", fam["os"])
    play["vars"]["netlog_blocks"] = config_blocks(plan.body_commands)
    if plan.inverse_commands:
        play["vars"]["netlog_inverse_blocks"] = config_blocks(plan.inverse_commands)
    cfg_args = {"lines": "{{ item.lines }}", "parents": "{{ item.parents if item.parents else omit }}"}
    checkpoint = f"netlog-{plan.plan_id.lower()}"
    tasks: list[dict[str, Any]] = [
        {"name": "Pre-checks (read-only)", fam["cmd"]: {"commands": plan.pre_checks},
         "register": "netlog_pre", "check_mode": False, "changed_when": False},
        {"name": "Dry run — show the diff, apply nothing", fam["cfg"]: dict(cfg_args),
         "loop": "{{ netlog_blocks }}", "check_mode": True, "diff": True, "tags": ["dry_run"]},
    ]
    apply_block: list[dict[str, Any]] = []
    if plan.vendor == VendorOS.CISCO_NXOS:
        apply_block.append({"name": "Checkpoint before change", fam["cmd"]: {"commands": [f"checkpoint {checkpoint}"]}})
    apply_block += [
        {"name": "Apply change", fam["cfg"]: dict(cfg_args), "loop": "{{ netlog_blocks }}",
         "register": "netlog_apply", "diff": True},
        {"name": "Post-checks", fam["cmd"]: {"commands": plan.post_checks}, "register": "netlog_post",
         "changed_when": False},
        {"name": "Persist (write memory) only after post-checks pass", fam["cfg"]: {"save_when": "modified"}},
    ]
    rescue: list[dict[str, Any]] = []
    if plan.vendor == VendorOS.CISCO_NXOS:
        rescue.append({"name": "Roll back to the pre-change checkpoint", "cisco.nxos.nxos_rollback":
                       {"rollback_to": checkpoint}, "when": "netlog_apply is defined and netlog_apply.changed"})
        rescue.append(_fail_task(plan, "Rolled back to the NX-OS checkpoint."))
    elif plan.inverse_commands:
        rescue.append({"name": "Roll back (inverse change)", fam["cfg"]: dict(cfg_args),
                       "loop": "{{ netlog_inverse_blocks }}",
                       "when": "netlog_apply is defined and netlog_apply.changed"})
        rescue.append(_fail_task(plan, "Inverse change applied."))
    else:
        rescue.append(_fail_task(plan, "No automatic inverse for this plan — roll back manually: "
                                 + " | ".join(plan.manual_rollback_commands)))
    tasks.append({"name": "Apply, verify, roll back on failure", "when": "not ansible_check_mode",
                  "tags": ["apply"], "block": apply_block, "rescue": rescue})
    play["tasks"] = tasks
    return play


def _junos_play(plan: RemediationPlan) -> dict[str, Any]:
    play = _base_play(plan, "ansible.netcommon.netconf", "junipernetworks.junos.junos")
    lines = [c.strip() for c in plan.body_commands if c.strip()]
    comment = f"netlog-ai {plan.plan_id}"
    play["tasks"] = [
        {"name": "Pre-checks (read-only)", "junipernetworks.junos.junos_command": {"commands": plan.pre_checks},
         "register": "netlog_pre", "check_mode": False, "changed_when": False},
        {"name": "Dry run — commit check + diff, apply nothing",
         "junipernetworks.junos.junos_config": {"lines": lines, "comment": comment},
         "check_mode": True, "diff": True, "tags": ["dry_run"]},
        {"name": "Apply with commit confirmed, verify, confirm", "when": "not ansible_check_mode", "tags": ["apply"],
         "block": [
             {"name": f"Commit confirmed {plan.rollback_minutes} (auto-reverts unless confirmed)",
              "junipernetworks.junos.junos_config": {"lines": lines, "confirm": plan.rollback_minutes,
                                                     "comment": comment},
              "register": "netlog_apply", "diff": True},
             {"name": "Post-checks", "junipernetworks.junos.junos_command": {"commands": plan.post_checks},
              "register": "netlog_post", "changed_when": False},
             {"name": "Confirm the commit (make permanent)",
              "junipernetworks.junos.junos_config": {"confirm_commit": True}},
         ],
         "rescue": [
             {"name": "Roll back the unconfirmed commit now",
              "junipernetworks.junos.junos_config": {"rollback": 1},
              "when": "netlog_apply is defined and netlog_apply.changed"},
             _fail_task(plan, "Rolled back (rollback 1)."),
         ]},
    ]
    return play


def _require_drain(plan: RemediationPlan, collection: str) -> None:
    if plan.action_type != RemediationActionType.GRACEFUL_LINK_DRAIN:
        raise ExportUnsupportedError(
            f"{plan.vendor.value}: {collection} is object-based; only graceful_link_drain is mapped. "
            "Use the CLI card for other changes.")


def _drain_interface(plan: RemediationPlan) -> str:
    for cmd in plan.body_commands:
        parts = cmd.split()
        if parts[:1] == ["edit"] and len(parts) > 1:
            return parts[1]
        if "interface" in parts and "ethernet" in parts:
            return parts[parts.index("ethernet") + 1]
    raise ExportUnsupportedError(f"could not find the drained interface in plan {plan.plan_id}")


def _fortios_play(plan: RemediationPlan) -> dict[str, Any]:
    _require_drain(plan, "fortinet.fortios")
    intf = _drain_interface(plan)
    play = _base_play(plan, "ansible.netcommon.httpapi", "fortinet.fortios.fortios")
    play["vars"].update({"vdom": "root", "ansible_httpapi_use_ssl": True})

    def intf_task(status: str, name: str) -> dict[str, Any]:
        return {"name": name, "fortinet.fortios.fortios_system_interface": {
            "vdom": "{{ vdom }}", "state": "present",
            "system_interface": {"name": intf, "status": status}}}

    dry = intf_task("down", "Dry run — show the diff, apply nothing")
    dry.update({"check_mode": True, "diff": True, "tags": ["dry_run"]})
    apply = intf_task("down", f"Drain: set {intf} status down")
    apply.update({"register": "netlog_apply", "diff": True})
    rollback = intf_task("up", f"Roll back: set {intf} status up")
    rollback["when"] = "netlog_apply is defined and netlog_apply.changed"
    def fact(name: str) -> dict[str, Any]:
        return {"name": name, "fortinet.fortios.fortios_configuration_fact": {
            "vdom": "{{ vdom }}", "selector": "system_interface", "params": {"name": intf}},
            "check_mode": False}

    play["tasks"] = [
        fact(f"Pre-check: current {intf} settings (read-only)"),
        dry,
        {"name": "Apply, verify, roll back on failure", "when": "not ansible_check_mode", "tags": ["apply"],
         "block": [apply, {**fact(f"Post-check: {intf} settings"), "register": "netlog_post"}],
         "rescue": [rollback, _fail_task(plan, f"{intf} set back to up.")]},
    ]
    return play


def _panos_play(plan: RemediationPlan) -> dict[str, Any]:
    _require_drain(plan, "paloaltonetworks.panos")
    intf = _drain_interface(plan)
    snapshot = f"netlog-ai-{plan.plan_id.lower()}.xml"
    play = _base_play(plan, "local", None)
    play["vars"]["provider"] = {"ip_address": "{{ ansible_host }}", "api_key": "{{ panos_api_key }}"}
    prov = "{{ provider }}"

    def link(state: str, name: str) -> dict[str, Any]:
        return {"name": name, "paloaltonetworks.panos.panos_interface": {
            "provider": prov, "if_name": intf, "link_state": state}}

    dry = link("down", "Dry run — show the diff, apply nothing")
    dry.update({"check_mode": True, "diff": True, "tags": ["dry_run"]})
    apply = link("down", f"Drain: link-state down on {intf}")
    apply.update({"register": "netlog_apply", "diff": True})
    play["tasks"] = [
        {"name": "Pre-check (read-only)", "paloaltonetworks.panos.panos_op": {
            "provider": prov, "cmd": f"show interface {intf}"}, "check_mode": False, "changed_when": False},
        dry,
        {"name": "Snapshot, apply, commit, verify — restore snapshot on failure",
         "when": "not ansible_check_mode", "tags": ["apply"],
         "block": [
             {"name": f"Save rollback snapshot {snapshot}", "paloaltonetworks.panos.panos_op": {
                 "provider": prov, "cmd": f"<save><config><to>{snapshot}</to></config></save>", "cmd_is_xml": True}},
             apply,
             {"name": "Commit", "paloaltonetworks.panos.panos_commit_firewall": {"provider": prov},
              "register": "netlog_commit"},
             {"name": "Post-check", "paloaltonetworks.panos.panos_op": {
                 "provider": prov, "cmd": "show routing protocol bgp summary"}, "changed_when": False},
         ],
         "rescue": [
             {"name": f"Load snapshot {snapshot}", "paloaltonetworks.panos.panos_op": {
                 "provider": prov, "cmd": f"<load><config><from>{snapshot}</from></config></load>",
                 "cmd_is_xml": True}, "when": "netlog_apply is defined and netlog_apply.changed"},
             {"name": "Commit the restored configuration",
              "paloaltonetworks.panos.panos_commit_firewall": {"provider": prov},
              "when": "netlog_apply is defined and netlog_apply.changed"},
             _fail_task(plan, f"Snapshot {snapshot} restored."),
         ]},
    ]
    return play


def _frr_play(plan: RemediationPlan) -> dict[str, Any]:
    play = _base_play(plan, "ssh", None)
    play["become"] = True
    argv = ["vtysh", "-c", "configure terminal"]
    for cmd in plan.body_commands:
        argv += ["-c", cmd.strip()]
    backup = f"/etc/frr/frr.conf.{plan.plan_id.lower()}.bak"
    play["tasks"] = [
        {"name": f"Pre-check: {c}", "ansible.builtin.command": {"argv": ["vtysh", "-c", c]},
         "check_mode": False, "changed_when": False}
        for c in plan.pre_checks
    ] + [
        {"name": "Dry run — commands that would be applied", "ansible.builtin.debug": {"var": "netlog_argv"},
         "vars": {"netlog_argv": argv}, "tags": ["dry_run"]},
        {"name": "Backup, apply, verify — restore backup on failure", "when": "not ansible_check_mode",
         "tags": ["apply"],
         "block": [
             {"name": "Backup frr.conf", "ansible.builtin.copy": {"src": "/etc/frr/frr.conf", "dest": backup,
                                                                 "remote_src": True}},
             {"name": "Apply via vtysh", "ansible.builtin.command": {"argv": argv}, "register": "netlog_apply"},
             *({"name": f"Post-check: {c}", "ansible.builtin.command": {"argv": ["vtysh", "-c", c]},
                "changed_when": False} for c in plan.post_checks),
             {"name": "Persist", "ansible.builtin.command": {"argv": ["vtysh", "-c", "write memory"]}},
         ],
         "rescue": [
             {"name": "Restore frr.conf", "ansible.builtin.copy": {"src": backup, "dest": "/etc/frr/frr.conf",
                                                                  "remote_src": True},
              "when": "netlog_apply is defined"},
             {"name": "Reload FRR", "ansible.builtin.systemd": {"name": "frr", "state": "reloaded"},
              "when": "netlog_apply is defined"},
             _fail_task(plan, f"{backup} restored."),
         ]},
    ]
    return play


# ── Nornir / NAPALM ─────────────────────────────────────────────────────────

def to_nornir_script(plan: RemediationPlan) -> str:
    """Python script (Nornir + nornir_napalm) with a NAPALM dry-run diff by default."""
    _screen(plan)
    driver = _NAPALM_DRIVER.get(plan.vendor)
    if driver is None:
        raise ExportUnsupportedError(f"{plan.vendor.value}: no NAPALM driver mapping — use the Ansible export or CLI card")
    config = "\n".join(c.strip() if plan.vendor == VendorOS.JUNIPER_JUNOS else c for c in plan.body_commands)
    return f'''#!/usr/bin/env python3
"""netlog-ai remediation {plan.plan_id} — {plan.device} ({plan.vendor.value}, NAPALM driver "{driver}").

Default run is a DRY RUN: NAPALM loads a merge candidate, prints the diff and
discards it. Pass --apply to commit, run post-checks, and roll back through
NAPALM if any post-check fails. Screened by netlog-ai SafetyGuardrail.
Requires: pip install nornir nornir_napalm nornir_utils
"""
import sys

from nornir import InitNornir
from nornir_napalm.plugins.tasks import napalm_cli, napalm_configure
from nornir_utils.plugins.functions import print_result

DEVICE = {json.dumps(plan.device)}
CONFIG = {json.dumps(config)}
PRE_CHECKS = {json.dumps(plan.pre_checks)}
POST_CHECKS = {json.dumps(plan.post_checks)}
APPLY = "--apply" in sys.argv


def rollback(task):
    task.host.get_connection("napalm", task.nornir.config).rollback()


def main() -> int:
    nr = InitNornir(config_file="config.yaml").filter(name=DEVICE)
    print_result(nr.run(task=napalm_cli, commands=PRE_CHECKS))
    result = nr.run(task=napalm_configure, configuration=CONFIG, dry_run=not APPLY)
    print_result(result)
    if not APPLY or result.failed:
        return 1 if result.failed else 0
    post = nr.run(task=napalm_cli, commands=POST_CHECKS)
    print_result(post)
    if post.failed:
        print_result(nr.run(task=rollback))
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


def export_plan(plan: RemediationPlan, fmt: str) -> str:
    """markdown | json | ansible | nornir."""
    fmt = (fmt or "markdown").lower()
    if fmt == "ansible":
        return to_ansible_playbook(plan)
    if fmt == "nornir":
        return to_nornir_script(plan)
    if fmt == "json":
        return json.dumps(plan.to_dict(), indent=2)
    if fmt == "markdown":
        return plan.to_markdown_card()
    raise ExportUnsupportedError(f"unknown export format {fmt!r} (markdown|json|ansible|nornir)")
