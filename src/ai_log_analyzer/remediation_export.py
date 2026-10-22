"""Export remediation plans as Ansible playbooks or Nornir/NAPALM scripts.

Every export re-screens the change and its rollback through
``SafetyGuardrail``, so a destructive command cannot slip in through the
automation path. Each export runs in three stages:

1. **Pre-checks**: read-only show commands, always executed.
2. **Dry run**: an Ansible ``check_mode: true`` + ``diff: true`` task
   (``--tags dry_run``), or NAPALM ``dry_run=True``. Nothing is applied.
3. **Apply → verify → confirm**, with a ``rescue`` rollback that only fires
   when the apply step actually changed the device. The verify step is a real
   gate: where the post-check output can be asserted reliably (a drained BGP
   peer must no longer be Established; Junos/IOS-XE/NX-OS/EOS) an ``assert``
   fails the play and triggers the rollback; everywhere else the play stops for
   an explicit operator ``yes`` (no answer = roll back). Nothing is ever
   confirmed or persisted on the strength of the post-checks merely running.

Only the Junos play (``commit confirmed``) has a device-side auto-revert timer;
the other exports have no dead-man timer, so their safety net is the dry run,
the verification gate and the rescue rollback (the CLI card's vendor timer is
not part of the playbook).

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

import ipaddress
import json
import re
from typing import Any

from ai_log_analyzer.remediation import (
    RemediationActionType,
    RemediationPlan,
    SafetyGuardrail,
    SafetyViolationError,
    VendorOS,
    clean_text,
    validate_ansible_host,
    validate_device,
    validate_interface,
    validate_neighbor_ip,
    validate_plan_id,
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


_TEMPLATE_RE = re.compile(r"\{\{|\{%|\{#")
_CONTROL_CHARS_RE = re.compile(r"[\r\n\x00-\x08\x0b-\x1f\x7f\x85  ]")


def _checks(commands: list[str]) -> list[str]:
    """Pre/post-checks without comment-only lines."""
    return [c for c in commands if c.strip() and not c.strip().startswith(("#", "!"))]


def _screen(plan: RemediationPlan, ansible: bool = False) -> None:
    if not plan.body_commands:
        raise ExportUnsupportedError(f"plan {plan.plan_id} has no body commands to export")
    validate_plan_id(plan.plan_id)
    if ansible:
        validate_ansible_host(plan.device)
    else:
        validate_device(plan.device)
    if plan.interface:
        validate_interface(plan.interface)
    if plan.bgp_neighbor_ip:
        validate_neighbor_ip(plan.bgp_neighbor_ip)
    SafetyGuardrail.validate(plan.body_commands, plan.rollback_minutes)
    if plan.inverse_commands:
        SafetyGuardrail.validate(plan.inverse_commands, plan.rollback_minutes)
    SafetyGuardrail.validate_read_only(plan.pre_checks, "pre-check")
    SafetyGuardrail.validate_read_only(plan.post_checks, "post-check")
    for cmd in [*plan.body_commands, *plan.inverse_commands, *plan.pre_checks, *plan.post_checks]:
        if _CONTROL_CHARS_RE.search(cmd):
            raise SafetyViolationError(f"command {clean_text(cmd, 60)!r} contains a line break or control character")
        if _TEMPLATE_RE.search(cmd):  # Ansible would template it on the controller
            raise SafetyViolationError(f"command {cmd!r} contains template syntax ({{{{ }}}} or {{% %}})")


def _header(plan: RemediationPlan, tool: str) -> str:
    timer = (f"commit confirmed {int(plan.rollback_minutes)} min auto-reverts unless the verification gate passes"
             if plan.vendor == VendorOS.JUNIPER_JUNOS else
             "no device-side auto-revert timer in this export: safety net = dry run + verification gate + rescue rollback")
    return (
        f"# netlog-ai remediation {clean_text(plan.plan_id, 64)} — {clean_text(plan.device, 255)} "
        f"({plan.vendor.value}) — {plan.action_type.value}\n"
        f"# Generated {clean_text(plan.created_at, 40)} for {tool}. Rationale: {clean_text(plan.rationale)}\n"
        f"# Blast radius: {clean_text(plan.blast_radius_notes) or 'review before running'}\n"
        f"# Rollback: {timer}.\n"
        "# 1) Dry run (nothing applied):  ansible-playbook -i <inventory> this.yml --check --diff\n"
        "#    or only the diff task:      ansible-playbook -i <inventory> this.yml --tags dry_run\n"
        "# 2) Apply, verify, confirm:     ansible-playbook -i <inventory> this.yml --diff\n"
        "#    (confirm/persist only runs after the post-check assertion or an operator 'yes')\n"
        "# Screened by netlog-ai SafetyGuardrail. Validate against a lab device first.\n"
        "---\n"
    )


def _post_assertion(plan: RemediationPlan) -> dict[str, str] | None:
    """Machine-checkable post-condition, or None when the output cannot be asserted reliably.

    Only a graceful drain of a known IPv4 BGP peer on Junos / IOS-XE / NX-OS / EOS qualifies:
    after the drain that peer must not be Established in ``show bgp summary``. The regexes
    avoid backslashes so they survive YAML, Jinja and Python string literals unchanged.
    """
    if plan.action_type != RemediationActionType.GRACEFUL_LINK_DRAIN or not plan.bgp_neighbor_ip:
        return None
    style = {VendorOS.ARISTA_EOS: "word", VendorOS.JUNIPER_JUNOS: "word",
             VendorOS.CISCO_IOS_XE: "numeric", VendorOS.CISCO_NXOS: "numeric"}.get(plan.vendor)
    try:
        ip = ipaddress.ip_address(plan.bgp_neighbor_ip)
    except ValueError:
        return None
    # IPv6 rows wrap on IOS/NX-OS, and the output must actually contain the summary.
    if style is None or ip.version != 4 or not any("bgp summary" in c.lower() for c in _checks(plan.post_checks)):
        return None
    peer = str(ip).replace(".", "[.]")
    established = f"(?m)^ *{peer} .* Estab" if style == "word" else f"(?m)^ *{peer} .* [0-9]+ *$"
    return {"neighbor": str(ip), "require": "(?i)bgp|peers", "established": established}


_VERIFIED = "netlog_verified | default(false) | bool"
_SHOW_CLI = "(netlog_post | default({})).stdout_lines | default('no post-checks configured')"


def _gate_tasks(plan: RemediationPlan, show: str, assertable: bool = False) -> list[dict[str, Any]]:
    """Verification gate between the post-checks and the confirm/persist step.

    Asserts on the post-check output when possible; otherwise stops for an explicit operator
    ``yes``. A failure raises inside the apply block, so the ``rescue`` rollback runs.
    ``show`` is a Jinja expression that renders the output for the operator; ``assertable``
    means the registered ``netlog_post.stdout`` is the CLI text the assertion can parse.
    """
    spec = _post_assertion(plan) if assertable else None
    if spec is not None:
        text = "netlog_post.stdout | join('\\n')"
        tasks: list[dict[str, Any]] = [{
            "name": f"Verify: BGP peer {spec['neighbor']} is no longer Established (fails -> roll back)",
            "ansible.builtin.assert": {
                "that": [f"({text}) is search('{spec['require']}')",
                         f"({text}) is not search('{spec['established']}')"],
                "fail_msg": f"netlog-ai {plan.plan_id}: post-checks do not show peer {spec['neighbor']} "
                            "drained (still Established, or no BGP summary in the output).",
                "success_msg": f"peer {spec['neighbor']} is no longer Established"}}]
    else:
        tasks = [
            {"name": "Post-check output for operator review", "ansible.builtin.debug": {"msg": f"{{{{ {show} }}}}"}},
            {"name": f"Operator verification — type yes to keep {plan.plan_id}; anything else rolls it back",
             "ansible.builtin.pause": {"prompt": f"netlog-ai {plan.plan_id}: post-check output cannot be asserted "
                                                 "automatically. Review it above. Type 'yes' to confirm, "
                                                 "anything else (or no answer) rolls the change back"},
             "register": "netlog_manual"},
            {"name": "Roll back unless the operator confirmed", "ansible.builtin.assert": {
                "that": ["(netlog_manual.user_input | default('') | trim | lower) == 'yes'"],
                "fail_msg": f"netlog-ai {plan.plan_id}: not confirmed by the operator."}},
        ]
    tasks.append({"name": "Verification gate passed", "ansible.builtin.set_fact": {"netlog_verified": True}})
    return tasks


def _fail_task(plan: RemediationPlan, how: str) -> dict[str, Any]:
    return {"name": "Stop — change rolled back or needs manual rollback",
            "ansible.builtin.fail": {"msg": f"netlog-ai {plan.plan_id}: post-checks failed. {how}"}}


# ── Ansible ─────────────────────────────────────────────────────────────────

def to_ansible_playbook(plan: RemediationPlan) -> str:
    """Ready-to-run playbook YAML for ``plan``. Raises ExportUnsupportedError / SafetyViolationError."""
    _screen(plan, ansible=True)
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
    pre, post = _checks(plan.pre_checks), _checks(plan.post_checks)
    checkpoint = f"netlog-{plan.plan_id.lower()}"
    tasks: list[dict[str, Any]] = [
        *([{"name": "Pre-checks (read-only)", fam["cmd"]: {"commands": pre},
            "register": "netlog_pre", "check_mode": False, "changed_when": False}] if pre else []),
        {"name": "Dry run — show the diff, apply nothing", fam["cfg"]: dict(cfg_args),
         "loop": "{{ netlog_blocks }}", "check_mode": True, "diff": True, "tags": ["dry_run"]},
    ]
    apply_block: list[dict[str, Any]] = []
    if plan.vendor == VendorOS.CISCO_NXOS:
        apply_block.append({"name": "Checkpoint before change", fam["cmd"]: {"commands": [f"checkpoint {checkpoint}"]}})
    apply_block += [
        {"name": "Apply change", fam["cfg"]: dict(cfg_args), "loop": "{{ netlog_blocks }}",
         "register": "netlog_apply", "diff": True},
        *([{"name": "Post-checks", fam["cmd"]: {"commands": post}, "register": "netlog_post",
            "changed_when": False}] if post else []),
        *_gate_tasks(plan, _SHOW_CLI, assertable=bool(post)),
        {"name": "Persist (write memory) — only after the verification gate passed", fam["cfg"]: {"save_when": "modified"},
         "when": _VERIFIED},
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
    pre, post = _checks(plan.pre_checks), _checks(plan.post_checks)
    play["tasks"] = [
        *([{"name": "Pre-checks (read-only)", "junipernetworks.junos.junos_command": {"commands": pre},
            "register": "netlog_pre", "check_mode": False, "changed_when": False}] if pre else []),
        {"name": "Dry run — commit check + diff, apply nothing",
         "junipernetworks.junos.junos_config": {"lines": lines, "comment": comment},
         "check_mode": True, "diff": True, "tags": ["dry_run"]},
        {"name": "Apply with commit confirmed, verify, confirm", "when": "not ansible_check_mode", "tags": ["apply"],
         "block": [
             {"name": f"Commit confirmed {plan.rollback_minutes} (auto-reverts unless confirmed)",
              "junipernetworks.junos.junos_config": {"lines": lines, "confirm": plan.rollback_minutes,
                                                     "comment": comment},
              "register": "netlog_apply", "diff": True},
             *([{"name": "Post-checks", "junipernetworks.junos.junos_command": {"commands": post},
                 "register": "netlog_post", "changed_when": False}] if post else []),
             *_gate_tasks(plan, _SHOW_CLI,
                          assertable=bool(post)),
             {"name": "Confirm the commit (make permanent) — only after the verification gate passed",
              "junipernetworks.junos.junos_config": {"confirm_commit": True}, "when": _VERIFIED},
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
         "block": [apply, {**fact(f"Post-check: {intf} settings"), "register": "netlog_post"},
                   *_gate_tasks(plan, "netlog_post | default({}) | to_nice_json")],
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
                 "provider": prov, "cmd": "show routing protocol bgp summary"}, "register": "netlog_post",
              "changed_when": False},
             *_gate_tasks(plan, "netlog_post | default({}) | to_nice_json"),
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
    # unique per plan instance: a second run for the same device/interface keeps its own backup
    backup = f"/etc/frr/frr.conf.{plan.plan_id.lower()}.{re.sub(r'[^0-9]', '', plan.created_at)[:20]}.bak"
    play["tasks"] = [
        {"name": f"Pre-check: {c}", "ansible.builtin.command": {"argv": ["vtysh", "-c", c]},
         "check_mode": False, "changed_when": False}
        for c in _checks(plan.pre_checks)
    ] + [
        {"name": "Dry run — commands that would be applied", "ansible.builtin.debug": {"var": "netlog_argv"},
         "vars": {"netlog_argv": argv}, "tags": ["dry_run"]},
        {"name": "Backup, apply, verify — restore backup on failure", "when": "not ansible_check_mode",
         "tags": ["apply"],
         "block": [
             {"name": "Backup frr.conf", "ansible.builtin.copy": {"src": "/etc/frr/frr.conf", "dest": backup,
                                                                 "remote_src": True}},
             {"name": "Apply via vtysh", "ansible.builtin.command": {"argv": argv}, "register": "netlog_apply"},
             *([{"name": "Post-checks (read-only)", "ansible.builtin.command": {"argv": ["vtysh", "-c", "{{ item }}"]},
                 "loop": _checks(plan.post_checks), "register": "netlog_post", "changed_when": False}]
               if plan.post_checks else []),
             *_gate_tasks(plan, "(netlog_post | default({})).results | default([]) | map(attribute='stdout_lines')"
                                " | list"),
             {"name": "Persist — only after the verification gate passed",
              "ansible.builtin.command": {"argv": ["vtysh", "-c", "write memory"]}, "when": _VERIFIED},
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
    spec = _post_assertion(plan)
    post = _checks(plan.post_checks)
    # every dynamic value is emitted through repr() (a valid Python literal); the docstring only
    # carries validated identifiers, never free text
    doc_device = plan.device.replace('"', "").replace("\\", "")
    return f'''#!/usr/bin/env python3
"""netlog-ai remediation {plan.plan_id} — {doc_device} ({plan.vendor.value}, NAPALM driver "{driver}").

Default run is a DRY RUN: NAPALM loads a merge candidate, prints the diff and
discards it. Pass --apply to commit and run the post-checks. The change is
kept only if the post-check assertion passes (or, when the output cannot be
asserted for this plan, the operator types "yes" on a terminal); otherwise it
is rolled back through NAPALM and the script exits 2. There is no device-side
auto-revert timer in this export. Screened by netlog-ai SafetyGuardrail.
Requires: pip install nornir nornir_napalm nornir_utils
"""
import re
import sys

from nornir import InitNornir
from nornir_napalm.plugins.tasks import napalm_cli, napalm_configure
from nornir_utils.plugins.functions import print_result

DEVICE = {repr(plan.device)}
CONFIG = {repr(config)}
PRE_CHECKS = {repr(_checks(plan.pre_checks))}
POST_CHECKS = {repr(post)}
# Post-condition on the post-check text: REQUIRE must match and ESTABLISHED must not
# (a drained BGP peer is no longer Established). None = ask the operator instead.
REQUIRE = {repr(spec["require"] if spec and post else None)}
ESTABLISHED = {repr(spec["established"] if spec and post else None)}
APPLY = "--apply" in sys.argv


def rollback(task):
    task.host.get_connection("napalm", task.nornir.config).rollback()


def assertion_failure(text):
    """Why the post-check output fails the assertion, or None when it holds."""
    if not re.search(REQUIRE, text):
        return "post-check output does not contain a BGP summary"
    if re.search(ESTABLISHED, text):
        return "the drained BGP peer is still Established"
    return None


def operator_confirms():
    if not sys.stdin.isatty():
        print("post-checks cannot be asserted automatically and there is no terminal to ask: rolling back")
        return False
    return input("Review the post-check output above. Type 'yes' to keep the change: ").strip().lower() == "yes"


def verified(post):
    if post is None or post.failed:
        return False
    out = post[DEVICE][0].result
    text = "\\n".join(str(v) for v in out.values()) if isinstance(out, dict) else str(out)
    if REQUIRE is None:
        return operator_confirms()
    problem = assertion_failure(text)
    if problem:
        print("ASSERTION FAILED: " + problem)
    return problem is None


def main() -> int:
    nr = InitNornir(config_file="config.yaml").filter(name=DEVICE)
    if DEVICE not in nr.inventory.hosts:
        print("device " + DEVICE + " not found in the Nornir inventory")
        return 1
    if PRE_CHECKS:
        print_result(nr.run(task=napalm_cli, commands=PRE_CHECKS))
    result = nr.run(task=napalm_configure, configuration=CONFIG, dry_run=not APPLY)
    print_result(result)
    if not APPLY or result.failed:
        return 1 if result.failed else 0
    post = nr.run(task=napalm_cli, commands=POST_CHECKS) if POST_CHECKS else None
    if post is not None:
        print_result(post)
    if not verified(post):
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
