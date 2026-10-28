"""Runbook export injection: the Netmiko script and the Ansible playbook keep finding text inert
(Zpfn6Dw7, by5QEPMn). Every text here is synthetic."""

from __future__ import annotations

import ast
from typing import Any

import pytest
import yaml

from ai_log_analyzer import runbook

pytestmark = pytest.mark.unit


# ── runbook.to_netmiko_script: the finding text must stay a string literal (Zpfn6Dw7) ─────────────

HOSTILE_TITLES = [
    'x"""; __import__("os").system("id"); """',
    'x"""\n__import__("os").system("id")\n"""',
    "x'''; __import__('os').system('id'); '''",
    'x""" + """ and __import__("os")',
    "x\\",
    "x __import__('os') ",
    'x"\\"""\\""""; __import__("os")',
]


def _netmiko_ast(finding: dict[str, Any], hosts: list[str]) -> ast.Module:
    return ast.parse(runbook.to_netmiko_script(finding, hosts, platform_hint="junos"))


@pytest.mark.parametrize("title", HOSTILE_TITLES)
def test_netmiko_script_keeps_a_hostile_title_inside_the_docstring(title: str) -> None:
    base = {"severity": "high", "patch": ["show version"]}
    benign = _netmiko_ast({**base, "title": "plain title"}, ["rt1"])
    hostile = _netmiko_ast({**base, "title": title}, ["rt1"])
    # same statements after the docstring: nothing was added, nothing moved
    assert [ast.dump(n) for n in hostile.body[1:]] == [ast.dump(n) for n in benign.body[1:]]
    assert not [n for n in ast.walk(hostile) if isinstance(n, ast.Name) and n.id == "__import__"]
    assert "__import__" in (ast.get_docstring(hostile, clean=False) or "") or "\\" in title


@pytest.mark.parametrize("field,value", [
    ("severity", '"""\nimport os\nos.system("id")\n"""'),
    ("severity", "high'''\nimport os\n'''"),
])
def test_netmiko_script_severity_cannot_leave_the_docstring(field: str, value: str) -> None:
    benign = _netmiko_ast({"title": "t", "patch": ["show version"]}, ["rt1"])
    hostile = _netmiko_ast({"title": "t", field: value, "patch": ["show version"]}, ["rt1"])
    assert [ast.dump(n) for n in hostile.body[1:]] == [ast.dump(n) for n in benign.body[1:]]


def test_netmiko_script_hostile_hostname_stays_a_string() -> None:
    host = 'rt1"""\nimport os\nos.system("id")\n"""'
    benign = _netmiko_ast({"title": "t", "patch": ["show version"]}, ["rt1"])
    hostile = _netmiko_ast({"title": "t", "patch": ["show version"]}, [host])
    assert [ast.dump(n) for n in hostile.body[1:] if not isinstance(n, ast.Assign)] == \
        [ast.dump(n) for n in benign.body[1:] if not isinstance(n, ast.Assign)]
    devices = next(n for n in hostile.body
                   if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "DEVICES")
    assert ast.literal_eval(devices.value) == [host]


def test_netmiko_script_tolerates_non_string_finding_fields() -> None:
    script = runbook.to_netmiko_script({"title": ["a", "b"], "severity": 5, "patch": ["x", 7, None]}, ["rt1"])
    ast.parse(script)


# ── runbook.to_ansible_playbook: no Jinja, no extra plays (by5QEPMn) ───────────────────────────────

class _Unsafe(str):
    """What `!unsafe` loads as, so a test can tell a tagged scalar from a plain one."""


class _AnsibleLoader(yaml.SafeLoader):
    pass


_AnsibleLoader.add_constructor("!unsafe", lambda loader, node: _Unsafe(loader.construct_scalar(node)))


def _load_playbook(text: str) -> Any:
    loader = _AnsibleLoader(text)  # SafeLoader plus the one `!unsafe` scalar constructor, nothing else
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()


JINJA_CMDS = [
    '{{ lookup("pipe","id") }}',
    "{% for i in range(3) %}x{% endfor %}",
    "{# c #} set system host-name x",
    "set snmp contact 'a: b' # c",
    "- hosts: all",
    'say "hi"\\n',
]
HOSTILE_PLAY_TITLES = [
    'Fix"\n- hosts: all\n  gather_facts: true\n  tasks:\n    - ansible.builtin.shell: id',
    "{{ lookup('pipe','id') }}",
    "x{% if 1 %}y{% endif %}",
    'a: "b"\n  pre_tasks: []',
    "plain title",
]


@pytest.mark.parametrize("platform", ["junos", "eos", "frr"])
@pytest.mark.parametrize("title", HOSTILE_PLAY_TITLES)
def test_ansible_playbook_is_one_play_with_inert_text(platform: str, title: str) -> None:
    finding = {"title": title, "severity": "high", "rationale": "why\n- hosts: all", "patch": JINJA_CMDS}
    doc = _load_playbook(runbook.to_ansible_playbook(finding, ["rt-01"], platform_hint=platform))
    assert isinstance(doc, list) and len(doc) == 1
    play = doc[0]
    assert set(play) == {"name", "hosts", "gather_facts", "serial", "tasks"}
    assert play["hosts"] == "rt-01" and len(play["tasks"]) == 2
    assert play["name"] == "Remediate: " + title[:60]
    if "{" in play["name"]:
        assert isinstance(play["name"], _Unsafe)
    apply_task = play["tasks"][0]
    module = next(k for k in apply_task if k not in ("name", "register"))
    if platform == "frr":
        body = apply_task[module]
        assert body == "\n".join(JINJA_CMDS) and isinstance(body, _Unsafe)
    else:
        lines = apply_task[module]["lines"]
        assert lines == JINJA_CMDS
        assert all(isinstance(line, _Unsafe) for line in lines if "{" in line)


ODD_TEXT = ["a b", "a\x85b", "a b", "a﻿b", "a\x00b", "a\tb", "a\rb", "a\x1bb", "café \U0001f600",
            "yes", "123", "~", "null", "- x", "# y", "k: v", "!tag x", "&anchor", "*alias", "@x", "%x",
            "'q'", '"d"',
            "a \\ b", "line1\nline2", "x\n\ny"]


@pytest.mark.parametrize("platform", ["junos", "frr"])
def test_ansible_playbook_round_trips_odd_text_exactly(platform: str) -> None:
    doc = _load_playbook(runbook.to_ansible_playbook({"title": "t", "patch": ODD_TEXT}, ["r1"], platform))
    task = doc[0]["tasks"][0]
    if platform == "frr":
        assert task["ansible.builtin.shell"] == "\n".join(ODD_TEXT)
    else:
        assert task["junipernetworks.junos.junos_config"]["lines"] == ODD_TEXT
    odd_title = _load_playbook(runbook.to_ansible_playbook({"title": " \x85  x", "patch": ["a"]},
                                                           ["h i"], platform))
    assert odd_title[0]["name"] == "Remediate:  \x85  x" and odd_title[0]["hosts"] == "h i"


def test_ansible_playbook_comment_header_cannot_break_out_of_the_comment() -> None:
    finding = {"title": "t\n- hosts: all - hosts: all", "severity": "low\nx: y", "rationale": "a\r\nb: c",
               "patch": ["show version"]}
    text = runbook.to_ansible_playbook(finding, ["rt\n- hosts: all"], platform_hint="junos")
    head = text.split("\n- name:", 1)[0]
    assert all(line.startswith("#") or line == "---" for line in head.split("\n")), head
    doc = _load_playbook(text)
    assert len(doc) == 1 and doc[0]["hosts"] == "rt\n- hosts: all"


def test_ansible_playbook_benign_output_is_still_readable() -> None:
    finding = {"title": "BFD", "patch": ["set protocols bgp bfd"]}
    text = runbook.to_ansible_playbook(finding, ["fw-02"], "junos")
    assert "junipernetworks.junos.junos_config" in text and "set protocols bgp bfd" in text
    assert "!unsafe" not in text and text.startswith("---\n# Auto-generated")
