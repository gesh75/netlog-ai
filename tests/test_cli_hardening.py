"""CLI hardening: clean errors and exit codes, --version, doctor, event-derived remediation."""
from __future__ import annotations

import argparse
import json

import pytest

from ai_log_analyzer import __version__, cli, doctor

pytestmark = pytest.mark.unit

LOG = "\n".join([
    "Oct 16 14:00:00 mx1 mib2d[1]: SNMP_TRAP_LINK_DOWN: ifIndex 500, ifAdminStatus up(1), ifOperStatus down(2), ifName ge-0/0/1",
    "Oct 16 14:00:01 mx1 rpd[1]: bgp_ev_peer: BGP peer 10.0.0.2 (External AS 65002) changed state from Established to Idle",
    "Oct 16 14:00:02 leaf1 Ebra: %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet3, changed state to down",
    "Oct 16 14:00:04 rt9 bgpd[1]: bgp neighbor 192.0.2.1 down",
]) + "\n"


def _run(monkeypatch, *argv) -> int:
    monkeypatch.setattr("sys.argv", ["ai-log-analyzer", *argv])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    return exc.value.code


def _ns(**kw) -> argparse.Namespace:
    base = {"frr": None, "file": None, "stdin": False, "tail": 200, "no_llm": True, "dedup": False}
    base.update(kw)
    return argparse.Namespace(**base)


def test_version_flag(monkeypatch, capsys):
    assert _run(monkeypatch, "--version") == 0
    assert __version__ in capsys.readouterr().out


def test_missing_file_is_a_clean_error_with_exit_2(tmp_path, capsys, monkeypatch):
    assert cli.cmd_analyze(_ns(file=[str(tmp_path / "nope.log")])) == 2
    err = capsys.readouterr().err
    assert "cannot read" in err and "no such file" in err and "Traceback" not in err
    assert _run(monkeypatch, "analyze", "--no-llm", "--file", str(tmp_path / "nope.log")) == 2
    assert cli.cmd_analyze(_ns(file=[str(tmp_path)])) == 2           # a directory is not a log file


def test_second_missing_file_is_reported_before_any_analysis(tmp_path, capsys):
    good = tmp_path / "a.log"
    good.write_text(LOG)
    assert cli.cmd_analyze(_ns(file=[str(good), str(tmp_path / "gone.log")])) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "gone.log" in captured.err


def test_snow_sync_without_url_is_an_error_not_a_silent_dry_run(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("SERVICENOW_URL", raising=False)
    monkeypatch.delenv("SNOW_URL", raising=False)
    log = tmp_path / "a.log"
    log.write_text(LOG)
    assert cli.cmd_analyze(_ns(file=[str(log)], snow_sync=True)) == 2
    captured = capsys.readouterr()
    assert "SERVICENOW_URL" in captured.err and "--snow-dry-run" in captured.err and captured.out == ""
    assert cli.cmd_analyze(_ns(file=[str(log)], snow_sync=True, snow_dry_run=True)) == 0
    assert json.loads(capsys.readouterr().out)["servicenow_sync"]


def test_remediation_json_and_ansible_format_conflict_is_an_error(monkeypatch, capsys):
    argv = ["remediation", "--device", "r1", "--vendor", "arista_eos", "--interface", "Ethernet1"]
    monkeypatch.setattr("sys.argv", ["x", *argv, "--json", "--format", "ansible"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2
    assert "--json cannot be combined" in capsys.readouterr().err
    assert _run(monkeypatch, *argv, "--json", "--format", "nornir") == 2
    assert _run(monkeypatch, *argv, "--json") == 0
    assert json.loads(capsys.readouterr().out.split("\n", 0)[0])["vendor"] == "arista_eos"
    assert _run(monkeypatch, *argv, "--json", "--format", "json") == 0


@pytest.mark.parametrize("value", ["0", "31", "-1", "abc", "5.5"])
def test_bad_rollback_minutes_is_a_usage_error(value, monkeypatch, capsys):
    assert _run(monkeypatch, "remediation", "--device", "r1", "--vendor", "arista_eos",
                "--rollback-minutes", value) == 2
    assert "rollback-minutes" in capsys.readouterr().err


def test_cmd_remediation_rejects_out_of_range_rollback_without_the_parser(capsys):
    args = argparse.Namespace(device="r1", vendor="arista_eos", action="drain", interface="Ethernet1",
                              bgp_neighbor=None, rollback_minutes=99, rationale="", json=False)
    assert cli.cmd_remediation(args) == 2
    assert "must be an integer from 1 to 30" in capsys.readouterr().err


def test_bad_device_or_interface_is_a_usage_error_not_a_traceback(capsys):
    for field, value in (("device", "r1\nreload"), ("interface", "Ethernet1;reload"), ("bgp_neighbor", "10.0.0.256")):
        kw = {"device": "r1", "vendor": "juniper_junos", "action": "drain", "interface": "xe-0/0/1",
              "bgp_neighbor": None, "rollback_minutes": 5, "rationale": "", "json": False, field: value}
        assert cli.cmd_remediation(argparse.Namespace(**kw)) == 2
        assert "error:" in capsys.readouterr().err


def test_remediation_flag_derives_vendor_and_interface_from_the_events(tmp_path, capsys):
    log = tmp_path / "net.log"
    log.write_text(LOG)
    assert cli.cmd_analyze(_ns(file=[str(log)], remediation=True)) == 0
    captured = capsys.readouterr()
    out = json.loads(captured.out)
    plans = {p["device"]: p for p in out["remediation_plans"]}
    assert plans["mx1"]["vendor"] == "juniper_junos" and plans["mx1"]["interface"] == "ge-0/0/1"
    assert plans["leaf1"]["vendor"] == "arista_eos" and plans["leaf1"]["interface"] == "Ethernet3"
    assert not any(p["interface"] == "Ethernet1" and p["device"] == "mx1" for p in plans.values())
    skipped = {s["device"]: s["reason"] for s in out["remediation_skipped"]}
    assert "interface" in skipped["rt9"] or "vendor" in skipped["rt9"]
    assert "no remediation plan for" in captured.err


def test_remediation_reports_refused_plans_instead_of_swallowing_them(tmp_path, capsys, monkeypatch):
    from ai_log_analyzer import remediation

    def boom(*_a, **_k):
        raise remediation.SafetyViolationError("refused for the test")
    monkeypatch.setattr(remediation.RemediationGenerator, "build_graceful_link_drain", boom)
    log = tmp_path / "net.log"
    log.write_text(LOG)
    assert cli.cmd_analyze(_ns(file=[str(log)], remediation=True)) == 0
    captured = capsys.readouterr()
    out = json.loads(captured.out)
    assert out["remediation_plans"] == []
    assert any("refused for the test" in s["reason"] for s in out["remediation_skipped"])
    assert "refused for the test" in captured.err


# ── doctor ──────────────────────────────────────────────────────────────────

def _by_name(checks):
    return {c["name"]: c for c in checks}


def test_doctor_flags_unwritable_stores_bad_env_and_never_prints_secrets(tmp_path):
    env = {"AI_LOG_ANALYZER_STATE_DB": str(tmp_path / "missing-dir" / "state.db"),
           "AI_LOG_ANALYZER_RAG_DB": str(tmp_path / "rag.db"), "ANALYZER_PORT": "99999",
           "LLM_PROVIDER": "claude", "ANALYZER_HOST": "0.0.0.0", "SERVICENOW_URL": "http://snow.example",
           "LLM_TIMEOUT": "soon"}
    by = _by_name(doctor.run_checks(env))
    assert by["AI_LOG_ANALYZER_STATE_DB"]["status"] == "fail"
    assert by["AI_LOG_ANALYZER_RAG_DB"]["status"] == "ok"
    assert by["ANALYZER_PORT"]["status"] == "fail"
    assert by["LLM_PROVIDER"]["status"] == "fail" and "ANTHROPIC_API_KEY" in by["LLM_PROVIDER"]["detail"]
    assert by["ANALYZER_HOST"]["status"] == "warn" and by["SERVICENOW_URL"]["status"] == "warn"
    assert by["LLM_TIMEOUT"]["status"] == "fail"
    secret = {"LLM_PROVIDER": "claude", "ANTHROPIC_API_KEY": "sk-ant-super-secret", "ANALYZER_HOST": "0.0.0.0",
              "AI_LOG_ANALYZER_API_TOKEN": "tok-super-secret"}
    blob = json.dumps(doctor.run_checks(secret))
    assert "super-secret" not in blob
    assert _by_name(doctor.run_checks(secret))["LLM_PROVIDER"]["status"] == "ok"


def test_doctor_checks_an_existing_sqlite_state_db_is_writable(tmp_path):
    import sqlite3
    db = tmp_path / "state.db"
    sqlite3.connect(db).close()
    assert _by_name(doctor.run_checks({"AI_LOG_ANALYZER_STATE_DB": str(db)}))["AI_LOG_ANALYZER_STATE_DB"]["status"] == "ok"
    db.chmod(0o400)
    import os
    if os.geteuid() != 0:                       # root ignores file modes
        assert _by_name(doctor.run_checks({"AI_LOG_ANALYZER_STATE_DB": str(db)}))["AI_LOG_ANALYZER_STATE_DB"]["status"] == "fail"


def test_doctor_command_exit_code_and_output(monkeypatch, capsys, tmp_path):
    for var in ("AI_LOG_ANALYZER_STATE_DB", "AI_LOG_ANALYZER_RAG_DB", "ANALYZER_PORT", "LLM_PROVIDER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    assert cli.cmd_doctor(argparse.Namespace(json=True)) in (0, 1)
    data = json.loads(capsys.readouterr().out)
    assert {c["name"] for c in data["checks"]} >= {"python", "package:flask"}
    assert data["summary"]["fail"] == sum(c["status"] == "fail" for c in data["checks"])
    monkeypatch.setenv("AI_LOG_ANALYZER_STATE_DB", str(tmp_path / "nodir" / "s.db"))
    assert cli.cmd_doctor(argparse.Namespace(json=False)) == 1
    out = capsys.readouterr().out
    assert "[fail] AI_LOG_ANALYZER_STATE_DB" in out and "failure(s)" in out
    assert _run(monkeypatch, "doctor") == 1
