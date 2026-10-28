"""Device triage returns log-derived text (patterns, process names) to the MCP client and /api/triage,
so it must pass the same secret sanitizer as fetch_logs and /api/sources/<id>/fetch."""
from __future__ import annotations

import asyncio

import pytest

from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.device_triage import normalize_pattern, triage_device, triage_from_manager
from ai_log_analyzer.sources.manager import manager as source_manager

pytestmark = pytest.mark.unit

COMMUNITY = "S3cretRWExampleOnly"
PASSWORD = "Hunter2xExampleOnly"
URL_PASS = "UrlPassExampleOnly1"
SECRET_MESSAGES = [
    f"%PARSER-3-ERR: snmp-server community {COMMUNITY} rw rejected",
    f"login failed for admin password={PASSWORD} from 192.0.2.7",
    f"fetch https://svc:{URL_PASS}@example.com/api failed",
]
ALL_SECRETS = (COMMUNITY, PASSWORD, URL_PASS)


def _events(appname: str = "parser") -> list[LogEvent]:
    return [LogEvent("2026-10-27T10:00:00", "r1", appname, "err", m) for m in SECRET_MESSAGES]


def _assert_clean(obj) -> None:
    text = repr(obj)
    assert not [s for s in ALL_SECRETS if s in text], text


def test_triage_device_patterns_are_sanitized_like_fetch_logs():
    result = triage_device("r1", _events()).to_dict()
    _assert_clean(result)
    assert len(result["patterns"]) == 3
    assert any("<REDACTED>" in p["pattern"] for p in result["patterns"])
    assert "community <REDACTED> rw rejected" in " ".join(p["pattern"] for p in result["patterns"])


def test_normalize_pattern_sanitizes_before_it_truncates():
    """A secret that starts inside the 120 character window must not survive the cut."""
    msg = "x" * 100 + f" password={PASSWORD}"
    assert PASSWORD[:6] not in normalize_pattern(msg)


def test_process_names_from_the_log_are_sanitized():
    ev = [LogEvent("2026-10-27T10:00:00", "r1", f"app?token={PASSWORD}", "err", "boom")]
    _assert_clean(triage_device("r1", ev).to_dict())


def test_ordinary_triage_output_is_unchanged():
    ev = [LogEvent("2026-10-27T10:00:00", "r1", "rpd", "err", "rpd[100]: peer 10.0.0.1 at 0xaaaa reset")]
    out = triage_device("r1", ev).to_dict()
    assert out["patterns"][0]["pattern"] == "rpd[N]: peer IP at 0xADDR reset"
    assert out["top_process"] == "rpd" and out["issue_type"] == "routing"


def _stub_manager(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(source_manager, "list_ids", lambda: ["s1"])
    monkeypatch.setattr(source_manager, "fetch", lambda sid, **kw: _events())


def test_triage_from_manager_result_is_clean(monkeypatch: pytest.MonkeyPatch):
    _stub_manager(monkeypatch)
    out = triage_from_manager("r1")
    assert out["ok"] and out["total_events"] == 3
    _assert_clean(out)


def test_api_triage_response_is_clean(monkeypatch: pytest.MonkeyPatch):
    from ai_log_analyzer.web.app import create_app
    _stub_manager(monkeypatch)
    app = create_app()
    app.config.update(TESTING=True)
    resp = app.test_client().post("/api/triage", json={"hostname": "r1"})
    assert resp.status_code == 200
    _assert_clean(resp.get_json())
    assert "<REDACTED>" in resp.get_data(as_text=True)


def test_mcp_analyze_device_result_is_clean(monkeypatch: pytest.MonkeyPatch):
    pytest.importorskip("mcp")
    from ai_log_analyzer.mcp_server import server as srv_mod
    _stub_manager(monkeypatch)
    res = asyncio.run(srv_mod._build_server().call_tool("analyze_device", {"hostname": "r1"}))
    assert res.is_error is False
    _assert_clean(res.structured_content)
    assert "<REDACTED>" in repr(res.structured_content)
