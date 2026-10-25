"""Hermetic ServiceNow source, sync, API, MCP, and overlay tests."""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

import pytest

from ai_log_analyzer.analytics import Finding
from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.cli import cmd_analyze
from ai_log_analyzer.servicenow_sync import (
    ServiceNowChangeRecord,
    ServiceNowClient,
    correlate_changes_with_findings,
)
from ai_log_analyzer.sources.base import LogSource, SourceConfig, SourceError
from ai_log_analyzer.sources.manager import SourceManager
from ai_log_analyzer.sources.servicenow import ServiceNowSource
from ai_log_analyzer.web.app import create_app

pytestmark = pytest.mark.unit

_ROOT = Path(__file__).resolve().parents[1]
_STATIC = _ROOT / "src" / "ai_log_analyzer" / "web" / "static"
_LOG = "\n".join([
    "2026-10-16T14:00:00Z leaf01 bgp neighbor 192.0.2.1 down",
    "2026-10-16T14:00:01Z leaf01 bgp neighbor 192.0.2.1 up",
    "2026-10-16T14:00:02Z leaf01 bgp neighbor 192.0.2.1 down",
])


class _Body:
    def __init__(self, payload: dict) -> None:
        self._raw = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._raw

    def __enter__(self) -> _Body:
        return self

    def __exit__(self, *_exc: object) -> bool:
        return False


def _cfg(url: str = "https://example.service-now.com", **extra: str) -> SourceConfig:
    return SourceConfig(
        id="snow-lab",
        type="servicenow",
        url=url,
        username="netops",
        password="not-a-real-secret",
        extra=extra,
        timeout_seconds=5,
    )


@pytest.fixture
def client():
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


def test_servicenow_source_is_registered() -> None:
    manager = SourceManager()
    assert "servicenow" in manager.known_kinds()
    src = ServiceNowSource.from_config(_cfg())
    assert isinstance(src, LogSource)
    assert ServiceNowSource.name == "servicenow"


@pytest.mark.parametrize("url", [
    "http://127.0.0.1",
    "http://localhost/api/now",
    "http://169.254.169.254/latest/meta-data",
    "http://metadata.google.internal",
])
def test_servicenow_rejects_ssrf_targets(url: str) -> None:
    with pytest.raises(SourceError):
        ServiceNowSource(_cfg(url))


def test_fetch_normalizes_string_and_display_value(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    def fake_open(req, timeout=5, context=None, **_kw):  # noqa: ANN001
        seen.append(req.full_url)
        if "em_alert" in req.full_url:
            return _Body({"result": [{
                "cmdb_ci": {"display_value": "leaf01", "value": "ci-1"},
                "short_description": "bgp neighbor down",
                "severity": "1",
                "sys_created_on": "2026-10-16 14:00:00",
            }]})
        return _Body({"result": [{
            "cmdb_ci": "spine01",
            "description": "interface Ethernet1 down",
            "priority": "2",
            "sys_created_on": "2026-10-16 14:05:00",
        }]})

    monkeypatch.setattr("ai_log_analyzer.sources.outbound.safe_urlopen", fake_open)
    alert = ServiceNowSource(_cfg(table="em_alert"))
    events = list(alert.fetch(since_seconds=3600, limit=10))
    assert len(events) == 1
    assert isinstance(events[0], LogEvent)
    assert events[0].hostname == "leaf01"
    assert "CRITICAL" in events[0].message
    assert "sysparm_display_value=true" in seen[0]
    assert "sys_created_on" in seen[0]

    incident = ServiceNowSource(_cfg(table="incident"))
    rows = list(incident.fetch())
    assert rows[0].hostname == "spine01"
    assert "ERROR" in rows[0].message
    assert "table/incident" in seen[-1]


def test_change_confidence_time_window_and_rollback() -> None:
    findings = [Finding("leaf01", "CRITICAL", "bgp neighbor down after mtu change")]
    near = ServiceNowChangeRecord(
        number="CHG0030001",
        short_description="bgp mtu change on the edge",
        cmdb_ci="leaf01.lab",
        start_date="2026-10-16T13:40:00Z",
        risk="High",
    )
    far = ServiceNowChangeRecord(
        number="CHG0030002",
        short_description="cosmetic banner edit",
        cmdb_ci="other-router",
        start_date="2026-10-15T00:00:00Z",
        risk="Moderate",
    )
    report = correlate_changes_with_findings(
        [far, near],
        findings,
        incident_timestamp="2026-10-16T14:00:00Z",
        lookback_minutes=180,
    )
    assert report.hits[0].change_number == "CHG0030001"
    assert report.hits[0].confidence == 1.0
    assert report.hits[0].rollback_recommended is True
    assert report.hits[0].time_delta_minutes == pytest.approx(20.0, abs=0.2)
    assert report.top_suspect_change == "CHG0030001"
    assert report.hits[1].confidence == 0.0
    assert report.hits[1].rollback_recommended is False


def test_sync_dry_run_and_idempotent_upsert(monkeypatch: pytest.MonkeyPatch) -> None:
    preview = ServiceNowClient("https://example.service-now.com", username="netops", password="x")
    dry = preview.sync_incident(
        {"summary": "bgp down", "devices": ["leaf01"]},
        dry_run=True,
    )
    assert dry.dry_run is True
    assert dry.action == "preview"
    assert dry.correlation_id.startswith("netlog-ai-")
    assert "work_notes" in dry.payload
    assert "Flap Dampening" in dry.payload["work_notes"]

    calls: list[tuple[str, str]] = []
    state = {"exists": False}

    def fake_open(req, timeout=15, context=None, **_kw):  # noqa: ANN001
        calls.append((req.method, req.full_url))
        if req.method == "GET":
            if state["exists"]:
                return _Body({"result": [{"sys_id": "sid-1", "number": "INC0010001"}]})
            return _Body({"result": []})
        if req.method == "POST":
            return _Body({"result": {"sys_id": "sid-2", "number": "INC0010002"}})
        return _Body({"result": {"sys_id": "sid-1", "number": "INC0010001"}})

    monkeypatch.setattr("ai_log_analyzer.sources.outbound.safe_urlopen", fake_open)
    created = preview.sync_incident({"summary": "bgp down", "devices": ["leaf01"]}, dry_run=False)
    assert created.action == "created"
    assert created.incident_number == "INC0010002"
    state["exists"] = True
    updated = preview.sync_incident({"summary": "bgp down", "devices": ["leaf01"]}, dry_run=False)
    assert updated.action == "updated"
    assert updated.sys_id == "sid-1"
    methods = [method for method, _url in calls]
    assert methods.count("POST") == 1
    assert "PATCH" in methods
    assert any("correlation_id" in url for _method, url in calls)


def test_deep_and_sync_routes(client) -> None:
    changes = [{
        "number": "CHG0030001",
        "short_description": "bgp mtu change",
        "cmdb_ci": "leaf01",
        "start_date": "2026-10-16T13:40:00Z",
        "risk": "High",
    }]
    deep = client.post("/api/analytics/deep", json={"log_text": _LOG, "changes": changes})
    assert deep.status_code == 200
    body = deep.get_json()
    assert body["flap_analysis"]["dampened_count"] == 1
    assert "leaf01" in body["device_overlays"]
    overlay = body["device_overlays"]["leaf01"]
    assert overlay["dampened_flaps"] >= 1
    assert overlay["active_change"] == "CHG0030001"
    assert "risk_tier" in overlay

    sync = client.post("/api/itsm/servicenow/sync", json={
        "log_text": _LOG,
        "changes": changes,
        "dry_run": True,
    })
    assert sync.status_code == 200
    synced = sync.get_json()
    assert synced["action"] == "preview"
    assert synced["correlation_id"].startswith("netlog-ai-")

    blocked = client.post("/api/itsm/servicenow/sync", json={
        "log_text": _LOG,
        "instance_url": "http://127.0.0.1",
        "dry_run": True,
    })
    assert blocked.status_code == 400


def test_mcp_deep_and_servicenow_tools() -> None:
    pytest.importorskip("mcp")
    from ai_log_analyzer.mcp_server.server import _build_server

    server = _build_server()
    names = {tool.name for tool in asyncio.run(server.list_tools())}
    assert {"netlog_deep_analytics", "netlog_servicenow_correlate_changes",
            "netlog_servicenow_sync_incident"} <= names
    deep = asyncio.run(server.call_tool("netlog_deep_analytics", {"log_text": _LOG}))
    assert deep.is_error is False
    content = deep.structured_content or {}
    assert content.get("flap_analysis", {}).get("dampened_count") == 1

    changes = json.dumps([{
        "number": "CHG0030001",
        "short_description": "bgp mtu change",
        "cmdb_ci": "leaf01",
        "start_date": "2026-10-16T13:40:00Z",
        "risk": "High",
    }])
    correlated = asyncio.run(server.call_tool(
        "netlog_servicenow_correlate_changes",
        {"log_text": _LOG, "changes_json": changes},
    ))
    assert correlated.is_error is False
    top = (correlated.structured_content or {})["change_correlation"]["top_suspect_change"]
    assert top == "CHG0030001"

    preview = asyncio.run(server.call_tool(
        "netlog_servicenow_sync_incident",
        {"log_text": _LOG, "dry_run": True, "changes_json": changes},
    ))
    assert preview.is_error is False
    assert (preview.structured_content or {})["action"] == "preview"


def test_frontend_overlay_markers() -> None:
    html = (_STATIC / "index.html").read_text(encoding="utf-8")
    script = (_STATIC / "app.js").read_text(encoding="utf-8")
    assert 'id="btn-deep-overlay"' in html
    assert 'id="deep-analytics-panel"' in html
    assert 'id="blast-radius-card"' in html
    assert 'id="flap-physics-card"' in html
    assert 'id="snow-correlation-card"' in html
    assert ".spof-critical" in script
    assert ".has-active-chg" in script
    assert "runDeepAnalyticsOverlay" in script
    assert "previewServiceNowSync" in script


def test_cli_deep_analytics_flag(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    log = tmp_path / "leaf.log"
    log.write_text("Oct 16 14:00:00 leaf01 bgpd[1]: bgp neighbor 192.0.2.1 down\n", encoding="utf-8")
    args = argparse.Namespace(
        frr=None, file=[str(log)], stdin=False, tail=50, no_llm=True,
        dedup=False, evpn_causal=False, remediation=False,
        deep_analytics=True, snow_changes_file="", snow_sync=False, snow_dry_run=False,
    )
    assert cmd_analyze(args) == 0
    payload = json.loads(capsys.readouterr().out)
    assert "deep_analytics" in payload
    assert "flap_analysis" in payload["deep_analytics"]
    assert "markdown" in payload["deep_analytics"]
