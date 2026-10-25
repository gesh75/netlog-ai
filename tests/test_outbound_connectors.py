"""Connector correctness: query construction, ordering, caps, injection, error mapping."""
from __future__ import annotations

import json
import urllib.parse
from typing import Any

import pytest
import requests

from ai_log_analyzer.netbox import NetBoxClient, NetBoxError
from ai_log_analyzer.servicenow_sync import ServiceNowClient
from ai_log_analyzer.sources import SourceConfig, SourceError
from ai_log_analyzer.sources.kibana import KibanaSource
from ai_log_analyzer.sources.librenms import LibreNMSSource
from ai_log_analyzer.sources.loki import LokiSource
from ai_log_analyzer.sources.servicenow import ServiceNowSource, _query
from ai_log_analyzer.sources.solarwinds import (
    SolarWindsConfig,
    SolarWindsConnector,
    _fair_cap,
)
from ai_log_analyzer.sources.splunk import SplunkSource

pytestmark = pytest.mark.unit

_EVIL = ['leaf1"} |= "x', "../../api/v0/devices", "x^ORcmdb_ciLIKEy", "a b", "a;b"]


class _Resp:
    def __init__(self, payload: Any, status: int = 200) -> None:
        self._payload, self.status_code = payload, status
        self.content = json.dumps(payload).encode()

    def json(self) -> Any:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(str(self.status_code))


# ── host_filter allowlist in every connector ─────────────────────────────────

@pytest.mark.parametrize("bad", _EVIL)
def test_host_filter_injection_rejected_by_connectors(monkeypatch: pytest.MonkeyPatch, bad: str) -> None:
    def no_network(*_a, **_k):
        raise AssertionError("must reject before any request")

    cfg = dict(id="x", url="https://h.example.com", api_token="t", username="u", password="p")
    for cls, kind in ((KibanaSource, "kibana"), (SplunkSource, "splunk"),
                      (LokiSource, "loki"), (LibreNMSSource, "librenms")):
        src = cls(SourceConfig(type=kind, **cfg))
        for verb in ("get", "post"):
            monkeypatch.setattr(src.session, verb, no_network)
        with pytest.raises(SourceError, match="host_filter"):
            list(src.fetch(host_filter=bad))
    snow = ServiceNowSource(SourceConfig(type="servicenow", **cfg))
    monkeypatch.setattr("ai_log_analyzer.sources.outbound.safe_urlopen", no_network)
    with pytest.raises(SourceError, match="host_filter"):
        list(snow.fetch(host_filter=bad))


def test_librenms_path_is_quoted(monkeypatch: pytest.MonkeyPatch) -> None:
    src = LibreNMSSource(SourceConfig(id="l", type="librenms", url="https://l.example.com", api_token="t"))
    seen: list[str] = []
    monkeypatch.setattr(src.session, "get", lambda url, **k: seen.append(url) or _Resp({"logs": []}))
    list(src.fetch(host_filter="sw-1.dc1"))
    assert seen[0].endswith("/api/v0/logs/eventlog/sw-1.dc1")


# ── ServiceNow change fetch ──────────────────────────────────────────────────

def _changes_client(monkeypatch: pytest.MonkeyPatch) -> tuple[ServiceNowClient, list[str]]:
    seen: list[str] = []

    def fake(req, timeout=15, **_kw):  # noqa: ANN001
        seen.append(req.full_url)

        class R:
            def read(self_inner):  # noqa: N805
                return b'{"result": []}'

            def __enter__(self_inner):  # noqa: N805
                return self_inner

            def __exit__(self_inner, *a):  # noqa: N805
                return False
        return R()

    monkeypatch.setattr("ai_log_analyzer.sources.outbound.safe_urlopen", fake)
    return ServiceNowClient("https://o.service-now.com", username="u", password="p"), seen


def _query_param(url: str) -> str:
    return urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["sysparm_query"][0]


def test_change_query_matches_reference_by_name_escapes_caret_and_orders(monkeypatch: pytest.MonkeyPatch) -> None:
    client, seen = _changes_client(monkeypatch)
    client.fetch_recent_changes(["leaf1", "evil^ORnumberSTARTSWITHCHG", "a,b"], limit=50)
    query = _query_param(seen[0])
    assert query.startswith("cmdb_ci.nameINleaf1,evil^^ORnumberSTARTSWITHCHG^")
    assert "a,b" not in query
    assert query.endswith("ORDERBYDESCsys_updated_on")
    client.fetch_recent_changes(None)
    assert _query_param(seen[1]) == "ORDERBYDESCsys_updated_on"


def test_incident_upsert_lookup_requires_active(monkeypatch: pytest.MonkeyPatch) -> None:
    client, seen = _changes_client(monkeypatch)
    client.sync_incident({"summary": "x", "devices": ["leaf1"]}, dry_run=False)
    assert _query_param(seen[0]).endswith("^active=true")


# ── ServiceNow log source ordering + pagination ──────────────────────────────

def test_servicenow_source_orders_newest_first_and_paginates(monkeypatch: pytest.MonkeyPatch) -> None:
    pages: list[dict[str, str]] = []

    def row(i: int) -> dict:
        return {"short_description": f"alert {i}", "cmdb_ci": "leaf1", "sys_created_on": "2026-10-16 10:00:00"}

    class R:
        def __init__(self, n: int) -> None:
            self.raw = json.dumps({"result": [row(i) for i in range(n)]}).encode()

        def read(self) -> bytes:
            return self.raw

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake(req, timeout=15, **_kw):  # noqa: ANN001
        q = {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlparse(req.full_url).query).items()}
        pages.append(q)
        return R(int(q["sysparm_limit"]))

    monkeypatch.setattr("ai_log_analyzer.sources.outbound.safe_urlopen", fake)
    src = ServiceNowSource(SourceConfig(id="s", type="servicenow", url="https://o.service-now.com",
                                        username="u", password="p"))
    events = list(src.fetch(limit=2500))
    assert len(events) == 2500
    assert [p["sysparm_offset"] for p in pages] == ["0", "1000", "2000"]
    assert [p["sysparm_limit"] for p in pages] == ["1000", "1000", "500"]
    assert all(p["sysparm_query"].endswith("ORDERBYDESCsys_created_on") for p in pages)


def test_servicenow_query_orders_after_filters() -> None:
    cfg = SourceConfig(id="s", type="servicenow", url="https://o.service-now.com",
                       extra={"sysparm_query": "priority=1"})
    q = _query(cfg, since_seconds=60, host_filter="leaf1")
    assert q.split("^")[-2:] == ["cmdb_ciLIKEleaf1", "ORDERBYDESCsys_created_on"]
    assert "priority=1" in q


# ── SolarWinds ───────────────────────────────────────────────────────────────

def _sw(mode: str = "swis") -> SolarWindsConnector:
    return SolarWindsConnector(SolarWindsConfig(endpoint_url="https://o.example.com:17778",
                                                api_token="t", mode=mode))  # type: ignore[arg-type]


def test_fair_cap_shares_the_budget() -> None:
    alerts = [f"a{i}" for i in range(900)]
    syslog = [f"s{i}" for i in range(900)]
    out = _fair_cap([alerts, syslog, []], 500)
    assert len(out) == 500
    assert sum(1 for line in out if line.startswith("s")) == 250
    assert _fair_cap([["a"], [f"s{i}" for i in range(10)]], 6) == ["a", "s0", "s1", "s2", "s3", "s4"]
    assert _fair_cap([["a", "b"]], 0) == []


def test_pull_logs_cap_keeps_syslog_when_alerts_flood() -> None:
    conn = _sw()
    flood = [{"TriggeredMessage": f"alert {i}", "EntityCaption": "core"} for i in range(900)]
    sys_rows = [{"Message": f"sys {i}", "Caption": "core", "LogLevel": "err"} for i in range(900)]

    def fake(method: str, path: str, **kw: Any) -> dict:
        query = (kw.get("json") or {}).get("query", "")
        if "AlertActive" in query:
            return {"results": flood}
        if "OLM.LogEntry" in query:
            return {"results": sys_rows}
        return {"results": []}

    conn._request = fake  # type: ignore[method-assign]
    lines = conn.pull_logs(limit=500)
    assert len(lines) == 500
    assert any("SolarWindsSyslog" in line for line in lines)


def test_swql_orders_newest_first_under_top() -> None:
    conn = _sw()
    queries: list[str] = []

    def fake(method: str, path: str, **kw: Any) -> dict:
        queries.append((kw.get("json") or {}).get("query", ""))
        return {"results": []}

    conn._request = fake  # type: ignore[method-assign]
    conn.pull_logs(limit=5)
    conn.pull_logs(limit=5, host_filter="leaf1")
    top = [q for q in queries if "TOP 10000" in q]
    assert len(top) >= 6
    assert all("ORDER BY" in q and q.rstrip().endswith("DESC") for q in top)


def test_solarwinds_http_and_json_errors_become_source_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _sw()
    monkeypatch.setattr(conn.session, "request", lambda *a, **k: _Resp({}, status=500))
    with pytest.raises(SourceError, match="HTTP 500"):
        conn.fetch_active_alerts()

    class BadJson(_Resp):
        def json(self):
            raise ValueError("not json")

    monkeypatch.setattr(conn.session, "request", lambda *a, **k: BadJson({"x": 1}))
    with pytest.raises(SourceError, match="non-JSON"):
        conn.fetch_active_alerts()

    def boom(*_a, **_k):
        raise requests.exceptions.ConnectionError("refused")

    monkeypatch.setattr(conn.session, "request", boom)
    with pytest.raises(SourceError):
        conn.fetch_active_alerts()


def test_olm_http_error_still_falls_back_to_syslog(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _sw()
    seen: list[str] = []

    def fake_request(method, url, **kw):
        query = (kw.get("json") or {}).get("query", "")
        seen.append(query)
        if "OLM.LogEntry" in query:
            return _Resp({}, status=404)
        return _Resp({"results": [{"Message": "m", "Caption": "h"}]})

    monkeypatch.setattr(conn.session, "request", fake_request)
    rows = conn._swis_syslog(since_seconds=60, host_filter="")
    assert rows and "Orion.SysLog" in seen[-1]


# ── Loki truncation flag ─────────────────────────────────────────────────────

def test_loki_flags_and_logs_truncation(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    src = LokiSource(SourceConfig(id="lk", type="loki", url="https://l.example.com", api_token="t"))
    seen: list[dict] = []

    def fake_get(url, params=None, **k):
        seen.append(params)
        n = int(params["limit"])
        return _Resp({"data": {"result": [{"stream": {"host": "h"},
                                           "values": [[str(i), f"line {i}"] for i in range(n)]}]}})

    monkeypatch.setattr(src.session, "get", fake_get)
    with caplog.at_level("WARNING"):
        assert len(list(src.fetch(limit=20_000))) == 5000
    assert seen[0]["limit"] == "5000"
    assert src.last_truncated is True
    assert "truncated" in caplog.text or "page cap" in caplog.text
    assert len(list(src.fetch(limit=10))) == 10
    assert src.last_truncated is False


# ── NetBox: errors are not "not found" ───────────────────────────────────────

def test_netbox_api_error_is_reported_as_error_not_missing() -> None:
    import urllib.error
    from io import BytesIO

    def broken(request, timeout=None):
        raise urllib.error.HTTPError(request.full_url, 500, "boom", hdrs={}, fp=BytesIO(b""))

    client = NetBoxClient(url="https://nb.example.com", token="tok", opener=broken)
    record = client.enrich("leaf1")
    assert record["found"] is None
    assert "500" in record["error"]
    assert "tok" not in json.dumps(record)
    with pytest.raises(NetBoxError):
        client._device_record("leaf1")

    class Empty:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"results": []}'

    missing = NetBoxClient(url="https://nb.example.com", token="tok", opener=lambda r, timeout=None: Empty())
    assert missing.enrich("leaf1")["found"] is False
