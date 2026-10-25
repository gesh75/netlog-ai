"""Credential pinning, redirect refusal and payload hygiene for the ITSM clients."""
from __future__ import annotations

import base64
import json
import socket
import urllib.request
from typing import Any

import pytest

from ai_log_analyzer.itsm import (
    IncidentEnrichmentPayload,
    JiraITSMClient,
    ServiceNowITSMClient,
)
from ai_log_analyzer.servicenow_sync import ServiceNowClient
from ai_log_analyzer.sources import SourceError

pytestmark = pytest.mark.unit

_ENV = {
    "SERVICENOW_URL": "https://corp.service-now.com",
    "SERVICENOW_USER": "svc-netlog",
    "SERVICENOW_PASSWORD": "env-pass-1",
    "SERVICENOW_TOKEN": "env-bearer-1",
    "JIRA_URL": "https://corp.atlassian.net",
    "JIRA_EMAIL": "bot@corp.example",
    "JIRA_API_TOKEN": "env-jira-token",
}


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    for name in ("SNOW_URL", "SNOW_USER", "SNOW_PASSWORD", "JIRA_BASE_URL",
                 "NETLOG_ALLOW_PRIVATE_OUTBOUND", "NETLOG_ALLOW_INSECURE_HTTP"):
        monkeypatch.delenv(name, raising=False)
    for name, value in _ENV.items():
        monkeypatch.setenv(name, value)


class _Resp:
    def __init__(self, payload: dict) -> None:
        self._raw = json.dumps(payload).encode()

    def read(self) -> bytes:
        return self._raw

    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *_a: object) -> bool:
        return False


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """Capture what would go on the wire instead of opening a socket."""
    requests: list[Any] = []

    def fake(req, timeout=15, **kw):  # noqa: ANN001
        requests.append((req, kw))
        return _Resp({"result": [], "issues": [], "key": "NET-1"})

    monkeypatch.setattr("ai_log_analyzer.sources.outbound.safe_urlopen", fake)
    return requests


def _payload(site: str = "DC1", summary: str = "bgp down") -> IncidentEnrichmentPayload:
    return IncidentEnrichmentPayload(
        site=site, root_device="leaf1", root_layer="L3", root_interface="Ethernet1",
        summary_title=summary, rca_rationale="because", confidence=0.9,
    )


# ── A: server credentials never go to a caller-chosen URL ────────────────────

def test_servicenow_sync_refuses_env_credentials_for_foreign_url(sent: list[Any]) -> None:
    client = ServiceNowClient(
        "https://attacker.example.com",
        username=_ENV["SERVICENOW_USER"], password=_ENV["SERVICENOW_PASSWORD"],
        bearer_token=_ENV["SERVICENOW_TOKEN"],
    )
    with pytest.raises(SourceError, match="refusing to send server-configured credentials"):
        client.sync_incident({"summary": "x", "devices": ["leaf1"]}, dry_run=False)
    with pytest.raises(SourceError, match="refusing"):
        client.fetch_recent_changes(["leaf1"])
    assert sent == []


def test_servicenow_sync_dry_run_never_trips_the_pin(sent: list[Any]) -> None:
    client = ServiceNowClient("https://attacker.example.com", username=_ENV["SERVICENOW_USER"],
                              password=_ENV["SERVICENOW_PASSWORD"])
    res = client.sync_incident({"summary": "x", "devices": ["leaf1"]}, dry_run=True)
    assert res.dry_run and sent == []


def test_servicenow_sync_sends_env_credentials_to_the_configured_url(sent: list[Any]) -> None:
    client = ServiceNowClient(_ENV["SERVICENOW_URL"] + "/", username=_ENV["SERVICENOW_USER"],
                              password=_ENV["SERVICENOW_PASSWORD"])
    client.sync_incident({"summary": "x", "devices": ["leaf1"]}, dry_run=False)
    req, _kw = sent[0]
    assert req.full_url.startswith("https://corp.service-now.com/api/now/table/incident")
    want = "Basic " + base64.b64encode(b"svc-netlog:env-pass-1").decode()
    assert req.get_header("Authorization") == want


def test_servicenow_sync_allows_a_foreign_url_with_the_callers_own_credentials(sent: list[Any]) -> None:
    client = ServiceNowClient("https://other.service-now.com", username="alice", password="alice-pw")
    client.sync_incident({"summary": "x", "devices": ["leaf1"]}, dry_run=False)
    assert sent and sent[0][0].full_url.startswith("https://other.service-now.com/")


def test_itsm_clients_pin_env_credentials(sent: list[Any]) -> None:
    with pytest.raises(SourceError, match="refusing"):
        ServiceNowITSMClient("https://attacker.example.com", _ENV["SERVICENOW_USER"],
                             _ENV["SERVICENOW_PASSWORD"])
    with pytest.raises(SourceError, match="refusing"):
        JiraITSMClient("https://attacker.example.com", _ENV["JIRA_EMAIL"], _ENV["JIRA_API_TOKEN"])
    # mixed: caller supplies the user but the password is the server's
    with pytest.raises(SourceError, match="refusing"):
        ServiceNowITSMClient("https://attacker.example.com", "mallory", _ENV["SERVICENOW_PASSWORD"])
    ok = JiraITSMClient(_ENV["JIRA_URL"], _ENV["JIRA_EMAIL"], _ENV["JIRA_API_TOKEN"])
    ok.find_open_issue_by_fingerprint("NETLOG-X")
    assert sent[0][0].full_url.startswith("https://corp.atlassian.net/rest/api/2/search")
    mine = JiraITSMClient("https://mine.atlassian.net", "me@x.example", "my-token")
    mine.find_open_issue_by_fingerprint("NETLOG-X")
    assert sent[1][0].full_url.startswith("https://mine.atlassian.net/")


@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "ftp://example.com", "http://example.com", "https://169.254.169.254",
    "https://2130706433", "https://127.1", "https://u:p@example.com",
])
def test_itsm_clients_reject_bad_urls_even_with_own_credentials(url: str) -> None:
    with pytest.raises(SourceError):
        JiraITSMClient(url, "me@x.example", "tok")
    with pytest.raises(SourceError):
        ServiceNowITSMClient(url, "me", "pw")
    with pytest.raises(SourceError):
        ServiceNowClient(url, username="me", password="pw")


def test_itsm_request_uses_the_hardened_opener_and_never_raw_urlopen(
        monkeypatch: pytest.MonkeyPatch, sent: list[Any]) -> None:
    def boom(*_a, **_k):
        raise AssertionError("raw urllib urlopen must not be used for credentialed calls")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    JiraITSMClient(_ENV["JIRA_URL"], _ENV["JIRA_EMAIL"], _ENV["JIRA_API_TOKEN"]).find_open_issue_by_fingerprint("N")
    ServiceNowITSMClient(_ENV["SERVICENOW_URL"], _ENV["SERVICENOW_USER"],
                         _ENV["SERVICENOW_PASSWORD"]).find_active_incident("N")
    ServiceNowClient(_ENV["SERVICENOW_URL"], username=_ENV["SERVICENOW_USER"],
                     password=_ENV["SERVICENOW_PASSWORD"]).fetch_recent_changes(["a"])
    assert len(sent) == 3


def test_redirect_to_another_host_is_refused_end_to_end(monkeypatch: pytest.MonkeyPatch) -> None:
    """The real opener: a 302 from the instance must not be followed (and must not
    replay the Authorization header at the Location target)."""
    import http.server
    import threading

    hits: list[tuple[str, str]] = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            hits.append((self.path, self.headers.get("Authorization", "")))
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/steal")
            self.end_headers()

        def log_message(self, *_a):
            pass

    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        client = ServiceNowITSMClient(f"http://127.0.0.1:{srv.server_address[1]}", "alice", "pw",
                                      allow_private=True)
        with pytest.raises(SourceError, match="redirect"):
            client.find_active_incident("NETLOG-1")
    finally:
        srv.shutdown()
        srv.server_close()
    assert [p for p, _ in hits] and all("steal" not in p for p, _ in hits)


def test_dns_name_resolving_to_loopback_is_refused_for_a_foreign_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda host, port, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))])
    client = ServiceNowITSMClient("https://rebind.example.com", "alice", "pw")
    with pytest.raises(SourceError):
        client.find_active_incident("NETLOG-1")


# ── D: free text is sanitized, labels are Jira-safe ──────────────────────────

def test_jira_label_is_sanitized_for_sites_with_spaces() -> None:
    labels = _payload(site="DC East 1").to_jira_issue_fields("NET")["labels"]
    assert "site-DC-East-1" in labels
    assert all(" " not in label for label in labels)


def test_jira_and_servicenow_bodies_are_sanitized(sent: list[Any]) -> None:
    secret = "snmp-server community SECRETHASH RO"
    jira = JiraITSMClient(_ENV["JIRA_URL"], _ENV["JIRA_EMAIL"], _ENV["JIRA_API_TOKEN"])
    jira.upsert_incident(_payload(summary=f"leak {secret}"))
    created = [json.loads(r.data) for r, _ in sent if r.get_method() == "POST"][0]
    assert "SECRETHASH" not in json.dumps(created)

    sent.clear()
    snow = ServiceNowITSMClient(_ENV["SERVICENOW_URL"], _ENV["SERVICENOW_USER"], _ENV["SERVICENOW_PASSWORD"])
    snow.upsert_incident(_payload(summary=f"leak {secret}"))
    created = [json.loads(r.data) for r, _ in sent if r.get_method() == "POST"][0]
    assert "SECRETHASH" not in json.dumps(created)


# ── F: version single-sourcing ───────────────────────────────────────────────

def test_user_agent_uses_package_version(sent: list[Any]) -> None:
    from ai_log_analyzer import __version__

    JiraITSMClient(_ENV["JIRA_URL"], _ENV["JIRA_EMAIL"], _ENV["JIRA_API_TOKEN"]).find_open_issue_by_fingerprint("N")
    ServiceNowClient(_ENV["SERVICENOW_URL"], username=_ENV["SERVICENOW_USER"],
                     password=_ENV["SERVICENOW_PASSWORD"]).fetch_recent_changes([])
    for req, _kw in sent:
        assert req.get_header("User-agent") == f"netlog-ai/{__version__}"
