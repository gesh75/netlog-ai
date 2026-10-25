"""SSRF guard: numeric host spellings, DNS resolution, redirects, registry wiring.

No real DNS or network: ``socket.getaddrinfo`` is monkeypatched and the only
sockets are 127.0.0.1 ephemeral servers.
"""
from __future__ import annotations

import http.server
import socket
import threading
import urllib.request

import pytest

from ai_log_analyzer.sources import SourceConfig, SourceError, registry
from ai_log_analyzer.sources.base import guarded_session, validate_host_filter, validate_outbound_url
from ai_log_analyzer.sources.manager import SourceManager
from ai_log_analyzer.sources.outbound import safe_urlopen

pytestmark = pytest.mark.unit

_PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")


@pytest.fixture(autouse=True)
def _no_proxy_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _PROXY_VARS:
        monkeypatch.delenv(name, raising=False)
    for name in ("NETLOG_ALLOW_PRIVATE_OUTBOUND", "NETLOG_ALLOW_INSECURE_HTTP"):
        monkeypatch.delenv(name, raising=False)


def _dns(monkeypatch: pytest.MonkeyPatch, table: dict[str, list[str]]) -> list[str]:
    """Fake getaddrinfo: ``table`` maps host -> addresses; unknown hosts raise."""
    calls: list[str] = []

    def fake(host, port, *_a, **_k):
        calls.append(host)
        if host not in table:
            raise socket.gaierror(-2, "Name or service not known")
        out = []
        for addr in table[host]:
            fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
            out.append((fam, socket.SOCK_STREAM, 6, "", (addr, port or 0)))
        return out

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    return calls


@pytest.mark.parametrize("url", [
    "http://2130706433/",          # decimal 127.0.0.1
    "http://127.1/",
    "http://0x7f.0.0.1/",
    "http://0177.0.0.1/",
    "http://0x7f000001/",
    "http://017700000001/",
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:7f00:1]/",
    "http://0.0.0.0/",
    "http://0/",
    "http://169.254.169.254/latest/meta-data",
    "http://2852039166/",          # decimal 169.254.169.254
    "http://100.100.100.200/",     # Alibaba metadata
    "http://100.64.0.1/",          # CGNAT
    "http://10.1.2.3/",
    "http://192.168.0.1/",
    "http://172.16.0.1/",
    "http://metadata.google.internal/",
    "http://localhost/",
    "http://foo.localhost/",
    "file:///etc/passwd",
    "ftp://example.com/x",
    "gopher://example.com/",
    "http:///nohost",
])
def test_literal_and_legacy_numeric_hosts_are_blocked(url: str) -> None:
    with pytest.raises(SourceError):
        validate_outbound_url(url, resolve=False)


@pytest.mark.parametrize("host,addr", [
    ("localtest.me", "127.0.0.1"),
    ("169.254.169.254.nip.io", "169.254.169.254"),
    ("internal.corp.example", "10.0.0.5"),
    ("cgnat.example", "100.64.3.3"),
    ("v6.example", "::1"),
    ("mapped.example", "::ffff:10.0.0.1"),
])
def test_dns_names_are_resolved_and_checked(monkeypatch: pytest.MonkeyPatch, host: str, addr: str) -> None:
    _dns(monkeypatch, {host: [addr]})
    with pytest.raises(SourceError):
        validate_outbound_url(f"https://{host}/")


def test_every_resolved_address_is_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    _dns(monkeypatch, {"mixed.example": ["93.184.216.34", "169.254.169.254"]})
    with pytest.raises(SourceError, match="blocked address"):
        validate_outbound_url("https://mixed.example/")


def test_unresolvable_host_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _dns(monkeypatch, {})
    with pytest.raises(SourceError, match="does not resolve"):
        validate_outbound_url("https://nope.example/")


def test_public_host_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _dns(monkeypatch, {"es.example.com": ["93.184.216.34", "2606:2800:220:1::1"]})
    assert validate_outbound_url("https://es.example.com:9200/x") == "https://es.example.com:9200/x"


def test_allow_private_permits_private_and_loopback_but_never_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    _dns(monkeypatch, {"corp.example": ["10.0.0.5"], "meta.example": ["169.254.169.254"]})
    assert validate_outbound_url("https://corp.example/", allow_private=True)
    assert validate_outbound_url("http://127.0.0.1:8080/", allow_private=True)
    assert validate_outbound_url("http://100.64.1.1/", allow_private=True)
    for url in ("https://meta.example/", "http://169.254.169.254/", "http://0.0.0.0/",
                "http://100.100.100.200/", "http://metadata.google.internal/"):
        with pytest.raises(SourceError):
            validate_outbound_url(url, allow_private=True)


def test_global_env_flag_acts_as_allow_private(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(SourceError):
        validate_outbound_url("http://10.0.0.1/")
    monkeypatch.setenv("NETLOG_ALLOW_PRIVATE_OUTBOUND", "1")
    assert validate_outbound_url("http://10.0.0.1/")


def test_require_https(monkeypatch: pytest.MonkeyPatch) -> None:
    _dns(monkeypatch, {"pub.example": ["93.184.216.34"]})
    with pytest.raises(SourceError, match="https"):
        validate_outbound_url("http://pub.example/", require_https=True)
    with pytest.raises(SourceError, match="https"):   # allow_private does not excuse a public host
        validate_outbound_url("http://pub.example/", require_https=True, allow_private=True)
    with pytest.raises(SourceError):                  # private host over http needs allow_private
        validate_outbound_url("http://10.0.0.1/", require_https=True)
    assert validate_outbound_url("http://127.0.0.1/", require_https=True, allow_private=True)
    monkeypatch.setenv("NETLOG_ALLOW_INSECURE_HTTP", "1")
    assert validate_outbound_url("http://pub.example/", require_https=True)
    with pytest.raises(SourceError, match="credentials"):
        validate_outbound_url("https://user:pw@pub.example/", require_https=True)


# ── host_filter allowlist ────────────────────────────────────────────────────

@pytest.mark.parametrize("bad", [
    '../../admin', 'leaf1"} |= "', 'x^ORcmdb_ciLIKEy', "a b", "a;b", "leaf\n1", "x" * 300, "a..b", "a/b",
])
def test_host_filter_rejects_injection(bad: str) -> None:
    with pytest.raises(SourceError):
        validate_host_filter(bad)


@pytest.mark.parametrize("good", ["leaf1", "leaf-1.dc1.example.com", "10.0.0.1", "fe80::1", "leaf*", ""])
def test_host_filter_accepts_names(good: str) -> None:
    assert validate_host_filter(good) == good


# ── registry wiring ──────────────────────────────────────────────────────────

def test_manager_add_applies_guard_to_every_network_connector(monkeypatch: pytest.MonkeyPatch) -> None:
    _dns(monkeypatch, {"evil.example": ["127.0.0.1"]})
    mgr = SourceManager()
    for kind, extra in (("kibana", {}), ("elasticsearch", {}), ("splunk", {}), ("loki", {}),
                        ("librenms", {}), ("servicenow", {}), ("solarwinds", {})):
        cfg = SourceConfig(id="x1", type=kind, url="https://evil.example", api_token="t",
                           username="u", password="p", extra=extra)
        with pytest.raises(SourceError):
            mgr.add(cfg)
    assert mgr.list_ids() == []


def test_extra_allow_private_from_a_caller_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    mgr = SourceManager()
    cfg = SourceConfig(id="k1", type="loki", url="http://10.0.0.7:3100", api_token="t",
                       extra={"allow_private": "true"})
    with pytest.raises(SourceError):
        mgr.add(cfg)
    # ...but the operator's own env knob (or an env-declared URL) still works
    monkeypatch.setenv("NETLOG_SOURCE_k1_ALLOW_PRIVATE", "true")
    assert mgr.add(cfg) is not None
    mgr.shutdown()


def test_operator_env_url_is_trusted_for_private_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    mgr = SourceManager()
    cfg = SourceConfig(id="k2", type="loki", url="http://10.0.0.7:3100", api_token="t")
    with pytest.raises(SourceError):
        mgr.add(cfg)
    monkeypatch.setenv("NETLOG_SOURCE_k2_URL", "http://10.0.0.7:3100")
    assert mgr.add(cfg) is not None
    # an attacker-chosen URL under the same id is not covered by that trust
    with pytest.raises(SourceError):
        mgr.add(SourceConfig(id="k2", type="loki", url="http://10.9.9.9:3100", api_token="t"))
    mgr.shutdown()


def test_non_network_kinds_are_not_resolved() -> None:
    class _Stub:
        kind = "stub-w2"
        name = "s"

        def healthcheck(self): return True
        def fetch(self, **_k): return []
        def close(self): return None

    registry.register("stub-w2", lambda cfg: _Stub())
    try:
        assert registry.create(SourceConfig(id="s", type="stub-w2", url="http://x")) is not None
    finally:
        registry._factories.pop("stub-w2", None)


# ── live sockets: redirects + connect-time check ─────────────────────────────

class _Handler(http.server.BaseHTTPRequestHandler):
    hits: list[str] = []

    def do_GET(self):  # noqa: N802
        _Handler.hits.append(self.path)
        if self.path.startswith("/redir"):
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest")
            self.end_headers()
            return
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a):
        pass


@pytest.fixture
def local_server():
    _Handler.hits = []
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def test_safe_urlopen_blocks_loopback_unless_allowed(local_server: str) -> None:
    req = urllib.request.Request(local_server + "/x")
    with pytest.raises(SourceError):
        safe_urlopen(req, 5, require_https=False)
    assert _Handler.hits == []
    with safe_urlopen(req, 5, allow_private=True, require_https=False) as resp:
        assert resp.status == 200
    assert _Handler.hits == ["/x"]


def test_safe_urlopen_never_follows_redirects(local_server: str) -> None:
    req = urllib.request.Request(local_server + "/redir", headers={"Authorization": "Basic c2VjcmV0"})
    with pytest.raises(SourceError, match="redirect"):
        safe_urlopen(req, 5, allow_private=True, require_https=False)
    assert _Handler.hits == ["/redir"]


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://127.0.0.1/x", "http://127.0.0.1/"])
def test_safe_urlopen_rejects_bad_schemes_and_plain_http(url: str) -> None:
    with pytest.raises(SourceError):
        safe_urlopen(urllib.request.Request(url), 5)


def test_connect_time_check_defeats_dns_rebinding(monkeypatch: pytest.MonkeyPatch, local_server: str) -> None:
    port = int(local_server.rsplit(":", 1)[1])
    answers = iter([["93.184.216.34"], ["127.0.0.1"], ["127.0.0.1"]])

    def rebinding(host, p, *_a, **_k):
        addr = next(answers)[0]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (addr, p or 0))]

    monkeypatch.setattr(socket, "getaddrinfo", rebinding)
    with pytest.raises(SourceError, match="loopback"):
        safe_urlopen(urllib.request.Request(f"http://rebind.example:{port}/x"), 5, require_https=False)
    assert _Handler.hits == []


def test_guarded_session_revalidates_redirect_targets(local_server: str) -> None:
    session = guarded_session(allow_private=True)
    with pytest.raises(SourceError):
        session.get(local_server + "/redir", timeout=5)
    assert session.get(local_server + "/ok", timeout=5).status_code == 200
