"""The SSRF guard of the requests-based connectors must bind to the address it checked (CWE-918).

Registration-time validation alone is not enough: a name that resolves to a public address when the source is
added can resolve to loopback / link-local / metadata when the request is made (DNS rebinding), and the
checked name can differ from the one the transport connects to (IDNA 2003 vs UTS46: ``faß`` is ``fass`` in
the stdlib and ``xn--fa-hia`` in requests). Every connection a connector opens goes only to an address that
was checked immediately before connecting; the name used for SNI, certificate checks and Host stays as given.

No real DNS or internet: ``socket.getaddrinfo`` is stubbed and the only sockets are 127.0.0.1 ephemeral ones.
"""
from __future__ import annotations

import errno
import http.server
import socket
import ssl
import threading

import pytest
import requests

from ai_log_analyzer.sources import SourceConfig, SourceError, registry
from ai_log_analyzer.sources.base import guarded_session, validate_outbound_url

pytestmark = pytest.mark.unit

PUBLIC = "93.184.216.34"
_PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy", "NO_PROXY", "no_proxy")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _PROXY_VARS:
        monkeypatch.delenv(name, raising=False)
    for name in ("NETLOG_ALLOW_PRIVATE_OUTBOUND", "NETLOG_ALLOW_INSECURE_HTTP"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def net(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record every TCP connect attempt; anything that is not loopback is refused locally, so even a guard
    that fails can never touch a real network from this suite."""
    real = socket.socket.connect
    attempts: list[str] = []

    def connect(self, address):
        host = str(address[0] if isinstance(address, tuple) else address)
        attempts.append(host)
        if not (host.startswith("127.") or host in ("0.0.0.0", "::1")):
            raise OSError(errno.ENETUNREACH, "test: non-loopback connect refused")
        return real(self, address)

    monkeypatch.setattr(socket.socket, "connect", connect)
    return attempts


def _external(attempts: list[str]) -> list[str]:
    return [a for a in attempts if not (a.startswith("127.") or a in ("0.0.0.0", "::1"))]


class _Handler(http.server.BaseHTTPRequestHandler):
    hits: list[tuple[str, str]] = []

    def do_GET(self):  # noqa: N802
        type(self).hits.append((self.path, self.headers.get("Host", "")))
        body = b'{"status": "green", "logs": [], "data": {"result": []}, "results": []}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = do_GET

    def log_message(self, *_a):
        pass


@pytest.fixture
def server():
    """A plain HTTP server on loopback: any hit on it is a connection the guard should have refused."""
    _Handler.hits = []
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


class Resolver:
    """Stub for socket.getaddrinfo. ``table`` maps an ASCII name to a list of answers, one per lookup of that
    name (the last answer repeats). Like the stdlib it encodes a non-ASCII name with the IDNA 2003 codec first."""

    def __init__(self, table: dict[str, list[list[str]]]) -> None:
        self.table = table
        self.calls: list[str] = []

    def __call__(self, host, port, *_a, **_k):
        name = host if host.isascii() else host.encode("idna").decode("ascii")
        n = self.calls.count(name)
        self.calls.append(name)
        if name not in self.table:
            raise socket.gaierror(-2, "Name or service not known")
        answers = self.table[name]
        out = []
        for addr in answers[min(n, len(answers) - 1)]:
            family = socket.AF_INET6 if ":" in addr else socket.AF_INET
            out.append((family, socket.SOCK_STREAM, 6, "", (addr, port or 0)))
        return out


def _resolver(monkeypatch: pytest.MonkeyPatch, table: dict[str, list[list[str]]]) -> Resolver:
    stub = Resolver(table)
    monkeypatch.setattr(socket, "getaddrinfo", stub)
    return stub


_KINDS = ["kibana", "elasticsearch", "splunk", "loki", "librenms", "solarwinds"]


def _config(kind: str, url: str, **kw) -> SourceConfig:
    return SourceConfig(id=f"{kind}-1", type=kind, url=url, api_token="S3cr3tExampleOnly",
                        username="svc", password="S3cr3tExampleOnly", **kw)


def _poke(src) -> None:
    """One healthcheck and one fetch; whatever the connector does, it must go through the guarded session."""
    src.healthcheck()
    list(src.fetch(since_seconds=60, limit=5))


# ── Test 1: DNS rebinding between registration and request ──────────────────

@pytest.mark.parametrize("kind", _KINDS)
@pytest.mark.parametrize("rebound_to", ["127.0.0.1", "0.0.0.0", "169.254.169.254", "10.0.0.5"])
def test_a_name_that_rebinds_to_an_internal_address_is_refused_at_request_time(
        monkeypatch: pytest.MonkeyPatch, server: int, net: list[str], kind: str, rebound_to: str) -> None:
    dns = _resolver(monkeypatch, {"rebind.example": [[PUBLIC], [rebound_to]]})
    src = registry.create(_config(kind, f"http://rebind.example:{server}"))   # public at add time
    assert dns.calls == ["rebind.example"]
    for call in (src.healthcheck, lambda: list(src.fetch(since_seconds=60, limit=5))):
        with pytest.raises(SourceError):
            call()
    assert _Handler.hits == [], "a credentialed request reached the rebound address"
    assert net == [], "a socket was opened towards a refused address"
    src.close()


def test_a_changed_dns_answer_refuses_the_next_fetch_of_a_long_lived_source(
        monkeypatch: pytest.MonkeyPatch, server: int, net: list[str]) -> None:
    dns = _resolver(monkeypatch, {"orion.example": [["127.0.0.1"], ["127.0.0.1"], ["169.254.169.254"]]})
    src = registry.create(_config("loki", f"http://orion.example:{server}", allow_private=True))
    assert src.healthcheck() is True                       # first request: operator-trusted private address
    n = len(_Handler.hits)
    src.session.close()                                    # drop the keep-alive connection: next call reconnects
    with pytest.raises(SourceError, match="blocked address"):
        src.healthcheck()                                  # DNS now points at the metadata service
    assert len(_Handler.hits) == n and _external(net) == []
    assert dns.calls.count("orion.example") == 3


# ── Test 2: IDNA differential ───────────────────────────────────────────────

_IDNA_TABLE = {"fass.evil.example": [[PUBLIC]], "xn--fa-hia.evil.example": [["127.0.0.1"]]}


def test_idna_lookalike_hosts_are_checked_under_the_name_the_transport_uses(
        monkeypatch: pytest.MonkeyPatch) -> None:
    _resolver(monkeypatch, _IDNA_TABLE)
    # the stdlib resolves "faß" as fass (public here); requests connects to xn--fa-hia (loopback here)
    with pytest.raises(SourceError, match="loopback"):
        validate_outbound_url("http://faß.evil.example:9200/")
    with pytest.raises(SourceError, match="loopback"):
        registry.create(_config("kibana", "http://faß.evil.example:9200"))


@pytest.mark.parametrize("kind", _KINDS)
def test_idna_lookalike_never_connects_to_the_internal_answer(
        monkeypatch: pytest.MonkeyPatch, server: int, net: list[str], kind: str) -> None:
    _resolver(monkeypatch, _IDNA_TABLE)
    src = None
    try:
        src = registry.create(_config(kind, f"http://faß.evil.example:{server}"))
        with pytest.raises(SourceError):
            _poke(src)
    except SourceError:
        pass                                               # refused already at registration: also fine
    assert _Handler.hits == [] and net == []
    if src is not None:
        src.close()


def test_fullwidth_digit_spellings_of_loopback_are_literals_not_names(monkeypatch: pytest.MonkeyPatch) -> None:
    _resolver(monkeypatch, {"127.0.0.1": [["127.0.0.1"]], "localhost": [["127.0.0.1"]]})
    for url in ("http://１２７.０.０.１/", "http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ/"):
        with pytest.raises(SourceError):
            validate_outbound_url(url)


# ── Test 3: redirect hops are checked before they are connected ─────────────

def test_a_redirect_hop_that_rebinds_is_refused(
        monkeypatch: pytest.MonkeyPatch, server: int, net: list[str]) -> None:
    class Redirect(_Handler):
        def do_GET(self):  # noqa: N802
            _Handler.hits.append((self.path, self.headers.get("Host", "")))
            self.send_response(302)
            self.send_header("Location", f"http://hop.example:{server_port}/next")
            self.send_header("Content-Length", "0")
            self.end_headers()

    srv = http.server.HTTPServer(("127.0.0.1", 0), Redirect)
    server_port = server
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
    try:
        # hop.example: public for the redirect pre-check, loopback-then-metadata when the hop connects
        _resolver(monkeypatch, {"127.0.0.1": [["127.0.0.1"]], "hop.example": [[PUBLIC], ["169.254.169.254"]]})
        session = guarded_session(allow_private=True)
        with pytest.raises(SourceError, match="blocked address"):
            session.get(f"http://127.0.0.1:{srv.server_address[1]}/start", timeout=5)
        assert [h[0] for h in _Handler.hits] == ["/start"]
        assert _external(net) == []
    finally:
        srv.shutdown()
        srv.server_close()


# ── Test 4: what must keep working ──────────────────────────────────────────

def test_the_connection_goes_to_the_address_that_was_checked_and_keeps_the_name(
        monkeypatch: pytest.MonkeyPatch, server: int) -> None:
    dns = _resolver(monkeypatch, {"loki.corp.example": [["127.0.0.1"]]})
    src = registry.create(_config("loki", f"http://loki.corp.example:{server}", allow_private=True))
    before = len(dns.calls)
    assert src.healthcheck() is True
    assert len(dns.calls) - before == 1                    # one lookup, and the connection used its result
    assert _Handler.hits == [("/ready", f"loki.corp.example:{server}")]   # Host is still the given name
    src.close()


def test_tls_server_name_and_certificate_checks_stay_on_the_original_name(
        monkeypatch: pytest.MonkeyPatch) -> None:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    accepted: list[tuple] = []
    threading.Thread(target=lambda: accepted.append(listener.accept()[1]), daemon=True).start()
    seen: dict = {}

    def fake_wrap(*_a, **kw):
        seen.update(kw)
        raise ssl.SSLError("stop after the TCP connect")

    monkeypatch.setattr("urllib3.connection.ssl_wrap_socket", fake_wrap)
    _resolver(monkeypatch, {"tls.corp.example": [["127.0.0.1"]]})
    with pytest.raises(requests.exceptions.SSLError):
        guarded_session(allow_private=True).get(f"https://tls.corp.example:{port}/x", timeout=5)
    listener.close()
    assert seen["server_hostname"] == "tls.corp.example"   # SNI / hostname verification: the given name
    assert accepted and accepted[0][0] == "127.0.0.1"      # TCP went to the checked address


def test_the_literal_and_private_rules_apply_to_every_request_not_only_registration(
        server: int, net: list[str]) -> None:
    session = guarded_session()                            # allow_private False
    with pytest.raises(SourceError):
        session.get(f"http://127.0.0.1:{server}/x", timeout=5)
    with pytest.raises(SourceError):
        session.get("http://169.254.169.254/latest/meta-data", timeout=5)
    assert _Handler.hits == [] and net == []
    assert guarded_session(allow_private=True).get(f"http://127.0.0.1:{server}/ok", timeout=5).status_code == 200
    with pytest.raises(SourceError):                       # link-local stays blocked even with allow_private
        guarded_session(allow_private=True).get("http://169.254.169.254/x", timeout=5)
