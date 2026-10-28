"""URL credentials must not leave through error text (CWE-209 / CWE-532).

``requests`` puts the full request URL, userinfo and query included, into the text of its exceptions. Connector
errors, the web API, MCP results, logs and audit rows must show neither the userinfo nor secret-looking query
values. One shared helper (``ai_log_analyzer.url_redact``) does the stripping for connectors, webhooks and the
triage sinks.
"""
from __future__ import annotations

import http.server
import json
import threading
import time

import pytest
import requests

from ai_log_analyzer.sources import SourceConfig, SourceError, registry
from ai_log_analyzer.sources.manager import SourceManager
from ai_log_analyzer.url_redact import redact_text, redact_url

pytestmark = pytest.mark.unit

SECRET = "S3cr3tExampleOnly"


# ── the helper ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("url,expected", [
    (f"https://svc:{SECRET}@es.example.com:9200/_search", "https://es.example.com:9200/_search"),
    (f"https://{SECRET}@es.example.com/x", "https://es.example.com/x"),
    (f"https://svc:{SECRET}@[2001:db8::1]:9200/x", "https://[2001:db8::1]:9200/x"),
    (f"https://svc:p%40ss{SECRET}@es.example.com/x", "https://es.example.com/x"),
    (f"https://es.example.com/x?token={SECRET}&q=1", "https://es.example.com/x?token=***&q=1"),
    (f"https://es.example.com/x?q=1&API_KEY={SECRET}", "https://es.example.com/x?q=1&API_KEY=***"),
    (f"https://es.example.com/x?sig={SECRET}&sv=1.0#frag", "https://es.example.com/x?sig=***&sv=1.0"),
    ("https://es.example.com/x?plain=1&flag", "https://es.example.com/x?plain=1&flag"),
    ("https://es.example.com", "https://es.example.com"),
])
def test_redact_url_keeps_the_path_and_masks_secrets(url: str, expected: str) -> None:
    assert redact_url(url) == expected


@pytest.mark.parametrize("url,expected", [
    (f"https://hooks.example.com/services/T000/B000/{SECRET}", "https://hooks.example.com/…"),
    (f"https://hooks.example.com/api/webhooks/1/{SECRET}?wait=true", "https://hooks.example.com/…"),
    (f"https://svc:{SECRET}@hooks.example.com:8443/x?sig={SECRET}", "https://hooks.example.com:8443/…"),
    ("https://hooks.example.com/", "https://hooks.example.com/"),
])
def test_redact_url_without_the_path_for_secret_paths(url: str, expected: str) -> None:
    assert redact_url(url, keep_path=False) == expected


@pytest.mark.parametrize("bad", ["", "not a url", "http://[::1", "https://", "://x", "http://h:99999999/p"])
def test_redact_url_never_raises_and_never_returns_more_than_it_got(bad: str) -> None:
    out = redact_url(bad)
    assert isinstance(out, str) and len(out) <= len(bad) + 20


_REQUESTS_TEXTS = [
    # requests.HTTPError
    f"401 Client Error: Unauthorized for url: https://svc:{SECRET}@es.example.com:9200/_cluster/health",
    f"503 Server Error: Service Unavailable for url: https://es.example.com/x?api_key={SECRET}&q=1",
    # urllib3 transport errors carry only path and query
    f"HTTPSConnectionPool(host='es.example.com', port=443): Max retries exceeded with url: "
    f"/services/T000/B000/{SECRET} (Caused by NameResolutionError(\"x\"))",
    f"HTTPSConnectionPool(host='es.example.com', port=443): Max retries exceeded with url: "
    f"/x?token={SECRET} (Caused by ConnectTimeoutError(<conn>, 'timed out'))",
    # requests.InvalidURL / MissingSchema
    f"Invalid URL 'https://svc:{SECRET}@': No host supplied",
    f"Invalid URL '/services/T000/B000/{SECRET}': No scheme supplied. Perhaps you meant https:///services/T000/B000/{SECRET}?",
    # proxy credentials inside a ProxyError
    f"Unable to connect to proxy (Caused by NewConnectionError('x')) http://puser:{SECRET}@proxy.example.com:3128",
]


@pytest.mark.parametrize("text", _REQUESTS_TEXTS)
def test_redact_text_removes_every_secret_form_from_exception_text(text: str) -> None:
    assert SECRET not in redact_text(text, keep_path=False)
    out = redact_text(text)
    # with the path kept, only a path that is itself a secret may remain (connector paths are not secrets)
    assert f"{SECRET}@" not in out and f"token={SECRET}" not in out and f"api_key={SECRET}" not in out


def test_redact_text_keeps_the_useful_part_of_the_message() -> None:
    out = redact_text(_REQUESTS_TEXTS[0])
    assert out == "401 Client Error: Unauthorized for url: https://es.example.com:9200/_cluster/health"
    out = redact_text(_REQUESTS_TEXTS[2], keep_path=False)
    assert out.startswith("HTTPSConnectionPool(host='es.example.com', port=443): Max retries exceeded with url: /…")
    assert "(Caused by NameResolutionError" in out


def test_redact_text_is_idempotent_and_passes_plain_text_through() -> None:
    for text in _REQUESTS_TEXTS:
        once = redact_text(text)
        assert redact_text(once) == once
    assert redact_text("connection reset by peer") == "connection reset by peer"
    assert redact_text("") == "" and redact_text(None) == ""   # type: ignore[arg-type]
    assert redact_text(ValueError(f"bad https://u:{SECRET}@h.example/")) == "bad https://h.example/"   # type: ignore[arg-type]


def test_redact_text_handles_several_urls_and_trailing_punctuation() -> None:
    text = f"tried https://a:{SECRET}@one.example/x, then (https://b:{SECRET}@two.example/y). done"
    assert redact_text(text) == "tried https://one.example/x, then (https://two.example/y). done"


# ReDoS / scaling: the scanner is linear, whatever shape the text has.
_ADVERSARIAL = [
    lambda n: "a" * n,
    lambda n: "://" * (n // 3),
    lambda n: "http://" * (n // 7),
    lambda n: "a" * n + "://",
    lambda n: "url: /" * (n // 6),
    lambda n: "Invalid URL '" * (n // 13),
    lambda n: "http://" + "?a=" * (n // 3),
    lambda n: "http://u:" + "@" * n,
]


@pytest.mark.parametrize("make", _ADVERSARIAL)
def test_redact_text_scales_linearly_on_adversarial_input(make) -> None:
    def cost(n: int) -> float:
        text = make(n)
        best = 1e9
        for _ in range(3):
            t0 = time.perf_counter()
            redact_text(text)
            best = min(best, time.perf_counter() - t0)
        return best

    small, big = cost(64 * 1024), cost(128 * 1024)
    assert big < 1.0, f"128 KiB took {big:.2f}s"
    assert big < max(small, 0.005) * 6, f"doubling the input cost {big / max(small, 1e-6):.1f}x"


# ── connectors, web API, MCP ────────────────────────────────────────────────

class _Upstream(http.server.BaseHTTPRequestHandler):
    status = 401

    def _answer(self):
        body = b'{"error": "nope"}'
        self.send_response(type(self).status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = _answer  # noqa: N815

    def log_message(self, *_a):
        pass


@pytest.fixture
def upstream():
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Upstream)
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


_KINDS = ["kibana", "splunk", "loki", "librenms"]


def _cfg(kind: str, port: int) -> SourceConfig:
    # a credentialed URL is accepted at registration; the credential must never come back out in an error
    return SourceConfig(id=f"{kind}-r", type=kind, url=f"http://svc:{SECRET}@127.0.0.1:{port}/proxy",
                        api_token="tok-0123456789abcdef", allow_private=True)


def _errors(src) -> list[str]:
    out = []
    for call in (src.healthcheck, lambda: list(src.fetch(since_seconds=60, limit=5))):
        try:
            call()
        except SourceError as exc:
            out.append(str(exc))
    return out


@pytest.mark.parametrize("status", [401, 403, 500, 503])
@pytest.mark.parametrize("kind", _KINDS)
def test_connector_errors_never_contain_the_url_credentials(upstream: int, kind: str, status: int) -> None:
    _Upstream.status = status
    src = registry.create(_cfg(kind, upstream))
    texts = _errors(src)
    assert texts, "the failing upstream must surface as a SourceError"
    for text in texts:
        assert SECRET not in text, text
        assert "127.0.0.1" in text or str(status) in text            # still says what failed
    src.close()


@pytest.mark.parametrize("kind", _KINDS)
def test_connector_connection_errors_never_contain_the_url_credentials(kind: str) -> None:
    src = registry.create(_cfg(kind, 1))                              # nothing listens on port 1
    texts = _errors(src)
    assert texts and all(SECRET not in t for t in texts), texts
    src.close()


def test_solarwinds_errors_never_contain_the_url_credentials(upstream: int) -> None:
    cfg = SourceConfig(id="sw-r", type="solarwinds", url=f"http://svc:{SECRET}@127.0.0.1:{upstream}",
                       username="svc", password=SECRET, allow_private=True)
    for status in (401, 503):
        _Upstream.status = status
        src = registry.create(cfg)
        with pytest.raises(SourceError) as exc:
            src.healthcheck()
        assert SECRET not in str(exc.value), exc.value
        src.close()
    down = SourceConfig(id="sw-d", type="solarwinds", url=f"http://svc:{SECRET}@127.0.0.1:1",
                        username="svc", password=SECRET, allow_private=True)
    with pytest.raises(SourceError) as exc:
        registry.create(down).healthcheck()
    assert SECRET not in str(exc.value)


def test_the_raw_exception_is_not_chained_onto_the_source_error(upstream: int) -> None:
    """Tracebacks print the chain; the cause's text still holds the credentials."""
    _Upstream.status = 401
    src = registry.create(_cfg("kibana", upstream))
    with pytest.raises(SourceError) as exc:
        src.healthcheck()
    chain, cur = [], exc.value
    while cur is not None:
        chain.append(repr(cur) + str(cur))
        cur = cur.__cause__ or (None if exc.value.__suppress_context__ else cur.__context__)
    assert all(SECRET not in c for c in chain), chain


def test_manager_healthcheck_hides_credentials_from_any_connector() -> None:
    class Plugin:
        kind, name = "plugin", "p"

        def healthcheck(self):
            raise SourceError(f"boom for url: https://svc:{SECRET}@h.example/x?token={SECRET}")

    mgr = SourceManager()
    mgr._sources["p"] = Plugin()
    out = mgr.healthcheck("p")
    assert out["ok"] is False and SECRET not in json.dumps(out) and "boom" in out["error"]


def test_web_api_never_returns_the_credentials(upstream: int, monkeypatch: pytest.MonkeyPatch) -> None:
    import ai_log_analyzer.web.app as web_app
    from ai_log_analyzer.sources.manager import manager as source_manager

    monkeypatch.setattr(web_app, "API_TOKEN", "")
    _Upstream.status = 401
    client = web_app.create_app().test_client()
    ids = []
    try:
        for kind in _KINDS:
            source_manager.add(_cfg(kind, upstream))
            ids.append(f"{kind}-r")
        bodies = []
        for sid in ids:
            bodies.append(client.post(f"/api/sources/{sid}/test", json={}).get_data(as_text=True))
            bodies.append(client.post(f"/api/sources/{sid}/fetch", json={"limit": 5}).get_data(as_text=True))
            bodies.append(client.post(f"/api/sources/{sid}/analyze", json={"limit": 5}).get_data(as_text=True))
        bodies.append(client.post("/api/correlate", json={"source_ids": ids}).get_data(as_text=True))
        bodies.append(client.post("/api/triage", json={"hostname": "leaf1", "source_ids": ids}).get_data(as_text=True))
        bodies.append(client.get("/api/sources").get_data(as_text=True))
        assert any("401" in b or "Unauthorized" in b for b in bodies), "the errors must still be informative"
        for body in bodies:
            assert SECRET not in body, body
    finally:
        for sid in ids:
            source_manager.remove(sid)


def test_mcp_tools_never_return_the_credentials(upstream: int, monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    pytest.importorskip("mcp")
    from ai_log_analyzer.mcp_server import server as srv_mod

    _Upstream.status = 401
    server = srv_mod._build_server()
    srv_mod.source_manager.add(_cfg("kibana", upstream))
    try:
        results = []
        for name, args in (("test_source", {"source_id": "kibana-r"}),
                           ("fetch_logs", {"source_id": "kibana-r"}),
                           ("correlate_sources", {}),
                           ("analyze_device", {"hostname": "leaf1"})):
            res = asyncio.run(server.call_tool(name, args))
            results.append(json.dumps(res.structured_content or {}, default=str))
        assert any("401" in r or "Unauthorized" in r for r in results)
        assert all(SECRET not in r for r in results), results
    finally:
        srv_mod.source_manager.remove("kibana-r")


def test_real_requests_exception_text_is_what_the_helper_expects(upstream: int) -> None:
    """Guards the assumption behind the helper: this ``requests`` really embeds the userinfo."""
    _Upstream.status = 401
    r = requests.get(f"http://svc:{SECRET}@127.0.0.1:{upstream}/x", timeout=5)
    with pytest.raises(requests.HTTPError) as exc:
        r.raise_for_status()
    assert SECRET in str(exc.value)
    assert SECRET not in redact_text(str(exc.value))
