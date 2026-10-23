"""/api/postmortem runs an operator-supplied regex: it must be bounded (length cap,
`regex` timeout) and every failure mode must be a 400, never a hung worker."""
from __future__ import annotations

import time

import pytest
import regex

import ai_log_analyzer.web.app as web_app
from ai_log_analyzer import postmortem
from ai_log_analyzer.web.app import create_app

DEVICES = [{"hostname": "r1", "platform": "junos", "config_text": "set system ntp server 10.0.0.1\n" * 3}]
REAL_REGEX = hasattr(regex, "__version__")      # the offline sandbox shim has no timeout support


@pytest.fixture
def client():
    return create_app().test_client()


def _site() -> str:
    return sorted(p.name for p in web_app.SITES_DIR.iterdir() if (p / "manifest.json").is_file())[0]


def test_search_uses_the_regex_module_with_a_timeout(monkeypatch):
    seen: dict = {}
    real_compile = regex.compile

    class _Spy:
        def __init__(self, inner):
            self._inner = inner

        def finditer(self, text, **kw):
            seen.update(kw)
            return self._inner.finditer(text)

    monkeypatch.setattr(postmortem.regex, "compile", lambda p, f=0: _Spy(real_compile(p, f)))
    out = postmortem.search_fleet(DEVICES, r"ntp\s+server")
    assert out["total_matches"] == 3
    assert 0 < seen["timeout"] <= postmortem.SEARCH_TIMEOUT_SECONDS


def test_timeout_is_reported_as_an_error_not_raised(monkeypatch):
    class _Slow:
        def finditer(self, text, **kw):
            raise TimeoutError

    monkeypatch.setattr(postmortem.regex, "compile", lambda p, f=0: _Slow())
    out = postmortem.search_fleet(DEVICES, r"(a+)+$")
    assert "timed out" in out["error"] and out["total_matches"] == 0


def test_route_returns_400_on_timeout(client, monkeypatch):
    class _Slow:
        def finditer(self, text, **kw):
            raise TimeoutError

    monkeypatch.setattr(postmortem.regex, "compile", lambda p, f=0: _Slow())
    r = client.post(f"/api/postmortem/{_site()}", json={"pattern": r"(\s*\w*)*#Z"})
    assert r.status_code == 400 and "timed out" in r.get_json()["error"]


def test_route_returns_400_on_invalid_regex(client):
    r = client.post(f"/api/postmortem/{_site()}", json={"pattern": "*invalid[regex"})
    import re
    assert r.status_code == 400
    # Position only: the regex library's message text is not echoed back to the client.
    assert re.fullmatch(r"invalid regex( \(syntax error at position \d+\))?", r.get_json()["error"])


def test_route_returns_400_on_oversized_pattern(client):
    r = client.post(f"/api/postmortem/{_site()}", json={"pattern": "a" * (postmortem.MAX_PATTERN_LENGTH + 1)})
    assert r.status_code == 400 and "exceeds" in r.get_json()["error"]


def test_route_still_serves_normal_searches(client):
    r = client.post(f"/api/postmortem/{_site()}", json={"pattern": "ntp"})
    assert r.status_code == 200 and "matches" in r.get_json()


@pytest.mark.skipif(not REAL_REGEX, reason="needs the real `regex` package for timeout=")
def test_catastrophic_pattern_on_a_6kb_config_finishes_fast():
    """The reproduced DoS: `(\\s*\\w*)*#Z` on a 6 KB config ran for >100 s under stdlib re."""
    text = ("   " + "word " * 4 + "\n") * 300
    devices = [{"hostname": "r1", "platform": "junos", "config_text": text[:6000]}]
    t0 = time.monotonic()
    out = postmortem.search_fleet(devices, r"(\s*\w*)*#Z")
    assert time.monotonic() - t0 < postmortem.TOTAL_TIMEOUT_SECONDS + 2
    assert out.get("error") is None or "timed out" in out["error"]
