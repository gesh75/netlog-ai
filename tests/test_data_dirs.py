"""Packaging contract: bundled demo data must resolve in every install mode.

samples/ and sites/ live inside the package (ai_log_analyzer/data/) so wheels
and Docker images boot with demo content; env vars override for custom data.
"""
from __future__ import annotations

import ipaddress
import re

import pytest

from ai_log_analyzer.web.app import SAMPLES_DIR, SITES_DIR, STATIC_DIR, _data_dir

_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_ALLOWED_NETS = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
)
_BANNED_SAMPLE_TOKENS = (
    "35793",
    "arelion",
    "akamai",
    "atom86",
    "got1",
    "fra2",
    "isi" + "vkov",
    "ilya." + "sivkov",
    "ix" + "peer",
    "04_scripts",
)


@pytest.mark.unit
def test_bundled_samples_resolve():
    assert (SAMPLES_DIR / "_manifest.json").is_file()
    assert list(SAMPLES_DIR.glob("*.txt")), "no sample configs found"


@pytest.mark.unit
def test_bundled_sites_resolve():
    assert SITES_DIR.is_dir()
    assert any(p.is_dir() for p in SITES_DIR.iterdir()), "no site bundles found"


@pytest.mark.unit
def test_vendored_topology_js_present():
    vendor = STATIC_DIR / "vendor"
    for lib in ("cytoscape.min.js", "elk.bundled.js", "cytoscape-elk.js"):
        assert (vendor / lib).is_file(), f"missing vendored {lib}"


@pytest.mark.unit
def test_env_override_wins(monkeypatch, tmp_path):
    monkeypatch.setenv("AI_LOG_ANALYZER_SAMPLES_DIR", str(tmp_path))
    assert _data_dir("AI_LOG_ANALYZER_SAMPLES_DIR", "samples") == tmp_path


def _ipv4_is_allowed(raw: str) -> bool:
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return True
    if addr.version != 4:
        return True
    return any(addr in net for net in _ALLOWED_NETS)


@pytest.mark.unit
def test_samples_stay_pseudonymized():
    """Public-repo guard: bundled samples must never reacquire real-world
    identifiers (RIR ASNs, provider names, real site codes, usernames)."""
    for f in SAMPLES_DIR.glob("*.txt"):
        text = f.read_text(errors="replace").lower()
        for token in _BANNED_SAMPLE_TOKENS:
            assert token not in text, f"{f.name} contains banned token {token!r}"
        assert "last commit" not in text, f"{f.name} contains a real-looking commit header"


@pytest.mark.unit
def test_bundled_demo_configs_use_documentation_or_private_ipv4():
    """Samples and site bundles must not ship real-looking public IPv4 addresses."""
    files = list(SAMPLES_DIR.glob("*.txt")) + list(SITES_DIR.rglob("*.txt"))
    assert files, "no demo configs found"
    for path in files:
        text = path.read_text(errors="replace")
        for match in _IPV4_RE.finditer(text):
            ip = match.group(1)
            assert _ipv4_is_allowed(ip), f"{path} contains non-documentation IPv4 {ip}"


@pytest.mark.unit
def test_bundled_sites_have_no_ix_peering_or_real_usernames():
    for config in SITES_DIR.rglob("*.txt"):
        text = config.read_text(errors="replace")
        lowered = text.lower()
        assert ("ix" + "peer") not in lowered, f"{config} contains IX peering labels"
        assert ("isi" + "vkov") not in lowered, f"{config} contains a real-looking username"
        assert "last commit" not in lowered, f"{config} contains a real-looking commit header"


@pytest.mark.unit
def test_bundled_sites_do_not_contain_credentials():
    """Public wheels must contain only sanitized site configurations."""
    credential_patterns = (
        re.compile(r"\$(?:6|y|aes1)\$(?!REDACTED)"),
        re.compile(r"-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----"),
    )
    for config in SITES_DIR.rglob("*.txt"):
        text = config.read_text(errors="replace")
        for pattern in credential_patterns:
            assert not pattern.search(text), f"{config} contains credential material"


@pytest.mark.unit
def test_index_html_has_no_cdn_scripts():
    """Air-gap guard: the UI must not load JS from external CDNs."""
    html = (STATIC_DIR / "index.html").read_text()
    external = re.findall(r'<script[^>]+src="(https?://[^"]+)"', html)
    assert not external, f"external scripts found: {external}"


@pytest.mark.unit
def test_index_evpn_causal_overlay_is_off_by_default():
    html = (STATIC_DIR / "index.html").read_text()
    assert 'id="topo-show-causal"' in html
    assert "checked" not in html.split('id="topo-show-causal"', 1)[1][:80]
    assert 'id="evpn-causal-panel" style="display:none;"' in html
