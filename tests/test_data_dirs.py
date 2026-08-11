"""Packaging contract: bundled demo data must resolve in every install mode.

samples/ and sites/ live inside the package (ai_log_analyzer/data/) so wheels
and Docker images boot with demo content; env vars override for custom data.
"""
from __future__ import annotations


import re

import pytest

from ai_log_analyzer.web.app import SAMPLES_DIR, SITES_DIR, STATIC_DIR, _data_dir


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


@pytest.mark.unit
def test_samples_stay_pseudonymized():
    """Public-repo guard: bundled samples must never reacquire real-world
    identifiers (RIR ASNs, provider names, real site codes)."""
    banned = ("35793", "arelion", "akamai", "atom86", "got1", "fra2")
    for f in SAMPLES_DIR.glob("*.txt"):
        text = f.read_text(errors="replace").lower()
        for token in banned:
            assert token not in text, f"{f.name} contains banned token {token!r}"


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
