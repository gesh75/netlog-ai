"""Smoke test run against an INSTALLED wheel (not the source tree).

Asserts that the demo data and web UI assets are really packaged, because the
repository's own tests run against src/ and cannot see a packaging omission.
Shared by ci.yml (PR-time build) and release.yml so they cannot drift.
"""
import pathlib

import ai_log_analyzer
import ai_log_analyzer.web.app as a

assert pathlib.Path(a.SAMPLES_DIR, "_manifest.json").is_file(), a.SAMPLES_DIR
assert any(pathlib.Path(a.SITES_DIR).iterdir()), a.SITES_DIR
assert pathlib.Path(a.STATIC_DIR, "vendor", "cytoscape.min.js").is_file()
assert (pathlib.Path(ai_log_analyzer.__file__).parent / "py.typed").is_file(), "py.typed missing"
print("wheel data OK", ai_log_analyzer.__version__)
