"""Guards on the published package metadata in pyproject.toml.

Background
----------
Through v0.5.0 the `parse` and `all` extras required `tfsm-fire>=0.1.0`. Upstream
withdrew that package from PyPI and deleted its GitHub repo in July 2026, which made
`pip install netlog-ai[parse]` and `pip install netlog-ai[all]` hard-fail for every
user and broke CI on all three supported Python versions.

The obvious-looking repair — repointing the extra at a `git+https://` URL — does not
work: PyPI rejects PEP 508 direct references in uploaded metadata, so such a wheel
cannot be published at all. It would pass local `pip install -e .` and then fail at
release time. These tests exist so that trap is caught in CI instead.

They are pure metadata assertions — no network, no build.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # Python 3.10 — pytest pulls tomli in as a transitive dep
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:  # pragma: no cover - only on a 3.10 env without tomli
        tomllib = None  # type: ignore[assignment]

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"
SRC = Path(__file__).resolve().parent.parent / "src"

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(tomllib is None,
                       reason="no TOML parser available (Python 3.10 without tomli)"),
]


def _project() -> dict:
    with PYPROJECT.open("rb") as handle:
        return tomllib.load(handle)["project"]


def _all_requirements() -> list[tuple[str, str]]:
    """Every (source, requirement) pair in the published metadata."""
    project = _project()
    pairs = [("dependencies", req) for req in project.get("dependencies", [])]
    for extra, reqs in project.get("optional-dependencies", {}).items():
        pairs.extend((f"optional-dependencies.{extra}", req) for req in reqs)
    return pairs


def _dist_name(requirement: str) -> str:
    """Normalized (PEP 503) distribution name from a PEP 508 requirement string.

    Matching on the parsed name rather than a substring matters here: `textfsm`
    *contains* the substring "tfsm", and it is a plausible future dependency —
    it is the maintained library the withdrawn package was built on.
    """
    name = re.split(r"[<>=!~;\[@\s]", requirement.strip(), maxsplit=1)[0]
    return re.sub(r"[-_.]+", "-", name).lower()


def test_no_direct_reference_requirements():
    """PEP 508 direct references (`name @ url`) cannot be published to PyPI.

    setuptools builds them happily and `pip install -e .` accepts them, so this only
    surfaces at upload time — after a tag has already been pushed. Catch it here.
    """
    offenders = [(src, req) for src, req in _all_requirements() if "@" in req]
    assert not offenders, (
        "direct-reference requirements cannot be uploaded to PyPI "
        f"(twine rejects them): {offenders}"
    )


WITHDRAWN = {"tfsm-fire"}


def test_no_withdrawn_tfsm_fire_dependency():
    """`tfsm-fire` is gone from PyPI — requiring it makes the package uninstallable.

    See docs/TFSM_AUTO_PARSER.md. The adapter stays; only the hard dependency is gone.

    Deliberately matches the exact normalized distribution name, not a substring:
    `textfsm` is a legitimate (and likely) future dependency that contains "tfsm".
    """
    offenders = [
        (src, req) for src, req in _all_requirements() if _dist_name(req) in WITHDRAWN
    ]
    assert not offenders, (
        "tfsm-fire was withdrawn from PyPI and its upstream repo deleted; requiring it "
        f"breaks install for all users: {offenders}"
    )


def test_dist_name_parsing():
    """_dist_name must key off the parsed name, or the guard above misfires."""
    assert _dist_name("tfsm-fire>=0.1.0") == "tfsm-fire"
    assert _dist_name("tfsm_fire >= 0.1.0") == "tfsm-fire"
    assert _dist_name('tfsm-fire @ git+https://example.invalid/x.git') == "tfsm-fire"
    assert _dist_name('mcp>=1.0,<2') == "mcp"
    assert _dist_name('tomli>=2.0; python_version < "3.11"') == "tomli"
    assert _dist_name("pytest-cov>=5.0") == "pytest-cov"
    # The false positive this guard exists to avoid:
    assert _dist_name("textfsm>=1.1.3") == "textfsm"
    assert _dist_name("textfsm>=1.1.3") not in WITHDRAWN


def test_mcp_extras_require_sdk_2x_without_hotfix_cap():
    """Issue #17: drop the #16 `mcp<2` hotfix now that the server targets 2.x.

    Both extras must require mcp 2 or newer. A leftover `<2` (the packaging
    hotfix) would pin us back to the 1.x FastMCP API.
    """
    extras = _project().get("optional-dependencies", {})
    for extra in ("mcp", "all"):
        reqs = [r for r in extras.get(extra, []) if _dist_name(r) == "mcp"]
        assert reqs, f"`{extra}` extra must depend on mcp"
        for req in reqs:
            assert re.search(r">=\s*2", req), f"`{extra}` must require mcp 2.x+: {req}"
            assert not re.search(r"<\s*2(\D|$)", req), f"`{extra}` still has the mcp<2 hotfix: {req}"


def test_all_extra_is_superset_of_named_extras():
    """`all` must actually mean "all the optional features", excluding dev tooling.

    Drift here is how `all` ends up advertising something it no longer installs.
    """
    extras = _project().get("optional-dependencies", {})
    assert "all" in extras, "the `all` extra is documented in the README and must exist"

    aggregate = set(extras["all"])
    for name, reqs in extras.items():
        if name in {"all", "dev"}:
            continue
        missing = set(reqs) - aggregate
        assert not missing, f"extra `{name}` has requirements missing from `all`: {missing}"


def test_package_version_matches_pyproject():
    """`ai_log_analyzer.__version__` must equal pyproject's version.

    Compared dynamically: no release should ever need to edit this test. (An installed
    dist's metadata and the editable checkout both derive from pyproject.toml; the
    `__init__` fallback literal is only used for non-installed checkouts and is
    checked separately below.)
    """
    import ai_log_analyzer

    ver = _project().get("version")
    assert ver, "pyproject.toml has no [project] version"
    assert ai_log_analyzer.__version__ == ver, (
        f"ai_log_analyzer.__version__ ({ai_log_analyzer.__version__}) != pyproject "
        f"version ({ver}); reinstall (`pip install -e .`) or bump the __init__ fallback"
    )


def test_init_fallback_version_matches_pyproject():
    """The hard-coded fallback in __init__.py (used when the dist is not installed)
    must track pyproject.toml, or non-installed checkouts report a stale version."""
    init = (SRC / "ai_log_analyzer" / "__init__.py").read_text(encoding="utf-8")
    m = re.search(r'__version__\s*=\s*"([^"]+)"\s*#\s*fallback', init)
    assert m, 'could not find the `__version__ = "x.y.z"  # fallback` line in __init__.py'
    assert m.group(1) == _project()["version"]


def _version_pattern(ver: str) -> re.Pattern[str]:
    """Match the app's version as a standalone token. `pkg@x.y.z` pins (vendored npm packages named in
    comments) are another project's version that may coincide with ours, so they are not matches."""
    return re.compile(r"(?<![\d.@])" + re.escape(ver) + r"(?![\d])")


def test_version_pattern_catches_real_copies_but_not_package_pins():
    pat = _version_pattern("2.2.0")
    assert pat.search('headers = {"User-Agent": "netlog-ai/2.2.0"}')
    assert pat.search('<span class="brand-version">v2.2.0</span>')
    assert not pat.search("vendored locally (cytoscape-elk@2.2.0)")
    assert not pat.search("netlog-ai/12.2.0") and not pat.search("netlog-ai/2.2.01")


def test_version_literal_not_scattered_through_src():
    """The current version must live in pyproject.toml (plus the single __init__
    fallback), not be hard-coded into User-Agent strings, HTML, etc. Every such copy
    goes stale at the next release."""
    ver = _project()["version"]
    pattern = _version_pattern(ver)
    offenders: list[str] = []
    for path in sorted((SRC / "ai_log_analyzer").rglob("*")):
        if not path.is_file() or path.suffix in {".pyc", ".png", ".ico", ".woff", ".woff2"}:
            continue
        if "vendor" in path.parts or "__pycache__" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        is_init = path.name == "__init__.py" and path.parent.name == "ai_log_analyzer"
        for lineno, line in enumerate(text.splitlines(), 1):
            if not pattern.search(line):
                continue
            if is_init and "# fallback" in line:
                continue
            offenders.append(f"{path.relative_to(SRC.parent)}:{lineno}")
    assert not offenders, (
        f"version {ver} is hard-coded outside pyproject.toml; use ai_log_analyzer.__version__: "
        f"{offenders}"
    )



def test_py_typed_marker_ships_in_wheel():
    """PEP 561: the package advertises inline types only if py.typed exists AND is
    declared as package data (otherwise setuptools leaves it out of the wheel)."""
    assert (SRC / "ai_log_analyzer" / "py.typed").is_file()
    with PYPROJECT.open("rb") as handle:
        data = tomllib.load(handle)
    pkg_data = data["tool"]["setuptools"]["package-data"]["ai_log_analyzer"]
    assert "py.typed" in pkg_data
