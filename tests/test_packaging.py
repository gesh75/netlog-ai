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


def test_no_withdrawn_tfsm_fire_dependency():
    """`tfsm-fire` is gone from PyPI — requiring it makes the package uninstallable.

    See docs/TFSM_AUTO_PARSER.md. The adapter stays; only the hard dependency is gone.
    """
    offenders = [
        (src, req) for src, req in _all_requirements() if "tfsm" in req.lower()
    ]
    assert not offenders, (
        "tfsm-fire was withdrawn from PyPI and its upstream repo deleted; requiring it "
        f"breaks install for all users: {offenders}"
    )


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
