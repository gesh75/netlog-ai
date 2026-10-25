"""Guards on the CI / release configuration (no network, no GitHub).

A tag push publishes to PyPI, so the properties below are worth pinning: the release
must be gated on CI, and the tag must match the version in pyproject.toml.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
SCRIPT = ROOT / ".github" / "scripts" / "check_tag_version.py"


def _load(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


def _triggers(doc: dict) -> dict:
    # PyYAML (YAML 1.1) parses the bare key `on` as boolean True.
    return doc.get("on") or doc.get(True) or {}


@pytest.mark.parametrize("path", sorted(WORKFLOWS.glob("*.yml")), ids=lambda p: p.name)
def test_workflows_are_valid_yaml_with_jobs(path):
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert doc.get("jobs"), f"{path.name} defines no jobs"


def test_ci_is_reusable_and_least_privilege():
    ci = _load("ci.yml")
    assert "workflow_call" in _triggers(ci), "release.yml reuses ci.yml as its gate"
    assert ci["permissions"] == {"contents": "read"}
    for name, job in ci["jobs"].items():
        assert "timeout-minutes" in job, f"ci job {name} has no timeout"


def test_release_publishing_is_gated_on_ci_and_build():
    rel = _load("release.yml")
    jobs = rel["jobs"]
    assert jobs["gate"]["uses"] == "./.github/workflows/ci.yml"
    for name in ("pypi", "github-release"):
        needs = jobs[name]["needs"]
        needs = [needs] if isinstance(needs, str) else needs
        assert {"gate", "build"} <= set(needs), f"{name} must need gate and build"
    assert rel["permissions"] == {"contents": "read"}
    steps = "\n".join(str(s.get("run", "")) for s in jobs["build"]["steps"])
    assert "check_tag_version.py" in steps
    assert "twine check" in steps
    assert "pip check" in steps


def _run(tag: str, pyproject: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), tag, str(pyproject)],
        capture_output=True, text=True, timeout=30,
    )


def _write_pyproject(tmp_path: Path, version: str) -> Path:
    path = tmp_path / "pyproject.toml"
    path.write_text(f'[project]\nname = "x"\nversion = "{version}"\n', encoding="utf-8")
    return path


def test_tag_matching_pyproject_version_passes(tmp_path):
    result = _run("v1.2.3", _write_pyproject(tmp_path, "1.2.3"))
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("tag", ["v1.2.4", "1.2.3", "v1.2", "v1.2.3rc1", "vv1.2.3"])
def test_tag_not_matching_pyproject_version_fails(tmp_path, tag):
    result = _run(tag, _write_pyproject(tmp_path, "1.2.3"))
    assert result.returncode == 1
    assert "does not match" in result.stdout
