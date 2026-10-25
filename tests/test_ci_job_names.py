"""The branch ruleset on main requires the status checks "test (3.10)", "test (3.11)" and "test (3.12)".
A job name that drifts (e.g. matrix keys leaking into it) would leave those checks waiting forever."""
from __future__ import annotations

from pathlib import Path

import yaml

CI = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"


def test_test_job_name_depends_only_on_the_python_version():
    job = yaml.safe_load(CI.read_text(encoding="utf-8"))["jobs"]["test"]
    assert job["name"] == "test (${{ matrix.python-version }})"


def test_required_python_versions_stay_in_the_matrix():
    matrix = yaml.safe_load(CI.read_text(encoding="utf-8"))["jobs"]["test"]["strategy"]["matrix"]
    assert {"3.10", "3.11", "3.12"} <= set(matrix["python-version"])
