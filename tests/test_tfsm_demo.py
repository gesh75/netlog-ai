"""Regression tests for the TextFSM terminal demo."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from demo import tfsm_demo


pytestmark = pytest.mark.unit


def test_demo_limits_every_template_scan(capsys: pytest.CaptureFixture[str]) -> None:
    """Even unstructured demo input must not scan the full template database."""
    result = SimpleNamespace(template=None, score=0.0, records=[], matched=False)

    with patch.object(tfsm_demo, "auto_parse", return_value=result) as auto_parse:
        assert tfsm_demo.main() == 0

    assert all(call.kwargs.get("filter_hint") for call in auto_parse.call_args_list)
    capsys.readouterr()
