"""Smoke test: verify _build_server() constructs without errors.

Ensures that all @mcp.tool() wrappers compile and register correctly.
Skipped gracefully when the MCP SDK is not installed.
"""
from __future__ import annotations

import pytest

pytest.importorskip("mcp")


@pytest.mark.unit
def test_build_server_registers_new_tools():
    """_build_server() must succeed (raises if any @mcp.tool() body is malformed)."""
    from ai_log_analyzer.mcp_server.server import _build_server

    srv = _build_server()
    # FastMCP keeps tools in an internal registry; just assert construction works.
    assert srv is not None
