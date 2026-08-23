"""Smoke + contract tests for the MCP 2.x server.

Ensures `_build_server()` constructs an `MCPServer`, every `@mcp.tool()`
wrapper registers, and the ImportError handler distinguishes "SDK absent"
from "SDK present but the 2.x API is missing" (issue #17).
Skipped at module level only when the MCP SDK is not installed — the
incompatibility tests stub `sys.modules` and do not need a real 2.x install.
"""
from __future__ import annotations

import asyncio
import builtins
import sys
import types

import pytest

pytest.importorskip("mcp")

EXPECTED_TOOLS = {
    "list_connector_kinds",
    "list_sources",
    "add_source",
    "test_source",
    "fetch_logs",
    "search_logs",
    "analyze_logs",
    "get_top_offenders",
    "correlate_sources",
    "analyze_device",
    "list_sites",
    "analyze_site",
}


def _block_mcp_imports(monkeypatch: pytest.MonkeyPatch, *, allow_root: types.ModuleType | None) -> None:
    """Force `from mcp.server.mcpserver import MCPServer` to fail.

    If ``allow_root`` is set, `import mcp` succeeds (incompatible-major case).
    Otherwise every `mcp*` import fails (not-installed case).
    """
    for key in list(sys.modules):
        if key == "mcp" or key.startswith("mcp."):
            monkeypatch.delitem(sys.modules, key, raising=False)
    if allow_root is not None:
        monkeypatch.setitem(sys.modules, "mcp", allow_root)

    real_import = builtins.__import__

    def guarded(
        name: str,
        globals: dict | None = None,
        locals: dict | None = None,
        fromlist: tuple = (),
        level: int = 0,
    ):
        blocked = "mcp.server.mcpserver"
        if allow_root is None:
            if name == "mcp" or name.startswith("mcp."):
                raise ImportError("No module named 'mcp'")
        elif name == blocked or name.startswith(blocked + "."):
            raise ImportError("No module named 'mcp.server.mcpserver'")
        elif name == "mcp":
            return allow_root
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", guarded)


@pytest.mark.unit
def test_build_server_registers_expected_tools():
    """_build_server() must construct MCPServer and register the public tool set."""
    from mcp.server.mcpserver import MCPServer

    from ai_log_analyzer.mcp_server.server import _build_server

    srv = _build_server()
    assert isinstance(srv, MCPServer)
    assert srv.name == "netlog-ai"
    names = {tool.name for tool in asyncio.run(srv.list_tools())}
    assert EXPECTED_TOOLS <= names


@pytest.mark.unit
def test_build_server_missing_sdk_reports_not_installed(monkeypatch: pytest.MonkeyPatch):
    """Absent SDK must not be reported as an incompatible version."""
    _block_mcp_imports(monkeypatch, allow_root=None)
    from ai_log_analyzer.mcp_server.server import _build_server

    with pytest.raises(RuntimeError, match=r"MCP SDK not installed") as excinfo:
        _build_server()
    assert "2.x required" not in str(excinfo.value)


@pytest.mark.unit
def test_build_server_incompatible_sdk_reports_version(monkeypatch: pytest.MonkeyPatch):
    """Installed 1.x (no mcp.server.mcpserver) must name the found version."""
    stub = types.ModuleType("mcp")
    stub.__version__ = "1.29.0"
    _block_mcp_imports(monkeypatch, allow_root=stub)
    from ai_log_analyzer.mcp_server.server import _build_server

    with pytest.raises(RuntimeError, match=r"MCP SDK 2\.x required") as excinfo:
        _build_server()
    message = str(excinfo.value)
    assert "1.29.0" in message
    assert "not installed" not in message


@pytest.mark.unit
def test_mcp_package_version_uses_metadata_when_dunder_missing(monkeypatch: pytest.MonkeyPatch):
    """SDK 2.x omits mcp.__version__; the error path must still name the package."""
    import importlib.metadata

    from ai_log_analyzer.mcp_server.server import _mcp_package_version

    monkeypatch.setitem(sys.modules, "mcp", types.ModuleType("mcp"))
    assert _mcp_package_version() == importlib.metadata.version("mcp")


@pytest.mark.unit
def test_server_source_uses_mcpserver_not_fastmcp():
    """Regression: the 1.x import path must stay gone (issue #17)."""
    from pathlib import Path

    src = Path(__file__).resolve().parents[1] / "src" / "ai_log_analyzer" / "mcp_server" / "server.py"
    text = src.read_text(encoding="utf-8")
    assert "from mcp.server.mcpserver import MCPServer" in text
    assert "from mcp.server.fastmcp" not in text
    assert "import FastMCP" not in text
