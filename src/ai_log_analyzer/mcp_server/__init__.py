"""MCP (Model Context Protocol) server for netlog-ai.

Exposes the analyzer pipeline as agent-callable tools so Claude Code, Cursor,
Continue, or any other MCP-compatible client can query netlog-ai directly.
"""
from ai_log_analyzer.mcp_server.server import run as run_mcp_server  # noqa: F401

__all__ = ["run_mcp_server"]
