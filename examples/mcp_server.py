"""
Cyberskill MCP server — exposes cybersecurity tools via the Model Context Protocol.

Connect this server to Claude Desktop, Claude Code, or any MCP-compatible client
so that Claude can call cyberskill tools natively without extra plumbing.

Usage:
    pip install "mcp[cli]"
    pip install -e .

    # Run directly (stdio transport — used by Claude Desktop / Claude Code):
    python examples/mcp_server.py

Claude Desktop config  (~/.config/claude/claude_desktop_config.json  or
~/Library/Application Support/Claude/claude_desktop_config.json on macOS):

    {
      "mcpServers": {
        "cyberskill": {
          "command": "python",
          "args": ["/absolute/path/to/examples/mcp_server.py"]
        }
      }
    }

Claude Code (add to your project's .mcp.json or pass via --mcp-config):

    {
      "mcpServers": {
        "cyberskill": {
          "command": "python",
          "args": ["examples/mcp_server.py"]
        }
      }
    }
"""
from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from cyberskill.skill import CyberskillAI

mcp = FastMCP(
    "cyberskill",
    instructions=(
        "You have access to a suite of cybersecurity tools covering the OWASP Top 10. "
        "Always verify you have authorisation before scanning a live target."
    ),
)

_skill = CyberskillAI()


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def list_tools() -> str:
    """Return every registered cybersecurity tool with OWASP coverage info."""
    return json.dumps(_skill.list_tools(), indent=2)


@mcp.tool()
def list_categories() -> str:
    """Return all OWASP Top 10 categories and the tools mapped to each one."""
    return json.dumps(_skill.list_categories(), indent=2)


@mcp.tool()
def tool_info(name: str) -> str:
    """Return metadata for a single tool.

    Args:
        name: Tool name, e.g. 'nmap', 'sqlmap', 'nuclei'.
    """
    try:
        return json.dumps(_skill.tool_info(name), indent=2)
    except KeyError:
        return json.dumps({"error": f"Unknown tool: {name!r}"})


@mcp.tool()
def scan(
    target: str,
    tools: list[str] | None = None,
    categories: list[str] | None = None,
    timeout: int = 300,
) -> str:
    """Run cybersecurity tools against a target and return a structured JSON report.

    Args:
        target:     IP address, hostname, or URL to scan.
        tools:      Specific tool names to run (e.g. ['nmap', 'sqlmap']).
                    Omit to cover all tools (or filter by categories).
        categories: OWASP category IDs to target (e.g. ['A03', 'A05']).
                    Omit to run all categories.
        timeout:    Per-tool execution timeout in seconds (default 300).
    """
    result = _skill.scan(target, tools=tools, categories=categories, timeout=timeout)
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Resources — expose static reference data
# ---------------------------------------------------------------------------

@mcp.resource("cyberskill://owasp/top10")
def owasp_top10() -> str:
    """OWASP Top 10 (2021) categories with descriptions and mapped tools."""
    return json.dumps(_skill.list_categories(), indent=2)


@mcp.resource("cyberskill://tools/available")
def available_tools() -> str:
    """All registered tools, including whether each binary is installed."""
    return json.dumps(_skill.list_tools(), indent=2)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
