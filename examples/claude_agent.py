"""
Claude API agent that exposes cyberskill as tools.

Usage:
    ANTHROPIC_API_KEY=sk-... python examples/claude_agent.py "Scan 192.168.1.1 for SQL injection"
    ANTHROPIC_API_KEY=sk-... python examples/claude_agent.py  # interactive mode

Install:
    pip install anthropic
    pip install -e .
"""
from __future__ import annotations

import json
import sys

import anthropic

from cyberskill.skill import CyberskillAI

# ---------------------------------------------------------------------------
# Tool schemas exposed to Claude
# ---------------------------------------------------------------------------

_TOOLS: list[dict] = [
    {
        "name": "list_tools",
        "description": (
            "Return every registered cybersecurity tool with its name, binary, "
            "description, whether it is installed, and its OWASP Top 10 categories."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "list_categories",
        "description": (
            "Return all ten OWASP Top 10 (2021) categories together with a "
            "description and the names of tools that cover each category."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "tool_info",
        "description": "Return detailed metadata for a single tool by its name.",
        "input_schema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Tool name, e.g. 'nmap'"},
            },
            "required": ["name"],
        },
    },
    {
        "name": "scan",
        "description": (
            "Run one or more cybersecurity tools against a target and return a "
            "structured JSON report.  Omit 'tools' and 'categories' to run a full "
            "assessment.  Always confirm with the user that they have authorisation "
            "to scan the target before calling this tool."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "IP address, hostname, or URL to scan.",
                },
                "tools": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Names of specific tools to run, e.g. ['nmap', 'sqlmap']. "
                        "Omit to use all tools (or filter by categories)."
                    ),
                },
                "categories": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "OWASP category IDs to target, e.g. ['A03', 'A05']. "
                        "Omit to use all categories."
                    ),
                },
                "timeout": {
                    "type": "integer",
                    "description": "Per-tool timeout in seconds (default 300).",
                },
            },
            "required": ["target"],
        },
    },
]


# ---------------------------------------------------------------------------
# Tool dispatch
# ---------------------------------------------------------------------------

def _dispatch(name: str, inputs: dict, skill: CyberskillAI) -> str:
    if name == "list_tools":
        return json.dumps(skill.list_tools(), indent=2)
    if name == "list_categories":
        return json.dumps(skill.list_categories(), indent=2)
    if name == "tool_info":
        try:
            return json.dumps(skill.tool_info(inputs["name"]), indent=2)
        except KeyError as exc:
            return json.dumps({"error": str(exc)})
    if name == "scan":
        result = skill.scan(
            inputs["target"],
            tools=inputs.get("tools"),
            categories=inputs.get("categories"),
            timeout=inputs.get("timeout", 300),
        )
        return json.dumps(result, indent=2)
    raise ValueError(f"Unknown tool: {name!r}")


# ---------------------------------------------------------------------------
# Agentic loop
# ---------------------------------------------------------------------------

def run_agent(user_request: str, *, verbose: bool = True) -> str:
    """Run a single conversation turn with the cyberskill tools.

    Returns the final text response from Claude.
    """
    client = anthropic.Anthropic()
    skill = CyberskillAI()

    messages: list[dict] = [{"role": "user", "content": user_request}]

    while True:
        response = client.messages.create(
            model="claude-opus-4-8",
            max_tokens=16000,
            thinking={"type": "adaptive"},
            tools=_TOOLS,
            messages=messages,
        )

        # Print text blocks as they arrive
        for block in response.content:
            if block.type == "text" and verbose:
                print(block.text, end="", flush=True)

        if response.stop_reason == "end_turn":
            print()
            break

        # Extract tool calls
        tool_use_blocks = [b for b in response.content if b.type == "tool_use"]
        if not tool_use_blocks:
            break

        # Append assistant turn (including tool_use blocks)
        messages.append({"role": "assistant", "content": response.content})

        # Execute tools and collect results
        tool_results = []
        for tb in tool_use_blocks:
            if verbose:
                print(f"\n[tool] {tb.name}({json.dumps(tb.input)})", flush=True)
            try:
                content = _dispatch(tb.name, tb.input, skill)
                tool_results.append(
                    {"type": "tool_result", "tool_use_id": tb.id, "content": content}
                )
            except Exception as exc:  # noqa: BLE001
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tb.id,
                        "content": str(exc),
                        "is_error": True,
                    }
                )

        messages.append({"role": "user", "content": tool_results})

    # Return the final text from the last assistant message
    for block in response.content:
        if block.type == "text":
            return block.text
    return ""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    args = sys.argv[1:]
    if args:
        run_agent(" ".join(args))
    else:
        print("Cyberskill AI — Claude-powered security assessment agent")
        print("Type your request and press Enter (Ctrl-C to quit).\n")
        while True:
            try:
                request = input("You: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nBye.")
                break
            if not request:
                continue
            print()
            run_agent(request)
            print()


if __name__ == "__main__":
    main()
