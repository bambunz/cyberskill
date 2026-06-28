"""Command-line interface for cyberskill."""
from __future__ import annotations

import json
import sys

import click

from cyberskill.skill import CyberskillAI


@click.group()
@click.version_option()
def cli() -> None:
    """AI-powered cybersecurity skill — OWASP Top 10 coverage.

    \b
    Examples:
      cyberskill list-tools
      cyberskill list-categories
      cyberskill scan 192.168.1.1
      cyberskill scan https://target.local -c A03 -c A05
      cyberskill scan https://target.local -t nmap -t sqlmap
    """


@cli.command()
@click.argument("target")
@click.option(
    "--tool", "-t",
    multiple=True,
    metavar="NAME",
    help="Run a specific tool. Repeatable (e.g. -t nmap -t sqlmap).",
)
@click.option(
    "--category", "-c",
    multiple=True,
    metavar="ID",
    help="Run all tools for an OWASP category ID (e.g. A03). Repeatable.",
)
@click.option(
    "--concurrency",
    default=5,
    show_default=True,
    help="Maximum number of tools to run in parallel.",
)
@click.option(
    "--timeout",
    default=300,
    show_default=True,
    help="Per-tool timeout in seconds.",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=None,
    help="Write JSON report to a file instead of stdout.",
)
def scan(
    target: str,
    tool: tuple[str, ...],
    category: tuple[str, ...],
    concurrency: int,
    timeout: int,
    output: str | None,
) -> None:
    """Scan TARGET with selected tools or OWASP categories.

    If neither --tool nor --category is given, a full OWASP assessment runs.
    """
    skill = CyberskillAI(concurrency=concurrency)
    report = skill.scan(
        target,
        tools=list(tool) or None,
        categories=list(category) or None,
        timeout=timeout,
    )
    data = json.dumps(report, indent=2)
    if output:
        with open(output, "w") as fh:
            fh.write(data)
        click.echo(f"Report written to {output}", err=True)
    else:
        click.echo(data)


@cli.command("list-tools")
def list_tools() -> None:
    """List all registered tools with availability and OWASP coverage."""
    skill = CyberskillAI()
    tools = skill.list_tools()
    if not tools:
        click.echo("No tools registered.")
        return
    for t in tools:
        tick = click.style("✓", fg="green") if t["available"] else click.style("✗", fg="red")
        cats = ", ".join(t["owasp_categories"])
        click.echo(f"  {tick}  {click.style(t['name'], bold=True):<14} {t['description']}")
        click.echo(f"          OWASP: {cats}\n")


@cli.command("list-categories")
def list_categories() -> None:
    """List OWASP Top 10 categories with the tools that cover each."""
    skill = CyberskillAI()
    for cat in skill.list_categories():
        click.echo(click.style(cat["label"], bold=True, fg="cyan"))
        tools_str = ", ".join(cat["tools"]) if cat["tools"] else click.style("(none)", dim=True)
        click.echo(f"  Tools : {tools_str}")
        click.echo(f"  {cat['description']}\n")


@cli.command("tool-info")
@click.argument("name")
def tool_info(name: str) -> None:
    """Show detailed information about a single tool."""
    skill = CyberskillAI()
    try:
        info = skill.tool_info(name)
    except KeyError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    click.echo(json.dumps(info, indent=2))
