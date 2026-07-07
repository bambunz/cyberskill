"""Command-line interface for cyberskill."""
from __future__ import annotations

import json
import sys

import click

from cyberskill.skill import CyberskillAI


def _render_report(report: dict) -> str:
    """Render a simple human-readable summary from a basic scan report dict."""
    lines: list[str] = []
    results: list[dict] = report.get("results", [])
    target = report.get("target", "unknown")
    lines.append(f"\n{'='*60}")
    lines.append(f"  SECURITY SCAN REPORT — {target}")
    lines.append(f"{'='*60}\n")

    issue_count = 0
    for r in results:
        tool = r.get("tool_name", "?")
        structured = r.get("structured", {}) or {}
        error = r.get("error")
        if error:
            lines.append(f"  [{tool}]  ERROR: {error}")
            continue
        issues = structured.get("issues") or structured.get("findings") or []
        if isinstance(issues, list) and issues:
            lines.append(f"  [{tool}]  {len(issues)} finding(s):")
            for item in issues[:10]:
                if isinstance(item, dict):
                    detail = item.get("finding") or item.get("detail") or str(item)
                else:
                    detail = str(item)
                lines.append(f"    • {detail}")
            if len(issues) > 10:
                lines.append(f"    … and {len(issues) - 10} more")
            issue_count += len(issues)
        else:
            lines.append(f"  [{tool}]  No issues found")
        lines.append("")

    lines.append(f"{'='*60}")
    lines.append(f"  Total issues: {issue_count}")
    lines.append(f"{'='*60}\n")
    return "\n".join(lines)


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
@click.option(
    "--format", "-f",
    "fmt",
    type=click.Choice(["json", "report"], case_sensitive=False),
    default="report",
    show_default=True,
    help="Output format: 'json' for raw JSON, 'report' for human-readable summary.",
)
def scan(
    target: str,
    tool: tuple[str, ...],
    category: tuple[str, ...],
    concurrency: int,
    timeout: int,
    output: str | None,
    fmt: str,
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
    if fmt == "report":
        text = _render_report(report)
        if output:
            with open(output, "w") as fh:
                fh.write(text)
            click.echo(f"Report written to {output}", err=True)
        else:
            click.echo(text)
    else:
        data = json.dumps(report, indent=2)
        if output:
            with open(output, "w") as fh:
                fh.write(data)
            click.echo(f"Report written to {output}", err=True)
        else:
            click.echo(data)


@cli.command("chained-scan")
@click.argument("target")
@click.option(
    "--timeout",
    default=300,
    show_default=True,
    help="Per-tool timeout in seconds.",
)
@click.option(
    "--concurrency",
    default=3,
    show_default=True,
    help="Maximum concurrent tool executions within a phase.",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=None,
    help="Write report to a file instead of stdout.",
)
@click.option(
    "--format", "-f",
    "fmt",
    type=click.Choice(["markdown", "json"], case_sensitive=False),
    default="markdown",
    show_default=True,
    help="Output format: 'markdown' (default) or 'json'.",
)
def chained_scan(
    target: str,
    timeout: int,
    concurrency: int,
    output: str | None,
    fmt: str,
) -> None:
    """Full chained multi-phase security assessment.

    \b
    Each phase feeds its findings into the next:
      Phase 1 — nmap: discover all open ports and services
      Phase 2 — nikto + ffuf + sslscan: fingerprint every web endpoint
      Phase 3 — nuclei + gobuster: CMS/tech-specific vuln templates
      Phase 4 — sqlmap + wfuzz + commix: injection testing on param URLs
      Phase 5 — hydra: brute-force auth services and login forms

    Progress is printed to stderr so you can pipe the report to a file.
    """
    def _progress(msg: str) -> None:
        click.echo(msg, err=True)

    skill = CyberskillAI()
    _progress(f"Starting chained scan on {target}")
    result = skill.chained_scan(
        target,
        timeout=timeout,
        concurrency=concurrency,
        output=fmt,
        progress_cb=_progress,
    )
    if output:
        with open(output, "w") as fh:
            fh.write(result if isinstance(result, str) else json.dumps(result, indent=2))
        click.echo(f"Report written to {output}", err=True)
    else:
        if isinstance(result, str):
            click.echo(result)
        else:
            click.echo(json.dumps(result, indent=2))


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
