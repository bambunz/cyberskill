"""CyberskillAI — primary AI-facing interface."""
from __future__ import annotations

import asyncio
from typing import Any

from cyberskill.models import OWASPCategory, ScanReport, ToolResult
from cyberskill.registry import registry
from cyberskill.runner import ScanRunner


class CyberskillAI:
    """AI-friendly facade over the tool registry and scan runner.

    All public methods are synchronous and return JSON-serialisable dicts.
    For async callers use ``async_scan`` / ``async_run_tools`` directly.

    Example usage (AI agent or script)::

        skill = CyberskillAI()
        report = skill.scan("192.168.1.1", categories=["A03", "A05"])
        print(report)   # JSON-serialisable dict

    Third-party tools are discovered automatically via Python entry-points
    (group ``cyberskill.tools``) on initialisation.
    """

    def __init__(self, concurrency: int = 5, auto_discover: bool = True) -> None:
        if auto_discover:
            import cyberskill.tools  # noqa: F401  triggers registry.register() calls
            registry.discover()
        self._runner = ScanRunner(concurrency=concurrency)

    # ------------------------------------------------------------------ #
    # Discovery                                                            #
    # ------------------------------------------------------------------ #

    def list_tools(self) -> list[dict[str, Any]]:
        """Return metadata for every registered tool, sorted by name."""
        out: list[dict[str, Any]] = []
        for name, cls in registry.all().items():
            tool = cls()
            out.append(
                {
                    "name": name,
                    "binary": cls.binary,
                    "description": cls.description,
                    "available": tool.is_available(),
                    "owasp_categories": [c.label for c in sorted(cls.owasp_categories)],
                }
            )
        return sorted(out, key=lambda t: t["name"])

    def list_categories(self) -> list[dict[str, Any]]:
        """Return all OWASP Top 10 categories with the tools mapped to each."""
        return [
            {
                "id": cat.value,
                "label": cat.label,
                "description": cat.description,
                "tools": sorted(cls.name for cls in registry.by_category(cat)),
            }
            for cat in OWASPCategory
        ]

    def tool_info(self, name: str) -> dict[str, Any]:
        """Return metadata for a single tool by name."""
        cls = registry.get(name)
        tool = cls()
        return {
            "name": cls.name,
            "binary": cls.binary,
            "description": cls.description,
            "available": tool.is_available(),
            "owasp_categories": [c.label for c in sorted(cls.owasp_categories)],
        }

    # ------------------------------------------------------------------ #
    # Scanning (sync wrappers)                                            #
    # ------------------------------------------------------------------ #

    def scan(
        self,
        target: str,
        *,
        tools: list[str] | None = None,
        categories: list[str] | None = None,
        timeout: int = 300,
    ) -> dict[str, Any]:
        """Scan *target* and return a JSON-serialisable report dict.

        Keyword args:
            tools:      run these specific tool names only.
            categories: run all tools for these OWASP category IDs,
                        e.g. ``["A03", "A05"]``.  If both *tools* and
                        *categories* are omitted a full assessment runs.
            timeout:    per-tool timeout in seconds.
        """
        report = asyncio.run(
            self._async_scan(target, tools=tools, categories=categories, timeout=timeout)
        )
        return report.to_dict()

    def run_tools(
        self,
        target: str,
        tool_names: list[str],
        timeout: int = 300,
    ) -> list[dict[str, Any]]:
        """Run a specific list of tools and return their results as dicts."""
        results = asyncio.run(self._runner.run_tools(tool_names, target, timeout))
        return [r.to_dict() for r in results]

    # ------------------------------------------------------------------ #
    # Scanning (async — for callers already in an event loop)             #
    # ------------------------------------------------------------------ #

    async def async_scan(
        self,
        target: str,
        *,
        tools: list[str] | None = None,
        categories: list[str] | None = None,
        timeout: int = 300,
    ) -> dict[str, Any]:
        """Async variant of :meth:`scan`."""
        report = await self._async_scan(
            target, tools=tools, categories=categories, timeout=timeout
        )
        return report.to_dict()

    # ------------------------------------------------------------------ #
    # Internal                                                             #
    # ------------------------------------------------------------------ #

    async def _async_scan(
        self,
        target: str,
        *,
        tools: list[str] | None,
        categories: list[str] | None,
        timeout: int,
    ) -> ScanReport:
        if tools:
            results = await self._runner.run_tools(tools, target, timeout)
            return ScanReport(target=target, results=results)
        if categories:
            owasp_cats = [OWASPCategory(c.upper()) for c in categories]
            results = await self._runner.run_categories(owasp_cats, target, timeout)
            return ScanReport(target=target, results=results)
        return await self._runner.full_assessment(target, timeout)
