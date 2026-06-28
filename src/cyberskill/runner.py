"""Async scan runner with concurrency control via semaphore."""
from __future__ import annotations

import asyncio
from typing import Any

from cyberskill.models import OWASPCategory, ScanReport, ToolResult
from cyberskill.registry import registry


class ScanRunner:
    """Runs tools concurrently against a target, capped by a semaphore.

    Instantiate once and reuse; the semaphore is per-instance.
    """

    def __init__(self, concurrency: int = 5) -> None:
        self._sem = asyncio.Semaphore(concurrency)

    async def _run_one(
        self,
        tool_cls: type,
        target: str,
        timeout: int,
        **options: Any,
    ) -> ToolResult:
        async with self._sem:
            return await tool_cls().run(target, timeout=timeout, **options)

    async def run_tools(
        self,
        tool_names: list[str],
        target: str,
        timeout: int = 300,
        **options: Any,
    ) -> list[ToolResult]:
        """Run a specific list of tools concurrently."""
        tool_classes = [registry.get(n) for n in tool_names]
        tasks = [self._run_one(cls, target, timeout, **options) for cls in tool_classes]
        return list(await asyncio.gather(*tasks))

    async def run_categories(
        self,
        categories: list[OWASPCategory],
        target: str,
        timeout: int = 300,
        **options: Any,
    ) -> list[ToolResult]:
        """Run all tools covering the given OWASP categories (deduplicated)."""
        seen: set[str] = set()
        tool_classes: list[type] = []
        for cat in categories:
            for cls in registry.by_category(cat):
                if cls.name not in seen:
                    seen.add(cls.name)
                    tool_classes.append(cls)
        tasks = [self._run_one(cls, target, timeout, **options) for cls in tool_classes]
        return list(await asyncio.gather(*tasks))

    async def full_assessment(
        self,
        target: str,
        timeout: int = 300,
        **options: Any,
    ) -> ScanReport:
        """Run every registered tool (deduped) across all OWASP categories."""
        results = await self.run_categories(list(OWASPCategory), target, timeout, **options)
        return ScanReport(target=target, results=results)
