"""Abstract base class for all cyberskill tool wrappers."""
from __future__ import annotations

import asyncio
import shutil
import time
from abc import ABC, abstractmethod
from typing import Any, ClassVar

from cyberskill.models import OWASPCategory, ToolResult


class ToolNotFoundError(RuntimeError):
    """Raised when the tool binary is not found on PATH."""


class ToolExecutionError(RuntimeError):
    """Raised when a tool exits with a non-zero code and produced no structured output."""


class BaseTool(ABC):
    """Base class every tool wrapper must inherit from.

    Subclasses set class-level metadata and implement ``build_command``
    and optionally ``_parse``. The ``run`` coroutine handles subprocess
    execution, timeout enforcement, and ToolResult construction.
    """

    name: ClassVar[str]
    binary: ClassVar[str]
    description: ClassVar[str] = ""
    owasp_categories: ClassVar[frozenset[OWASPCategory]]

    def is_available(self) -> bool:
        """Return True if the tool binary exists on PATH."""
        return shutil.which(self.binary) is not None

    @abstractmethod
    def build_command(self, target: str, **options: Any) -> list[str]:
        """Return the argv list to execute against *target*."""
        ...

    def _parse(self, stdout: str, stderr: str, returncode: int) -> dict[str, Any]:
        """Parse raw subprocess output into a structured dict.

        Override in subclasses. The default returns the raw stdout.
        """
        return {"raw": stdout}

    async def _exec(self, cmd: list[str], timeout: int) -> tuple[str, str, int]:
        """Execute *cmd* as a subprocess, returning (stdout, stderr, returncode)."""
        if not shutil.which(cmd[0]):
            raise ToolNotFoundError(
                f"'{cmd[0]}' not found on PATH — install it first."
            )
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=float(timeout)
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return "", f"Timed out after {timeout}s", -1

        return (
            stdout_b.decode(errors="replace"),
            stderr_b.decode(errors="replace"),
            proc.returncode or 0,
        )

    async def run(self, target: str, timeout: int = 300, **options: Any) -> ToolResult:
        """Execute the tool against *target* and return a :class:`ToolResult`."""
        cmd = self.build_command(target, **options)
        cmd_str = " ".join(cmd)
        t0 = time.monotonic()
        error: str | None = None
        structured: dict[str, Any] = {}
        stdout = stderr = ""
        returncode = 0

        try:
            stdout, stderr, returncode = await self._exec(cmd, timeout)
            structured = self._parse(stdout, stderr, returncode)
        except ToolNotFoundError as exc:
            returncode = 127
            error = str(exc)

        return ToolResult(
            tool_name=self.name,
            target=target,
            command=cmd_str,
            stdout=stdout,
            stderr=stderr,
            returncode=returncode,
            duration_seconds=time.monotonic() - t0,
            owasp_categories=self.owasp_categories,
            structured=structured,
            error=error,
        )
