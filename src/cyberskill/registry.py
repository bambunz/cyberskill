"""Tool registry and third-party plugin discovery."""
from __future__ import annotations

import warnings
from importlib.metadata import entry_points
from typing import TYPE_CHECKING

from cyberskill.models import OWASPCategory

if TYPE_CHECKING:
    from cyberskill.base import BaseTool

_ENTRY_POINT_GROUP = "cyberskill.tools"


class ToolRegistry:
    """Maps tool names to BaseTool classes and indexes them by OWASP category.

    Built-in tools register themselves at module import time via a
    module-level ``registry.register(MyTool)`` call in each tools/*.py file.

    Third-party packages can ship tools by declaring an entry point under
    the ``cyberskill.tools`` group in their pyproject.toml and calling
    ``registry.discover()`` (done automatically by CyberskillAI on init).
    """

    def __init__(self) -> None:
        self._tools: dict[str, type[BaseTool]] = {}
        self._by_category: dict[OWASPCategory, set[str]] = {
            c: set() for c in OWASPCategory
        }

    def register(self, tool_cls: type[BaseTool]) -> None:
        """Register a BaseTool subclass."""
        self._tools[tool_cls.name] = tool_cls
        for cat in tool_cls.owasp_categories:
            self._by_category.setdefault(cat, set()).add(tool_cls.name)

    def get(self, name: str) -> type[BaseTool]:
        """Return the tool class for *name*, raising KeyError if unknown."""
        try:
            return self._tools[name]
        except KeyError:
            raise KeyError(f"Tool '{name}' is not registered") from None

    def list_tools(self) -> list[str]:
        """Return sorted list of registered tool names."""
        return sorted(self._tools)

    def by_category(self, category: OWASPCategory) -> list[type[BaseTool]]:
        """Return all tool classes that address *category*."""
        names = self._by_category.get(category, set())
        return [self._tools[n] for n in names if n in self._tools]

    def all(self) -> dict[str, type[BaseTool]]:
        """Return a shallow copy of the full tool map."""
        return dict(self._tools)

    def discover(self) -> None:
        """Load third-party tools declared under the ``cyberskill.tools`` entry-point group."""
        for ep in entry_points(group=_ENTRY_POINT_GROUP):
            try:
                cls = ep.load()
                self.register(cls)
            except Exception as exc:  # noqa: BLE001
                warnings.warn(
                    f"Failed to load cyberskill.tools entry point '{ep.name}': {exc}",
                    stacklevel=2,
                )


# Module-level singleton shared across the entire package.
registry = ToolRegistry()
