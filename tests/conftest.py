"""Shared fixtures for cyberskill tests."""
from __future__ import annotations

import pytest

from cyberskill.base import BaseTool
from cyberskill.models import OWASPCategory, ToolResult
from cyberskill.registry import ToolRegistry


class FakeTool(BaseTool):
    name = "fake"
    binary = "fake"
    description = "Fake tool for testing"
    owasp_categories = frozenset({OWASPCategory.A03, OWASPCategory.A05})

    def build_command(self, target: str, **kwargs) -> list[str]:
        return ["fake", "--target", target]

    def _parse(self, stdout: str, stderr: str, returncode: int) -> dict:
        return {"parsed": True, "data": stdout}


@pytest.fixture
def fake_tool_cls() -> type[BaseTool]:
    return FakeTool


@pytest.fixture
def fresh_registry() -> ToolRegistry:
    """A new ToolRegistry with FakeTool pre-registered."""
    reg = ToolRegistry()
    reg.register(FakeTool)
    return reg


@pytest.fixture
def sample_result() -> ToolResult:
    return ToolResult(
        tool_name="fake",
        target="10.0.0.1",
        command="fake --target 10.0.0.1",
        stdout="hello world",
        stderr="",
        returncode=0,
        duration_seconds=0.5,
        owasp_categories=frozenset({OWASPCategory.A03}),
        structured={"parsed": True},
    )
