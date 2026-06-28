"""Tests for BaseTool contract."""
from __future__ import annotations

import pytest

from cyberskill.base import ToolNotFoundError
from cyberskill.models import OWASPCategory


@pytest.mark.asyncio
async def test_run_returns_tool_result_on_success(fake_tool_cls, monkeypatch):
    async def mock_exec(self, cmd, timeout):
        return ("stdout data", "", 0)

    monkeypatch.setattr("cyberskill.base.BaseTool._exec", mock_exec)
    result = await fake_tool_cls().run("10.0.0.1")
    assert result.tool_name == "fake"
    assert result.success is True
    assert result.structured == {"parsed": True, "data": "stdout data"}


@pytest.mark.asyncio
async def test_run_returns_error_when_tool_missing(fake_tool_cls, monkeypatch):
    monkeypatch.setattr("cyberskill.base.shutil.which", lambda _: None)
    result = await fake_tool_cls().run("10.0.0.1")
    assert result.returncode == 127
    assert result.error is not None
    assert result.success is False


@pytest.mark.asyncio
async def test_run_records_duration(fake_tool_cls, monkeypatch):
    async def mock_exec(self, cmd, timeout):
        return ("", "", 0)

    monkeypatch.setattr("cyberskill.base.BaseTool._exec", mock_exec)
    result = await fake_tool_cls().run("10.0.0.1")
    assert result.duration_seconds >= 0


def test_build_command_includes_target(fake_tool_cls):
    cmd = fake_tool_cls().build_command("192.168.1.1")
    assert "192.168.1.1" in cmd


def test_owasp_categories_is_frozenset(fake_tool_cls):
    assert isinstance(fake_tool_cls.owasp_categories, frozenset)


def test_is_available_false_when_binary_missing(fake_tool_cls, monkeypatch):
    monkeypatch.setattr("cyberskill.base.shutil.which", lambda _: None)
    assert fake_tool_cls().is_available() is False
