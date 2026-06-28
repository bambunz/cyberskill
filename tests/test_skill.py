"""Tests for CyberskillAI facade."""
from __future__ import annotations

import pytest

from cyberskill.models import OWASPCategory, ScanReport, ToolResult


def _make_report(target: str = "10.0.0.1") -> ScanReport:
    r = ToolResult(
        tool_name="fake",
        target=target,
        command="fake --target " + target,
        stdout="",
        stderr="",
        returncode=0,
        duration_seconds=0.1,
        owasp_categories=frozenset({OWASPCategory.A05}),
    )
    return ScanReport(target=target, results=[r])


def test_list_tools_returns_list(monkeypatch):
    import cyberskill.skill as skill_mod
    from cyberskill.registry import ToolRegistry

    reg = ToolRegistry()
    monkeypatch.setattr(skill_mod, "registry", reg)

    from cyberskill.skill import CyberskillAI
    skill = CyberskillAI(auto_discover=False)
    assert isinstance(skill.list_tools(), list)


def test_list_categories_returns_ten(monkeypatch):
    import cyberskill.skill as skill_mod
    from cyberskill.registry import ToolRegistry

    reg = ToolRegistry()
    monkeypatch.setattr(skill_mod, "registry", reg)

    from cyberskill.skill import CyberskillAI
    skill = CyberskillAI(auto_discover=False)
    cats = skill.list_categories()
    assert len(cats) == 10


def test_scan_returns_serialisable_dict(monkeypatch):
    import cyberskill.skill as skill_mod
    import cyberskill.runner as runner_mod
    from cyberskill.registry import ToolRegistry

    reg = ToolRegistry()
    monkeypatch.setattr(skill_mod, "registry", reg)
    monkeypatch.setattr(runner_mod, "registry", reg)

    async def fake_full(_self, target, timeout=300, **kw):
        return _make_report(target)

    monkeypatch.setattr(
        "cyberskill.runner.ScanRunner.full_assessment", fake_full
    )

    from cyberskill.skill import CyberskillAI
    skill = CyberskillAI(auto_discover=False)
    result = skill.scan("10.0.0.1")
    assert isinstance(result, dict)
    assert result["target"] == "10.0.0.1"
    assert "results" in result


def test_tool_info_raises_for_unknown(monkeypatch):
    import cyberskill.skill as skill_mod
    from cyberskill.registry import ToolRegistry

    reg = ToolRegistry()
    monkeypatch.setattr(skill_mod, "registry", reg)

    from cyberskill.skill import CyberskillAI
    skill = CyberskillAI(auto_discover=False)
    with pytest.raises(KeyError):
        skill.tool_info("ghost_tool")
