"""Tests for ToolRegistry."""
from __future__ import annotations

import pytest

from cyberskill.models import OWASPCategory
from cyberskill.registry import ToolRegistry


def test_register_and_get(fresh_registry, fake_tool_cls):
    assert fresh_registry.get("fake") is fake_tool_cls


def test_list_tools_contains_registered(fresh_registry):
    assert "fake" in fresh_registry.list_tools()


def test_list_tools_sorted(fresh_registry):
    tools = fresh_registry.list_tools()
    assert tools == sorted(tools)


def test_by_category_returns_registered_tool(fresh_registry, fake_tool_cls):
    results = fresh_registry.by_category(OWASPCategory.A03)
    assert fake_tool_cls in results


def test_by_category_miss(fresh_registry, fake_tool_cls):
    results = fresh_registry.by_category(OWASPCategory.A01)
    assert fake_tool_cls not in results


def test_get_missing_raises_key_error(fresh_registry):
    with pytest.raises(KeyError, match="not registered"):
        fresh_registry.get("nonexistent")


def test_all_returns_shallow_copy(fresh_registry, fake_tool_cls):
    all_tools = fresh_registry.all()
    assert "fake" in all_tools
    # Mutating the returned dict must not affect the registry
    all_tools["injected"] = fake_tool_cls
    assert "injected" not in fresh_registry.all()


def test_register_overwrites_same_name(fresh_registry, fake_tool_cls):
    """Re-registering the same name replaces it (idempotent)."""
    fresh_registry.register(fake_tool_cls)
    assert fresh_registry.list_tools().count("fake") == 1


def test_all_owasp_categories_initialised():
    reg = ToolRegistry()
    for cat in OWASPCategory:
        # No KeyError — every category bucket exists from the start
        assert isinstance(reg.by_category(cat), list)
