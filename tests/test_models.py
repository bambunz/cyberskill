"""Tests for data models."""
from __future__ import annotations

import json

import pytest

from cyberskill.models import OWASPCategory, ScanReport, ToolResult


def _make(*, returncode: int = 0, error: str | None = None) -> ToolResult:
    return ToolResult(
        tool_name="nmap",
        target="10.0.0.1",
        command="nmap 10.0.0.1",
        stdout="output",
        stderr="",
        returncode=returncode,
        duration_seconds=1.0,
        owasp_categories=frozenset({OWASPCategory.A05}),
        error=error,
    )


# ── ToolResult ────────────────────────────────────────────────────────────────

def test_success_true_when_rc_zero_no_error():
    assert _make().success is True


def test_success_false_when_nonzero_rc():
    assert _make(returncode=1).success is False


def test_success_false_when_error_set():
    assert _make(error="tool missing").success is False


def test_to_dict_has_required_keys():
    keys = _make().to_dict().keys()
    required = {"tool", "target", "command", "success", "returncode",
                "duration_seconds", "owasp_categories", "structured", "stdout", "stderr", "error"}
    assert required <= keys


def test_to_dict_owasp_labels_contain_id():
    r = _make()
    labels = r.to_dict()["owasp_categories"]
    assert any("A05" in lbl for lbl in labels)


def test_to_dict_duration_rounded():
    r = ToolResult(
        tool_name="x", target="t", command="x t", stdout="", stderr="",
        returncode=0, duration_seconds=1.23456789,
        owasp_categories=frozenset({OWASPCategory.A01}),
    )
    assert r.to_dict()["duration_seconds"] == round(1.23456789, 3)


# ── ScanReport ────────────────────────────────────────────────────────────────

def test_scan_report_to_dict_counts():
    r1 = _make(returncode=0)
    r2 = _make(returncode=1)
    report = ScanReport(target="10.0.0.1", results=[r1, r2])
    d = report.to_dict()
    assert d["total_tools"] == 2
    assert d["successful_tools"] == 1


def test_scan_report_to_json_parseable():
    report = ScanReport(target="10.0.0.1", results=[_make()])
    data = json.loads(report.to_json())
    assert data["target"] == "10.0.0.1"
    assert isinstance(data["results"], list)


# ── OWASPCategory ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("cat_id,expected_text", [
    ("A01", "Broken Access Control"),
    ("A02", "Cryptographic"),
    ("A03", "Injection"),
    ("A07", "Authentication"),
    ("A10", "SSRF"),
])
def test_label_contains_category_keyword(cat_id: str, expected_text: str):
    cat = OWASPCategory(cat_id)
    assert expected_text in cat.label


def test_description_is_non_empty():
    for cat in OWASPCategory:
        assert len(cat.description) > 30
