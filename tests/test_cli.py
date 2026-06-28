"""Tests for the Click CLI."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from cyberskill.cli import cli


def _mock_skill(tools=None, categories=None, scan_result=None):
    skill = MagicMock()
    skill.list_tools.return_value = tools or [
        {
            "name": "nmap",
            "binary": "nmap",
            "description": "Network scanner",
            "available": True,
            "owasp_categories": ["A05:2021 – Security Misconfiguration"],
        }
    ]
    skill.list_categories.return_value = categories or [
        {
            "id": "A01",
            "label": "A01:2021 – Broken Access Control",
            "description": "Access control failures.",
            "tools": ["gobuster", "ffuf"],
        }
    ]
    skill.scan.return_value = scan_result or {
        "target": "10.0.0.1",
        "timestamp": "2025-01-01T00:00:00+00:00",
        "total_tools": 1,
        "successful_tools": 1,
        "results": [],
    }
    return skill


def test_list_tools_exit_zero():
    runner = CliRunner()
    with patch("cyberskill.cli.CyberskillAI", return_value=_mock_skill()):
        result = runner.invoke(cli, ["list-tools"])
    assert result.exit_code == 0
    assert "nmap" in result.output


def test_list_tools_shows_description():
    runner = CliRunner()
    with patch("cyberskill.cli.CyberskillAI", return_value=_mock_skill()):
        result = runner.invoke(cli, ["list-tools"])
    assert "Network scanner" in result.output


def test_list_categories_exit_zero():
    runner = CliRunner()
    with patch("cyberskill.cli.CyberskillAI", return_value=_mock_skill()):
        result = runner.invoke(cli, ["list-categories"])
    assert result.exit_code == 0
    assert "A01" in result.output


def test_scan_outputs_json():
    runner = CliRunner()
    with patch("cyberskill.cli.CyberskillAI", return_value=_mock_skill()):
        result = runner.invoke(cli, ["scan", "10.0.0.1"])
    assert result.exit_code == 0
    assert '"target"' in result.output
    assert "10.0.0.1" in result.output


def test_scan_writes_file(tmp_path):
    runner = CliRunner()
    out = tmp_path / "report.json"
    with patch("cyberskill.cli.CyberskillAI", return_value=_mock_skill()):
        result = runner.invoke(cli, ["scan", "10.0.0.1", "-o", str(out)])
    assert result.exit_code == 0
    assert out.exists()
    assert "10.0.0.1" in out.read_text()


def test_scan_with_category_flag():
    runner = CliRunner()
    mock = _mock_skill()
    with patch("cyberskill.cli.CyberskillAI", return_value=mock):
        result = runner.invoke(cli, ["scan", "10.0.0.1", "-c", "A03"])
    assert result.exit_code == 0
    mock.scan.assert_called_once_with(
        "10.0.0.1", tools=None, categories=["A03"], timeout=300
    )


def test_scan_with_tool_flag():
    runner = CliRunner()
    mock = _mock_skill()
    with patch("cyberskill.cli.CyberskillAI", return_value=mock):
        result = runner.invoke(cli, ["scan", "10.0.0.1", "-t", "nmap", "-t", "sqlmap"])
    assert result.exit_code == 0
    mock.scan.assert_called_once_with(
        "10.0.0.1", tools=["nmap", "sqlmap"], categories=None, timeout=300
    )


def test_tool_info_unknown_exits_nonzero():
    runner = CliRunner()
    mock = _mock_skill()
    mock.tool_info.side_effect = KeyError("ghost")
    with patch("cyberskill.cli.CyberskillAI", return_value=mock):
        result = runner.invoke(cli, ["tool-info", "ghost"])
    assert result.exit_code != 0
