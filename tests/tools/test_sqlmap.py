"""Tests for SqlmapTool."""
from __future__ import annotations

import pytest

from cyberskill.models import OWASPCategory
from cyberskill.tools.sqlmap import SqlmapTool

_SAMPLE_OUTPUT = """\
        sqlmap identified the following injection point(s) with a total of 42 requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause

Parameter: name (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind
---

available databases [3]:
[*] information_schema
[*] dvwa
[*] mysql
"""


def test_build_command_has_required_flags():
    cmd = SqlmapTool().build_command("http://target/page?id=1")
    assert "-u" in cmd
    assert "--batch" in cmd
    assert "http://target/page?id=1" in cmd


def test_build_command_with_data():
    cmd = SqlmapTool().build_command("http://t/login", data="user=admin&pass=x")
    assert "--data" in cmd
    assert "user=admin&pass=x" in cmd


def test_parse_detects_vulnerability():
    parsed = SqlmapTool()._parse(_SAMPLE_OUTPUT, "", 0)
    assert parsed["vulnerable"] is True


def test_parse_extracts_parameters():
    parsed = SqlmapTool()._parse(_SAMPLE_OUTPUT, "", 0)
    assert "id" in parsed["vulnerable_parameters"]
    assert "name" in parsed["vulnerable_parameters"]


def test_parse_extracts_injection_types():
    parsed = SqlmapTool()._parse(_SAMPLE_OUTPUT, "", 0)
    types = " ".join(parsed["injection_types"])
    assert "boolean-based blind" in types
    assert "time-based blind" in types


def test_parse_extracts_databases():
    parsed = SqlmapTool()._parse(_SAMPLE_OUTPUT, "", 0)
    assert "dvwa" in parsed["databases"]
    assert "mysql" in parsed["databases"]


def test_parse_no_vulnerability():
    parsed = SqlmapTool()._parse("No injectable parameter found.", "", 1)
    assert parsed["vulnerable"] is False
    assert parsed["vulnerable_parameters"] == []


def test_owasp_category():
    assert OWASPCategory.A03 in SqlmapTool.owasp_categories
    assert len(SqlmapTool.owasp_categories) == 1
