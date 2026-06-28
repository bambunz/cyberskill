"""Tests for NucleiTool."""
from __future__ import annotations

import json

from cyberskill.models import OWASPCategory
from cyberskill.tools.nuclei import NucleiTool

_FINDING = {
    "template-id": "CVE-2021-44228",
    "info": {
        "name": "Log4Shell",
        "severity": "critical",
        "tags": ["cve", "log4j"],
        "description": "Remote code execution in Log4j.",
    },
    "type": "http",
    "matched-at": "http://10.0.0.1/api/v1",
}

_SAMPLE_OUTPUT = "\n".join([
    json.dumps(_FINDING),
    json.dumps({**_FINDING, "info": {**_FINDING["info"], "severity": "high"}, "template-id": "other-cve"}),
    "not-json-line",  # should be silently skipped
    "",
])


def test_build_command_json_flag():
    cmd = NucleiTool().build_command("http://target")
    assert "-j" in cmd


def test_build_command_severity():
    cmd = NucleiTool().build_command("http://target", severity="high,critical")
    assert "high,critical" in cmd


def test_build_command_excludes_dos_by_default():
    cmd = NucleiTool().build_command("http://target")
    assert "dos" in cmd


def test_parse_extracts_findings():
    parsed = NucleiTool()._parse(_SAMPLE_OUTPUT, "", 0)
    assert parsed["total"] == 2
    assert parsed["findings"][0]["template_id"] == "CVE-2021-44228"
    assert parsed["findings"][0]["severity"] == "critical"


def test_parse_by_severity():
    parsed = NucleiTool()._parse(_SAMPLE_OUTPUT, "", 0)
    assert parsed["by_severity"]["critical"] == 1
    assert parsed["by_severity"]["high"] == 1


def test_parse_skips_invalid_json():
    parsed = NucleiTool()._parse("not json\nalso not json\n", "", 0)
    assert parsed["total"] == 0


def test_owasp_mapping():
    cats = NucleiTool.owasp_categories
    assert OWASPCategory.A04 in cats
    assert OWASPCategory.A05 in cats
    assert OWASPCategory.A06 in cats
    assert OWASPCategory.A10 in cats
