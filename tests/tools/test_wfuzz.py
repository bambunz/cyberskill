"""Tests for WfuzzTool."""
from __future__ import annotations

from cyberskill.models import OWASPCategory
from cyberskill.tools.wfuzz import WfuzzTool

_SAMPLE_OUTPUT = """\
000000001: 200   1 L   7 W   45 Ch  "/admin"
000000002: 301   0 L   0 W    0 Ch  "/images"
000000003: 403   1 L   9 W   89 Ch  "/.htaccess"
"""


def test_build_command_appends_fuzz():
    cmd = WfuzzTool().build_command("http://target.local")
    url = next(a for a in cmd if "FUZZ" in a)
    assert url.startswith("http://target.local")


def test_build_command_respects_existing_fuzz():
    cmd = WfuzzTool().build_command("http://target.local?id=FUZZ")
    assert any("id=FUZZ" in a for a in cmd)


def test_build_command_traversal_mode_uses_lfi_wordlist():
    cmd = WfuzzTool().build_command("http://target.local", mode="traversal")
    wl = next((a for i, a in enumerate(cmd) if cmd[i - 1] == "-w"), "")
    assert "LFI" in wl or "lfi" in wl.lower() or "traversal" in wl.lower()


def test_parse_extracts_hits():
    parsed = WfuzzTool()._parse(_SAMPLE_OUTPUT, "", 0)
    assert parsed["total"] == 3
    assert parsed["hits"][0]["status"] == "200"
    assert parsed["hits"][0]["payload"] == "/admin"


def test_parse_empty_output():
    parsed = WfuzzTool()._parse("", "", 0)
    assert parsed["total"] == 0
    assert parsed["hits"] == []


def test_owasp_mapping():
    cats = WfuzzTool.owasp_categories
    assert OWASPCategory.A01 in cats
    assert OWASPCategory.A03 in cats
    assert OWASPCategory.A07 in cats
    assert OWASPCategory.A10 in cats
