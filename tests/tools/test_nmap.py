"""Tests for NmapTool."""
from __future__ import annotations

import pytest

from cyberskill.models import OWASPCategory
from cyberskill.tools.nmap import NmapTool

_SAMPLE_XML = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.41"/>
        <script id="http-headers" output="Content-Type: text/html"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="closed"/>
        <service name="http-proxy"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 4.15" accuracy="96"/>
    </os>
  </host>
</nmaprun>
"""


def test_build_command_includes_target():
    cmd = NmapTool().build_command("10.0.0.1")
    assert "10.0.0.1" in cmd
    assert "nmap" in cmd


def test_build_command_version_scan_flag():
    cmd = NmapTool().build_command("10.0.0.1")
    assert "-sV" in cmd


def test_build_command_os_detect():
    cmd = NmapTool().build_command("10.0.0.1", os_detect=True)
    assert "-O" in cmd


def test_build_command_xml_output():
    cmd = NmapTool().build_command("10.0.0.1")
    assert "-oX" in cmd


def test_build_command_custom_ports():
    cmd = NmapTool().build_command("10.0.0.1", ports="22,80,443")
    assert "22,80,443" in cmd


def test_parse_open_ports_only():
    parsed = NmapTool()._parse(_SAMPLE_XML, "", 0)
    ports = parsed["hosts"][0]["open_ports"]
    assert len(ports) == 2  # closed port excluded


def test_parse_port_details():
    parsed = NmapTool()._parse(_SAMPLE_XML, "", 0)
    port80 = next(p for p in parsed["hosts"][0]["open_ports"] if p["port"] == "80")
    assert port80["service"] == "http"
    assert "Apache" in port80["product"]
    assert "http-headers" in port80["scripts"]


def test_parse_host_address():
    parsed = NmapTool()._parse(_SAMPLE_XML, "", 0)
    assert parsed["hosts"][0]["address"] == "10.0.0.1"


def test_parse_invalid_xml():
    parsed = NmapTool()._parse("not xml", "", 0)
    assert parsed.get("parse_error") is True


def test_owasp_mapping():
    assert OWASPCategory.A02 in NmapTool.owasp_categories
    assert OWASPCategory.A05 in NmapTool.owasp_categories
    assert OWASPCategory.A06 in NmapTool.owasp_categories


@pytest.mark.asyncio
async def test_run_tool_not_found(monkeypatch):
    monkeypatch.setattr("cyberskill.base.shutil.which", lambda _: None)
    result = await NmapTool().run("10.0.0.1")
    assert result.returncode == 127
    assert "not found" in (result.error or "").lower()
