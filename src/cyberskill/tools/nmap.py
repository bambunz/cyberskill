"""nmap — network scanner for ports, services, OS detection, SSL scripts."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urlparse

from cyberskill.base import BaseTool
from cyberskill.models import OWASPCategory
from cyberskill.registry import registry


def _host(target: str) -> str:
    """Strip URL scheme/path — nmap only accepts hostnames or IPs."""
    p = urlparse(target)
    return p.hostname if p.scheme in ("http", "https") and p.hostname else target


class NmapTool(BaseTool):
    name = "nmap"
    binary = "nmap"
    description = "Port/service/OS scanner with NSE script support (SSL, HTTP headers, CVEs)"
    owasp_categories = frozenset({
        OWASPCategory.A02,
        OWASPCategory.A05,
        OWASPCategory.A06,
    })

    def build_command(
        self,
        target: str,
        *,
        ports: str = "1-1000",
        os_detect: bool = False,
        scripts: str = "ssl-cert,ssl-enum-ciphers,http-headers",
        udp: bool = False,
        **_: Any,
    ) -> list[str]:
        cmd = ["nmap", "-sV", "--open", "-oX", "-", "-p", ports]
        if udp:
            cmd[1] = "-sUV"
        if os_detect:
            cmd += ["-O", "--osscan-guess"]
        if scripts:
            cmd += ["--script", scripts]
        cmd.append(_host(target))
        return cmd

    def _parse(self, stdout: str, stderr: str, returncode: int) -> dict[str, Any]:
        hosts: list[dict[str, Any]] = []
        try:
            root = ET.fromstring(stdout)
        except ET.ParseError:
            return {"hosts": hosts, "parse_error": True, "raw": stdout[:500]}

        for host_el in root.findall("host"):
            addr_el = host_el.find("address[@addrtype='ipv4']") or host_el.find("address")
            address = addr_el.get("addr", "") if addr_el is not None else ""

            hostname_el = host_el.find(".//hostname")
            hostname = hostname_el.get("name", "") if hostname_el is not None else ""

            open_ports: list[dict[str, Any]] = []
            for port_el in host_el.findall(".//port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                svc = port_el.find("service")
                entry: dict[str, Any] = {
                    "port": port_el.get("portid", ""),
                    "protocol": port_el.get("protocol", ""),
                    "service": svc.get("name", "") if svc is not None else "",
                    "product": svc.get("product", "") if svc is not None else "",
                    "version": svc.get("version", "") if svc is not None else "",
                    "cpe": [c.text for c in port_el.findall(".//cpe") if c.text],
                    "scripts": {},
                }
                for script_el in port_el.findall("script"):
                    entry["scripts"][script_el.get("id", "")] = script_el.get("output", "")
                open_ports.append(entry)

            os_matches: list[str] = []
            for osm in host_el.findall(".//osmatch"):
                os_matches.append(f"{osm.get('name', '')} ({osm.get('accuracy', '')}%)")

            hosts.append({
                "address": address,
                "hostname": hostname,
                "open_ports": open_ports,
                "os_matches": os_matches,
            })

        return {"hosts": hosts, "total_hosts": len(hosts)}


registry.register(NmapTool)
