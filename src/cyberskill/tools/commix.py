"""commix — automated command injection exploitation."""
from __future__ import annotations

import re
from typing import Any

from cyberskill.base import BaseTool
from cyberskill.models import OWASPCategory
from cyberskill.registry import registry


class CommixTool(BaseTool):
    name = "commix"
    binary = "commix"
    description = "Command injection scanner: classic, blind time-based, file-based techniques"
    owasp_categories = frozenset({OWASPCategory.A03})

    def build_command(
        self,
        target: str,
        *,
        data: str = "",
        cookie: str = "",
        level: int = 1,
        technique: str = "",
        os_cmd: str = "id",
        suffix: str = "",
        prefix: str = "",
        **_: Any,
    ) -> list[str]:
        """
        technique: 'classic', 'blind' (time-based), 'file' (file-based), or '' for all
        os_cmd:    OS command to run on successful injection (default: 'id')
        """
        cmd = [
            "commix",
            "--url", target,
            "--batch",
            "--output-dir", "/tmp/commix_out",
        ]
        if data:
            cmd += ["--data", data]
        if cookie:
            cmd += ["--cookie", cookie]
        if level > 1:
            cmd += ["--level", str(level)]
        if technique:
            cmd += ["--technique", technique]
        if prefix:
            cmd += ["--prefix", prefix]
        if suffix:
            cmd += ["--suffix", suffix]
        cmd += ["--os-cmd", os_cmd]
        return cmd

    def _parse(self, stdout: str, stderr: str, returncode: int) -> dict[str, Any]:
        vulnerable = False
        injection_points: list[str] = []
        techniques_found: list[str] = []
        command_output: list[str] = []

        for line in stdout.splitlines():
            low = line.lower()

            if "is vulnerable" in low or ("parameter" in low and "injectable" in low):
                vulnerable = True
                m = re.search(r"parameter\s+['\"]?(\w+)['\"]?", line, re.I)
                if m:
                    injection_points.append(m.group(1))

            if "technique" in low:
                m2 = re.search(r"technique[:\s]+(.+)", line, re.I)
                if m2:
                    techniques_found.append(m2.group(1).strip())

            # Capture command output lines (e.g. uid=0(root)...)
            if re.match(r"^\s+(uid=|root|www-data|\d+:\d+:\d+)", line):
                command_output.append(line.strip())

        return {
            "vulnerable": vulnerable,
            "injection_points": sorted(set(injection_points)),
            "techniques_found": sorted(set(techniques_found)),
            "command_output": command_output,
        }


registry.register(CommixTool)
